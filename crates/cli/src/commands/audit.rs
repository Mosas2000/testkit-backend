use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand, ValueEnum};
use proc_macro2::{Group, TokenStream, TokenTree};
use quote::ToTokens;
use serde::{Deserialize, Serialize};
use syn::ext::IdentExt;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, FnArg, ImplItemFn, ItemFn, Local, Pat, Signature, Type};
use walkdir::WalkDir;

use super::CliError;

/// This CLI scans written Rust syntax without expanding procedural or
/// declarative macros. Generated code requires separate inspection.
pub const MACRO_SOURCE_LIMITATION: &str =
    "source-only scan: procedural macros and macro_rules! are not expanded; generated entry points and other generated code require separate inspection";

/// How to read every finding this scanner emits. Each rule is a syntactic
/// heuristic: a finding means the source matched a pattern, which is a
/// signal for manual review — not a definitive defect report — and a
/// missing finding is never a security guarantee.
pub const FINDING_NATURE: &str =
    "heuristic: each finding is a pattern-match signal for manual review, possibly a false positive; it is not a definitive defect report and a clean scan is not a security guarantee";

/// How to read a parse warning as distinct from a finding. A **finding** is
/// a heuristic pattern match over source that parsed successfully: it is
/// rendered in the report, counted in `summary.finding_count`, and is the
/// only thing `--strict` fails on. A **parse warning** means an input could
/// not be read or parsed, so it was never scanned at all: warnings go to
/// stderr only, never count as findings, and make the audit incomplete
/// rather than a strict-mode failure.
pub const PARSE_WARNING_NATURE: &str =
    "parse warnings are not findings: an input that could not be read or parsed was skipped without being scanned; warnings are reported on stderr and, in JSON, under summary.parser_limitations, never counted in finding_count, and never trigger --strict; they make the audit incomplete instead";

/// How to suppress findings in source code. Suppressions use a special comment
/// format that the scanner recognizes and respects.
pub const SUPPRESSION_GUIDANCE: &str =
    "to suppress a finding, add `// audit:allow(<rule_id>)` on the line before it,
or add `// audit:allow_all` to suppress all findings on that line.
Suppressions apply only to the line they precede and do not cascade.
Use `// audit:allow(<rule_id>, \"reason for suppression\")` to document why.";

/// Returns the canonical documentation URI for a SARIF rule descriptor.
///
/// Returns `None` when `rule_id` is empty or whitespace-only so callers never
/// emit a broken anchor-only URI.
fn sarif_rule_help_uri(rule_id: &str) -> Option<String> {
    let trimmed = rule_id.trim();
    if trimmed.is_empty() {
        return None;
    }
    let repo = env!("CARGO_PKG_REPOSITORY").trim_end_matches('/');
    let base = if repo.is_empty() {
        "https://github.com/soroban-testkit/soroban-testkit"
    } else {
        repo
    };
    Some(format!("{base}/blob/main/docs/audit-rules.md#{trimmed}"))
}

/// Single mapping from a rule severity to a SARIF reporting level. Both the
/// `rules` metadata and the `results` entries (and the `audit rules`
/// machine-readable listing) route through this one function, so the
/// severity shown in JSON and text can never disagree with the level SARIF
/// consumers see.
fn sarif_level(severity: &str) -> &'static str {
    match severity {
        "error" => "error",
        "warning" => "warning",
        _ => "note",
    }
}

/// Rewrites a source line into a safe snippet: ANSI terminal escapes
/// (e.g. `ESC[31m`) are removed and control characters collapse to a
/// single space, so copying an arbitrary source line into a report cannot
/// inject output or mangle the surrounding text.
fn sanitize_snippet(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // Skip the rest of a CSI-style escape sequence (ESC [ params
            // final-byte). Other ESC forms simply drop the escape byte.
            if chars.peek() == Some(&'[') {
                for skipped in chars.by_ref() {
                    if skipped.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        if c.is_control() {
            if !out.ends_with(' ') {
                out.push(' ');
            }
        } else {
            out.push(c);
        }
    }
    out.trim_end().to_string()
}

/// GitHub Actions workflow command level for a finding severity.
fn annotation_level(severity: &str) -> &'static str {
    match severity {
        "error" => "error",
        "warning" => "warning",
        _ => "notice",
    }
}

/// Escape a workflow-command property value (`%`, CR, LF, colon, comma).
fn escape_annotation_property(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
        .replace(':', "%3A")
        .replace(',', "%2C")
}

/// Escape a workflow-command message payload (`%`, CR, LF).
fn escape_annotation_message(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

/// Render one GitHub Actions workflow annotation per finding.
///
/// Annotations go to stderr only, so `--format json`/`sarif` stdout stays
/// machine-parseable. The stable rule id is used as the annotation `title`.
fn render_annotations(findings: &[Finding]) -> Vec<String> {
    findings
        .iter()
        .map(|finding| {
            let level = annotation_level(&finding.severity);
            let file = escape_annotation_property(&finding.file.to_string_lossy());
            let mut properties = format!(
                "file={file},line={},title={}",
                finding.line,
                escape_annotation_property(rule_identifier(finding.rule))
            );
            if let Some(end) = finding.end_line {
                if end > finding.line {
                    properties.push_str(&format!(",endLine={end}"));
                }
            }
            let message = escape_annotation_message(&sanitize_snippet(&format!(
                "heuristic finding (manual review): {}",
                finding.message
            )));
            format!("::{level} {properties}::{message}")
        })
        .collect()
}

/// Arguments for `soroban-testkit audit`.
#[derive(Args)]
pub struct AuditArgs {
    #[command(subcommand)]
    command: Option<AuditCommand>,
    /// Path to the contract crate to audit, or `-` to scan Rust source from
    /// stdin.
    ///
    /// Supported scan roots:
    /// - a directory: every `.rs` file beneath it is scanned recursively;
    /// - a single `.rs` file;
    /// - `-`: read Rust source from stdin.
    ///
    /// While scanning a directory these are excluded (skipped, never
    /// descended into): `target/`, `vendor/`, `node_modules/`, and any hidden
    /// directory (its name begins with `.`, e.g. `.git/`, `.github/`, `.cargo/`),
    /// along with any directories specified via `--exclude <DIR>` or `exclude` in
    /// configuration (supporting exact directory paths relative to the project root;
    /// glob matching is not supported). A
    /// missing path is reported as an actionable error rather than an empty
    /// "no findings" result. Explicitly selecting an excluded directory or
    /// one of its files still scans that input. Empty Rust files are valid
    /// and produce no findings.
    /// Findings and baseline entries use workspace-relative paths, and
    /// findings are reported in one canonical order: file, then line, then
    /// rule, then message. Config is discovered from the source directory
    /// up to the workspace root (or from the current directory for stdin).
    /// Files that cannot be read or parsed produce a *parse warning* on
    /// stderr — an input skipped, never scanned — not a finding: warnings
    /// are listed under `summary.parser_limitations` in JSON reports, apart
    /// from `findings`, never count toward `finding_count`, and never trigger
    /// `--strict`. Other files are scanned, then the command exits non-zero
    /// to indicate an incomplete audit.
    ///
    /// This static scan does not expand procedural macros or macro_rules!
    /// invocations. Inspect generated code separately (e.g. cargo expand).
    ///
    /// Every path the command compares or prints is normalized through one
    /// canonical routine first (symlinks and `.`/`..` components resolved),
    /// so one file always reports under a single workspace-relative
    /// spelling no matter how it was spelled on the command line.
    #[arg(value_name = "PATH", default_value = ".", global = true)]
    path: PathBuf,
    /// Exit non-zero if any findings are reported. Inputs that fail to read
    /// or parse always exit non-zero, with or without this flag, so `--strict`
    /// never changes that rule.
    #[arg(long, global = true)]
    strict: bool,
    /// Output format. JSON and SARIF are intended for automation and code scanning.
    #[arg(long, value_enum, default_value_t = AuditOutputFormat::Text, global = true)]
    format: AuditOutputFormat,
    /// Path to a baseline file containing findings to ignore, relative to
    /// the current directory. Expects a JSON array of `{"file", "line", "rule"}`
    /// objects with workspace-relative paths (or `<stdin>`).
    #[arg(long, value_name = "FILE", global = true)]
    baseline: Option<PathBuf>,
    /// Print only the audit summary, omitting individual finding details.
    /// Only supported with text output.
    #[arg(long, global = true)]
    pub summary_only: bool,
    /// Suppress ANSI color escape sequences in text output.
    /// Precedence: `--no-color` flag, then `NO_COLOR` environment variable,
    /// then automatic terminal detection (or `CLICOLOR_FORCE`).
    #[arg(long, global = true)]
    pub no_color: bool,
    /// Wrap human-readable finding messages to the specified maximum character width.
    /// Allowed values: integers between 20 and 1000. When omitted, messages are not wrapped.
    #[arg(long, value_name = "WIDTH", allow_hyphen_values = true, global = true)]
    pub width: Option<String>,
    /// List all audit rules without running an audit.
    #[arg(long, global = true)]
    pub list_rules: bool,
    /// Include glob patterns to filter scanned files. Can be specified multiple times.
    /// A file is scanned if it matches at least one include pattern (or if no include
    /// patterns are specified).
    #[arg(long = "include", value_name = "GLOB", action = clap::ArgAction::Append, global = true)]
    pub include: Vec<String>,
    /// Path to a project-level audit config, overriding automatic discovery.
    /// Defaults to `.soroban-testkit.toml` (then `soroban-testkit.toml`) searched from
    /// the scan root up to the workspace root.
    #[arg(long, value_name = "PATH", global = true)]
    pub config: Option<PathBuf>,
    /// Emit GitHub Actions workflow annotations (`::warning file=...`) on stderr.
    /// Findings are heuristic signals for manual review; annotations never change
    /// stdout or exit codes.
    #[arg(long, global = true)]
    pub annotations: bool,
    /// Exclude glob patterns or directory paths relative to the workspace root
    /// from recursive scans. Repeatable. Exclude patterns take precedence over
    /// include patterns.
    #[arg(long = "exclude", value_name = "GLOB_OR_DIR", action = clap::ArgAction::Append, global = true)]
    pub exclude: Vec<String>,
    /// Run only the specified audit rule(s) by stable identifier (repeatable
    /// or comma-separated). Use `soroban-testkit audit rules` to list valid IDs.
    #[arg(long = "rule", value_name = "RULE_ID", value_delimiter = ',', action = clap::ArgAction::Append, global = true)]
    pub rules: Vec<String>,
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Explain a specific audit rule.
    Explain {
        /// Rule ID to explain.
        rule: String,
    },
    /// List all rules with their descriptions in machine-readable format.
    Rules,
    /// Output JSON schema for machine-readable audit reports.
    Schema,
    /// List all audit rules without running an audit.
    ListRules,
    /// Refresh a finding baseline JSON file from the current audit findings.
    RefreshBaseline {
        /// Path to the baseline JSON file to create or update.
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
        /// Path to the baseline JSON file to create or update.
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,
    },
}

/// Machine- and human-readable audit output formats.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum AuditOutputFormat {
    /// Human-readable compiler-style diagnostics.
    #[default]
    Text,
    /// A stable JSON report containing all findings.
    Json,
    /// SARIF 2.1.0 for GitHub and other code-scanning systems.
    Sarif,
}

/// Configuration for audit rules, loaded from `.soroban-testkit.toml` or
/// `soroban-testkit.toml` in the repository root.
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct AuditConfig {
    #[serde(default)]
    pub rules: HashMap<String, RuleConfig>,
    #[serde(default)]
    pub width: Option<toml::Value>,
    #[serde(default, deserialize_with = "deserialize_exclude")]
    pub exclude: Vec<PathBuf>,
}

fn deserialize_exclude<'de, D>(deserializer: D) -> Result<Vec<PathBuf>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ExcludeVal {
        Single(String),
        List(Vec<String>),
    }

    match Option::<ExcludeVal>::deserialize(deserializer)? {
        Some(ExcludeVal::Single(s)) => Ok(vec![PathBuf::from(s)]),
        Some(ExcludeVal::List(l)) => Ok(l.into_iter().map(PathBuf::from).collect()),
        None => Ok(Vec::new()),
    }
}

/// Per-rule configuration.
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct RuleConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub severity: Option<String>,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub file: PathBuf,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
    pub rule: &'static str,
    pub severity: String,
    pub message: String,
    /// The offending source line, filled from the file/stdin text when the
    /// finding is created. Terminal escape sequences are stripped and
    /// control characters collapsed at render time, so this field is
    /// stored raw. `None` when no source text was available.
    pub source_snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BaselineEntry {
    file: String,
    line: usize,
    rule: String,
}

impl Finding {
    fn matches_baseline(&self, entry: &BaselineEntry) -> bool {
        self.file.to_string_lossy() == entry.file
            && self.line == entry.line
            && self.rule == entry.rule
    }
}

/// Static checks over a contract crate. **Not a security product** — a
/// linter with heuristics, each independently useful and each
/// capable of missing real bugs or flagging non-bugs. The absence of a
/// finding here is never a security guarantee.
///
/// # Rule Confidence & Known Limitations
///
/// Confidence scale:
/// - `high`: direct syntactic match for specific APIs with minimal false positives.
/// - `medium`: AST-based pattern matching within single-function scope; limited by
///   lack of cross-function, cross-crate, or macro expansion analysis.
/// - `low`: token/string heuristics based on identifiers or substring matches; prone
///   to false positives and negatives due to lack of type and execution flow analysis.
/// - `not assessed`: rule has not been formally evaluated.
///
/// 1. `missing-require-auth` [medium]: Entry points taking an `Address` parameter
///    that never call `require_auth` in the function body.
///    Limitations: Cannot inspect macro-generated code; auth in private helpers
///    without recognized auth stems is missed; no cross-file call graph analysis.
/// 2. `unchecked-i128-arithmetic` [medium]: Arithmetic (`+ - * /`) on an explicitly
///    `i128`-typed binding, done outside a `checked_`/`saturating_`/`wrapping_` call.
///    Limitations: Only tracks parameter bindings; ignores local `let` bindings
///    and struct fields; does not inspect macro expansions.
/// 3. `missing-ttl-bump` [low]: Storage reads with no `.extend_ttl(` call in the same function.
///    Limitations: Heuristic token matching; does not verify key equivalence; does
///    not detect TTL bumps in helper functions or separate transactions; ignores
///    instance storage.
/// 4. `broad-mock-all-auths` [high]: Test functions using `mock_all_auths()` bypassing auth.
///    Limitations: Cannot detect calls generated through external test macros or
///    helper functions outside test modules.
/// 5. `ignored-token-transfer-result` [medium]: Token transfer operations whose return
///    value is not handled.
///    Limitations: Syntactic heuristic matching transfer methods without type resolution;
///    `let _ = ...` bypasses detection.
/// 6. `missing-positive-amount-validation` [low]: Signed amount parameters with no comparison
///    against zero.
///    Limitations: Only inspects parameters named `*amount*`; does not evaluate
///    branching/control flow; helper validation missed.
/// 7. `unchecked-timestamp-arithmetic` [low]: Unchecked timestamp arithmetic operations.
///    Limitations: Substring match on `timestamp`; flags unrelated arithmetic in the
///    same function; no semantic type checking.
/// 8. `unchecked-amount-division` [medium]: Unchecked `/` or `/=` in amount calculations.
///    Limitations: Matches amount-related identifier stems syntactically; non-zero
///    positive literal divisors are skipped; control-flow zero checks are not tracked.
/// 9. `unchecked-narrowing-conversion` [medium]: Integer `as` casts that can truncate.
///    Limitations: Tracks parameter and annotated local types; when source type is
///    unknown, casts to `< 128`-bit integer types are flagged as potentially narrowing.
/// 10. `ignored-contract-call-result` [medium]: Contract calls (`try_*`,
///     `try_invoke_contract`) whose `Result` return value is discarded.
///     Limitations: Syntactic heuristic matching `try_*` contract call patterns;
///     excludes `try_transfer`/`try_transfer_from` (covered by `ignored-token-transfer-result`).
/// 11. `storage-write-missing-ttl` [medium]: Persistent or temporary storage writes
///     (`.set`, `.update`) without a matching `.extend_ttl(` in the same function.
///     Limitations: Does not check `instance()` storage; does not verify key equivalence
///     between write and `extend_ttl`; does not inspect helper functions.
///
/// # Scan roots and exclusions
///
/// The supported scan roots are documented on `AuditArgs::path`: a
/// directory is walked recursively for `.rs` files, a single `.rs` file is
/// scanned directly, and `-` reads Rust source from stdin. Directory walks
/// prune `target/`, `vendor/`, `node_modules/`, and every hidden directory
/// (a name beginning with `.`, such as `.git/` or `.github/`) via
/// `collect_rust_sources`, so build output and vendored/tooling trees are
/// never audited. A non-existent root returns an actionable error naming the
/// supported inputs instead of silently reporting "no findings".
///
/// This source-only scan cannot inspect code generated by procedural macros
/// or macro_rules!. Text, JSON and SARIF reports disclose that limitation.
///
/// Every finding is a syntactic pattern match, not proof of a defect
/// ([`FINDING_NATURE`]). The heuristic nature is spelled out wherever users
/// read reports: the closing `note` of text diagnostics, the `limitations`
/// section of JSON and SARIF reports, the `audit rules` listing, and
/// `audit explain <rule>`. Rule severities map to SARIF levels through one
/// shared function (`sarif_level`), so text, JSON and SARIF can never
/// disagree about the same finding.
pub fn run(args: AuditArgs) -> Result<(), CliError> {
    if args.summary_only && args.format != AuditOutputFormat::Text {
        return Err(CliError(
            "--summary-only is only supported for text output; omit --summary-only or use --format text".into(),
        ));
    }

    if args.list_rules
        || matches!(
            &args.command,
            Some(AuditCommand::Rules | AuditCommand::ListRules)
        )
    {
        return list_rules(args.format);
    }
    if let Some(AuditCommand::Explain { rule }) = &args.command {
        return explain_rule(rule);
    }
    if let Some(AuditCommand::Schema) = &args.command {
        return output_schema();
    }
    let refresh_baseline_target = match &args.command {
        Some(AuditCommand::RefreshBaseline { file, output }) => Some(
            output
                .clone()
                .or_else(|| file.clone())
                .or_else(|| args.baseline.clone())
                .unwrap_or_else(|| PathBuf::from(".soroban-testkit-baseline.json")),
        ),
        _ => None,
    };

    for pat in &args.include {
        validate_glob(pat)?;
    }
    let mut exclude_globs = Vec::new();
    let mut exclude_dirs = Vec::new();
    for pat in &args.exclude {
        validate_glob(pat)?;
        if pat.contains(['*', '?', '[', '{']) {
            exclude_globs.push(pat.clone());
        } else {
            exclude_globs.push(pat.clone());
            exclude_dirs.push(PathBuf::from(pat));
        }
    }
    let stdin = args.path == Path::new("-");
    let mut parse_warnings = Vec::new();
    let mut scanned_files = 0usize;
    let mut skipped_files = 0usize;
    let source_dir = if stdin {
        canonical_path(&std::env::current_dir()?)?
    } else {
        fs::metadata(&args.path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                CliError(format!(
                    "path {} does not exist; pass a contract crate directory, a single .rs file, \
                     or `-` to read Rust source from stdin",
                    args.path.display()
                ))
            } else {
                CliError(format!(
                    "failed to access scan path {}: {err}; check path permissions and re-run",
                    args.path.display()
                ))
            }
        })?;
        let root = canonical_path(&args.path)?;
        if root.is_dir() {
            root
        } else {
            root.parent().unwrap_or(&root).to_path_buf()
        }
    };
    let workspace = find_workspace_root(&source_dir);
    let mut config = load_config(&source_dir, &workspace, args.config.as_deref())?;
    apply_selected_rules(&args.rules, &mut config)?;

    let mut raw_exclusions = config.exclude.clone();
    raw_exclusions.extend(exclude_dirs);
    let exclusions = normalize_and_validate_exclusions(&raw_exclusions, &workspace)?;

    let sources = if stdin {
        Vec::new()
    } else {
        collect_rust_sources_filtered_with_exclusions(
            &args.path,
            &workspace,
            &exclusions,
            &mut parse_warnings,
            &args.include,
            &exclude_globs,
        )?
    };

    if refresh_baseline_target.is_none()
        && !stdin
        && (!args.include.is_empty() || !args.exclude.is_empty())
        && sources.is_empty()
    {
        match args.format {
            AuditOutputFormat::Text => {
                println!("audit: no files matched the configured include/exclude filters");
            }
            AuditOutputFormat::Json => {
                let report = serde_json::json!({
                    "tool": "soroban-testkit",
                    "version": 1,
                    "findings": [],
                    "summary": {
                        "finding_count": 0,
                        "files_scanned": 0,
                        "skipped_file_count": 0,
                        "by_severity": [],
                        "parser_limitations": [],
                        "limitations": [MACRO_SOURCE_LIMITATION, FINDING_NATURE],
                        "message": "no files matched the configured include/exclude filters"
                    }
                });
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            }
            AuditOutputFormat::Sarif => {
                let report = serde_json::json!({
                    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                    "version": "2.1.0",
                    "runs": [{
                        "tool": {
                            "driver": {
                                "name": "soroban-testkit",
                                "version": env!("CARGO_PKG_VERSION"),
                                "semanticVersion": env!("CARGO_PKG_VERSION"),
                                "informationUri": env!("CARGO_PKG_REPOSITORY"),
                                "rules": []
                            }
                        },
                        "invocations": [{
                            "executionSuccessful": true,
                            "properties": {
                                "filesScanned": 0,
                                "skippedFileCount": 0,
                                "findingCount": 0
                            }
                        }],
                        "results": [],
                        "properties": {
                            "limitations": [MACRO_SOURCE_LIMITATION, FINDING_NATURE],
                            "message": "no files matched the configured include/exclude filters"
                        }
                    }]
                });
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            }
        }
        return Ok(());
    }
    let mut baseline = if refresh_baseline_target.is_some() {
        Vec::new()
    } else {
        let mut loaded = load_baseline(&args.baseline)?;
        normalize_baseline_entries(&mut loaded, &workspace)?;
        loaded
    };
    let _ = &mut baseline;
    let mut findings = Vec::new();

    if stdin {
        let source = read_stdin_source(std::io::stdin())?;
        match audit_source(
            Path::new("<stdin>"),
            &source,
            &mut findings,
            &config,
            &source,
        ) {
            Ok(()) => scanned_files += 1,
            Err(err) => {
                skipped_files += 1;
                parse_warnings.push(err);
            }
        }
    } else {
        for path in sources {
            match audit_file(&path, &mut findings, &config) {
                Ok(()) => scanned_files += 1,
                Err(err) => {
                    skipped_files += 1;
                    parse_warnings.push(err);
                }
            }
        }
        for finding in &mut findings {
            finding.file = workspace_relative_path(&finding.file, &workspace);
        }
    }

    findings.retain(|f| !baseline.iter().any(|b| f.matches_baseline(b)));
    // Paths are final now, so this is the ordering every rendered report
    // is guaranteed to follow.
    normalize_findings(&mut findings);

    if let Some(target) = refresh_baseline_target {
        if !parse_warnings.is_empty() {
            for warning in &parse_warnings {
                eprintln!("audit: warning: {warning}");
            }
            return Err(CliError(format!(
                "cannot refresh baseline {}: {} parse warning(s); fix the reported inputs and re-run",
                target.display(),
                parse_warnings.len()
            )));
        }
        let entries = write_baseline_file(&target, &findings)?;
        if args.format == AuditOutputFormat::Json {
            let report = serde_json::json!({
                "baseline": target.to_string_lossy(),
                "entry_count": entries.len(),
            });
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        } else {
            let noun = if entries.len() == 1 {
                "entry"
            } else {
                "entries"
            };
            println!(
                "audit: refreshed baseline {} ({} {noun})",
                target.display(),
                entries.len()
            );
        }
        return Ok(());
    }

    let width = resolve_width(&args.width, &config)?;
    let parser_limitations: Vec<String> = parse_warnings.iter().map(ToString::to_string).collect();
    let use_color = should_color(args.no_color);
    let rendered_report = if args.summary_only {
        DiagnosticRenderer::new(&findings).render_summary_only_colored(use_color)
    } else if args.format == AuditOutputFormat::Text {
        DiagnosticRenderer::new(&findings).render_text_colored_with_width(use_color, width)
    } else {
        render_findings_with_limitations_and_scanned(
            &findings,
            args.format,
            &parser_limitations,
            skipped_files,
            scanned_files,
        )?
    };
    print!("{rendered_report}");

    // #318: workflow annotations are an additive stderr channel.
    if args.annotations {
        for annotation in render_annotations(&findings) {
            eprintln!("{annotation}");
        }
    }

    // Findings (heuristic pattern matches over parsed source) were just
    // rendered above; these are parse warnings (inputs that were never
    // scanned), and the two are reported through different channels on
    // purpose so a skipped file can never be mistaken for a finding.
    if !parse_warnings.is_empty() {
        for warning in &parse_warnings {
            eprintln!("audit: warning: {warning}");
        }
        eprintln!(
            "audit: summary: {scanned_files} input(s) scanned, {skipped_files} skipped (see parse warnings above)"
        );
        eprintln!("audit: note: {PARSE_WARNING_NATURE}");
        return Err(CliError(format!(
            "audit incomplete: {} parse warning(s); findings cover only successfully parsed files; \
             fix the reported inputs and re-run",
            parse_warnings.len()
        )));
    }

    if args.strict && !findings.is_empty() {
        return Err(CliError(format!(
            "{} audit finding(s) (--strict)",
            findings.len()
        )));
    }
    Ok(())
}

/// Directories excluded from a workspace scan regardless of where they
/// appear. Hidden directories (names beginning with `.`) are excluded as
/// well, by `is_scannable_entry`.
///
/// These are build output and dependency/tooling trees that either generated
/// non-contract Rust or would just slow the scan down; the audit is meant to
/// run on hand-written contract source.
pub const AUDIT_EXCLUDED_DIRS: &[&str] = &["target", "vendor", "node_modules"];

/// Prunes excluded directories during a walk. Returns `true` for the user's
/// chosen root (even if it happens to share a name with an excluded
/// directory) and for every non-directory entry; returns `false` for
/// excluded directories so [`WalkDir`] never descends into them.
fn is_scannable_entry(entry: &walkdir::DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return true;
    }
    // Never prune the root the user explicitly asked us to scan.
    if entry.depth() == 0 {
        return true;
    }
    let file_name = entry.file_name();
    let name = file_name.to_string_lossy();
    let name: &str = &name;
    !(name.starts_with('.') || AUDIT_EXCLUDED_DIRS.contains(&name))
}

fn normalize_and_validate_exclusions(
    raw_exclusions: &[PathBuf],
    workspace: &Path,
) -> Result<Vec<PathBuf>, CliError> {
    let mut normalized = Vec::new();
    for raw in raw_exclusions {
        let mut clean = Vec::new();
        let mut is_relative = true;

        if raw.is_absolute() {
            if let Ok(rel) = raw.strip_prefix(workspace) {
                for comp in rel.components() {
                    match comp {
                        std::path::Component::CurDir => {}
                        std::path::Component::ParentDir => {
                            if clean.pop().is_none() {
                                return Err(CliError(format!(
                                    "excluded directory `{}` escapes the project root",
                                    raw.display()
                                )));
                            }
                        }
                        std::path::Component::Normal(c) => clean.push(c),
                        _ => {}
                    }
                }
                is_relative = false;
            } else {
                return Err(CliError(format!(
                    "excluded directory `{}` escapes the project root",
                    raw.display()
                )));
            }
        }

        if is_relative {
            for comp in raw.components() {
                match comp {
                    std::path::Component::CurDir => {}
                    std::path::Component::ParentDir => {
                        if clean.pop().is_none() {
                            return Err(CliError(format!(
                                "excluded directory `{}` escapes the project root",
                                raw.display()
                            )));
                        }
                    }
                    std::path::Component::Normal(c) => clean.push(c),
                    _ => {}
                }
            }
        }

        if !clean.is_empty() {
            let p: PathBuf = clean.into_iter().collect();
            normalized.push(p);
        }
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

/// Walks `root` and returns the `.rs` files that should be audited, applying
/// the exclusions documented on `AuditArgs::path`.
///
/// A root that does not exist is an error, not an empty scan: silently
/// reporting "no findings" for a typo'd path would be worse than useless in
/// CI, so the message names every supported input form.
/// Validates a glob pattern syntax, ensuring no unclosed classes or invalid ranges.
pub fn validate_glob(pattern: &str) -> Result<(), CliError> {
    if pattern.trim().is_empty() {
        return Err(CliError(format!(
            "invalid glob pattern '{pattern}': pattern cannot be empty; provide a pattern like '**/*.rs'"
        )));
    }
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            let mut j = i + 1;
            let mut found_close = false;
            while j < bytes.len() {
                if bytes[j] == b']' {
                    found_close = true;
                    break;
                }
                j += 1;
            }
            if !found_close {
                return Err(CliError(format!(
                    "invalid glob pattern '{pattern}': unclosed character class '['; provide a closing ']'"
                )));
            }
            let class = &bytes[i + 1..j];
            let class_content = if !class.is_empty() && (class[0] == b'!' || class[0] == b'^') {
                &class[1..]
            } else {
                class
            };
            if class_content.is_empty() {
                return Err(CliError(format!(
                    "invalid glob pattern '{pattern}': empty character class '[]'"
                )));
            }
            let mut k = 0;
            while k < class_content.len() {
                if k + 2 < class_content.len() && class_content[k + 1] == b'-' {
                    if class_content[k] > class_content[k + 2] {
                        return Err(CliError(format!(
                            "invalid glob pattern '{pattern}': invalid range '{}-{}' in character class",
                            class_content[k] as char, class_content[k + 2] as char
                        )));
                    }
                    k += 3;
                } else {
                    k += 1;
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    Ok(())
}

fn match_char_class(class: &[u8], ch: u8) -> bool {
    if class.is_empty() {
        return false;
    }
    let (negated, class) = if class[0] == b'!' || class[0] == b'^' {
        (true, &class[1..])
    } else {
        (false, class)
    };
    let mut matched = false;
    let mut i = 0;
    while i < class.len() {
        if i + 2 < class.len() && class[i + 1] == b'-' {
            let start = class[i];
            let end = class[i + 2];
            if ch >= start && ch <= end {
                matched = true;
                break;
            }
            i += 3;
        } else {
            if class[i] == ch {
                matched = true;
                break;
            }
            i += 1;
        }
    }
    if negated {
        !matched
    } else {
        matched
    }
}

fn match_single_segment(pat: &[u8], text: &[u8]) -> bool {
    let mut p = 0;
    let mut t = 0;
    let mut star_p = None;
    let mut star_t = 0;

    while t < text.len() {
        if p < pat.len() && pat[p] == b'[' {
            let close = match pat[p + 1..].iter().position(|&b| b == b']') {
                Some(pos) => p + 1 + pos,
                None => return false,
            };
            let class = &pat[p + 1..close];
            if match_char_class(class, text[t]) {
                p = close + 1;
                t += 1;
                continue;
            } else if let Some(sp) = star_p {
                star_t += 1;
                t = star_t;
                p = sp + 1;
                continue;
            } else {
                return false;
            }
        } else if p < pat.len() && pat[p] == b'?' {
            p += 1;
            t += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star_p = Some(p);
            p += 1;
            star_t = t;
        } else if p < pat.len() && pat[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some(sp) = star_p {
            star_t += 1;
            t = star_t;
            p = sp + 1;
        } else {
            return false;
        }
    }

    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

fn match_segments(pat: &[&str], path: &[&str]) -> bool {
    match (pat.first(), path.first()) {
        (None, None) => true,
        (Some(&"**"), _) => {
            if match_segments(&pat[1..], path) {
                return true;
            }
            if !path.is_empty() && match_segments(pat, &path[1..]) {
                return true;
            }
            false
        }
        (Some(p), Some(t)) => {
            if match_single_segment(p.as_bytes(), t.as_bytes()) {
                match_segments(&pat[1..], &path[1..])
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Matches a glob pattern against a relative path.
pub fn glob_matches(pattern: &str, path: &str) -> bool {
    let mut pat_norm = pattern.replace('\\', "/");
    let has_slash = pat_norm.contains('/');

    if pat_norm.ends_with('/') {
        pat_norm.push_str("**");
    }

    let pat_clean = pat_norm.strip_prefix("./").unwrap_or(&pat_norm);
    let pat_clean = pat_clean.strip_prefix('/').unwrap_or(pat_clean);

    let path_norm = path.replace('\\', "/");
    let path_clean = path_norm.strip_prefix("./").unwrap_or(&path_norm);
    let path_clean = path_clean.strip_prefix('/').unwrap_or(path_clean);

    let path_segs: Vec<&str> = path_clean.split('/').filter(|s| !s.is_empty()).collect();

    // If pattern had no slash and no wildcards, match against any directory component or file name
    if !has_slash && !pattern.contains('*') && !pattern.contains('?') && !pattern.contains('[') {
        if path_segs.contains(&pat_clean) {
            return true;
        }
    }

    // If pattern had no slash, it matches against the file's basename
    if !has_slash {
        if let Some(file_name) = path_segs.last() {
            if match_single_segment(pat_clean.as_bytes(), file_name.as_bytes()) {
                return true;
            }
        }
    }

    let pat_segs: Vec<&str> = pat_clean.split('/').filter(|s| !s.is_empty()).collect();
    match_segments(&pat_segs, &path_segs)
}

/// Evaluates include and exclude patterns against a relative path.
/// Exclude patterns take precedence over include patterns.
pub fn matches_filter(
    rel_path: &str,
    include_patterns: &[String],
    exclude_patterns: &[String],
) -> bool {
    let rel_norm = rel_path.replace('\\', "/");
    let rel_norm = rel_norm.strip_prefix("./").unwrap_or(&rel_norm);
    let rel_norm = rel_norm.strip_prefix('/').unwrap_or(rel_norm);

    // 1. Exclude wins: if matches any exclude pattern, skip file
    for pat in exclude_patterns {
        if glob_matches(pat, rel_norm) {
            return false;
        }
    }

    // 2. Include patterns: if specified, must match at least one
    if !include_patterns.is_empty() {
        return include_patterns
            .iter()
            .any(|pat| glob_matches(pat, rel_norm));
    }

    // 3. Otherwise included by default
    true
}

fn collect_rust_sources(
    root: &Path,
    warnings: &mut Vec<CliError>,
) -> Result<Vec<PathBuf>, CliError> {
    collect_rust_sources_filtered_with_exclusions(root, root, &[], warnings, &[], &[])
}

fn check_scan_path(root: &Path) -> Result<fs::Metadata, CliError> {
    let metadata = fs::metadata(root).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            CliError(format!(
                "path {} does not exist; pass a contract crate directory, a single .rs file, \
                 or `-` to read Rust source from stdin",
                root.display()
            ))
        } else {
            CliError(format!(
                "failed to access scan path {}: {err}; check path permissions and re-run",
                root.display()
            ))
        }
    })?;
    Ok(metadata)
}

fn is_scannable_dir(entry: &walkdir::DirEntry, workspace: &Path, exclusions: &[PathBuf]) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    let name = entry.file_name().to_string_lossy();
    if name.starts_with('.') || AUDIT_EXCLUDED_DIRS.contains(&name.as_ref()) {
        return false;
    }
    let rel = workspace_relative_path(entry.path(), workspace);
    !exclusions
        .iter()
        .any(|excl| rel == *excl || rel.starts_with(excl))
}

fn collect_rust_sources_filtered(
    root: &Path,
    warnings: &mut Vec<CliError>,
    include_patterns: &[String],
    exclude_patterns: &[String],
) -> Result<Vec<PathBuf>, CliError> {
    let metadata = check_scan_path(root)?;
    if metadata.is_file() {
        let file_name = root.file_name().unwrap_or_default().to_string_lossy();
        return Ok(
            if matches_filter(&file_name, include_patterns, exclude_patterns) {
                vec![root.to_path_buf()]
            } else {
                Vec::new()
            },
        );
    }

    let workspace = find_workspace_root(root);
    let mut sources = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| is_scannable_dir(entry, &workspace, &[]))
    {
        let entry = entry.map_err(|err| {
            CliError(format!(
                "failed to scan directory {}: {err}; check path permissions and re-run",
                err.path().unwrap_or(root).display()
            ))
        })?;
        if entry.file_type().is_file() && entry.path().extension().is_some_and(|ext| ext == "rs") {
            let rel = entry.path().strip_prefix(root).unwrap_or(entry.path());
            if matches_filter(&rel.to_string_lossy(), include_patterns, exclude_patterns) {
                sources.push(entry.path().to_path_buf());
            }
        }
    }
    sources.sort();
    let _ = warnings;
    Ok(sources)
}

fn collect_rust_sources_with_exclusions(
    root: &Path,
    workspace: &Path,
    exclusions: &[PathBuf],
    include_patterns: &[String],
    exclude_patterns: &[String],
    warnings: &mut Vec<CliError>,
) -> Result<Vec<PathBuf>, CliError> {
    let metadata = check_scan_path(root)?;
    let is_root_file = metadata.is_file();
    if is_root_file {
        let rel = workspace_relative_path(root, workspace);
        let excluded = exclusions
            .iter()
            .any(|excl| rel == *excl || rel.starts_with(excl));
        let rel_str = rel.to_string_lossy();
        return Ok(
            if excluded || !matches_filter(&rel_str, include_patterns, exclude_patterns) {
                Vec::new()
            } else {
                vec![root.to_path_buf()]
            },
        );
    }

    let mut sources = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| is_scannable_dir(entry, workspace, exclusions))
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                warnings.push(CliError(format!(
                    "failed to scan directory {}: {err}; check path permissions and re-run",
                    err.path().unwrap_or(root).display()
                )));
                continue;
            }
        };
        if entry.file_type().is_file() && entry.path().extension().is_some_and(|ext| ext == "rs") {
            let rel = workspace_relative_path(entry.path(), workspace);
            if matches_filter(&rel.to_string_lossy(), include_patterns, exclude_patterns) {
                sources.push(entry.path().to_path_buf());
            }
        }
    }
    sources.sort();
    Ok(sources)
}

/// Definition of an audit rule in the central registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleDefinition {
    pub id: &'static str,
    pub severity: &'static str,
    pub description: &'static str,
    pub explanation: &'static str,
    pub remediation: &'static str,
}

pub const RULE_REGISTRY: &[RuleDefinition] = &[
    RuleDefinition {
        id: "broad-mock-all-auths",
        severity: "warning",
        description: "Test functions using mock_all_auths() bypass auth checks entirely.",
        explanation: "broad-mock-all-auths: Test functions using mock_all_auths() bypass auth checks entirely.\n\
             This rule detects mock_all_auths in test functions.\n\
             Fix: Replace with granular auth checks for specific callers to ensure auth is properly tested.\n\
             Reference: https://developers.stellar.org/docs/build/smart-contracts/guides/testing",
        remediation: "Replace broad mock_all_auths() with granular mock_auths(&[...]) or targeted caller authorizations so unintended missing auth checks are not masked.",
    },
    RuleDefinition {
        id: "ignored-token-transfer-result",
        severity: "warning",
        description: "Token transfer operations can fail; their results must be handled.",
        explanation: "ignored-token-transfer-result: Token transfer operations can fail and their results must be handled.\n\
             This rule detects transfer/transfer_from/try_transfer calls whose results are not used.\n\
             Fix: Propagate the result with ?, match on it, or explicitly bind it (let _ = ...).\n\
             Reference: https://developers.stellar.org/docs/build/smart-contracts/guides/tokens",
        remediation: "Propagate the Result with ?, match on the return value, or assert on the outcome so failed token transfers cannot fail silently.",
    },
    RuleDefinition {
        id: "missing-positive-amount-validation",
        severity: "warning",
        description: "Signed amount parameters should be validated against zero.",
        explanation: "missing-positive-amount-validation: Signed amount parameters should be validated.\n\
             This rule detects amount parameters (signed integers) with no comparison against zero.\n\
             Fix: Add a check like assert!(amount > 0) to validate amounts before use.\n\
             Reference: https://developers.stellar.org/docs/build/smart-contracts/guides/security",
        remediation: "Validate that the amount is strictly positive with require!(amount > 0, ...) or an explicit condition before transferring or updating state.",
    },
    RuleDefinition {
        id: "missing-require-auth",
        severity: "warning",
        description: "Entry points that accept an Address parameter must validate the caller with require_auth().",
        explanation: "missing-require-auth: Entry points that accept an Address parameter must validate the caller.\n\
             This rule detects functions with Address parameters that never call require_auth().\n\
             Fix: Call address.require_auth() to ensure the caller is authorized.\n\
             Reference: https://developers.stellar.org/docs/build/smart-contracts/guides/security",
        remediation: "Call address.require_auth() or address.require_auth_for_args(...) at the start of the function body to verify that the transaction signer authorized the operation.",
    },
    RuleDefinition {
        id: "missing-ttl-bump",
        severity: "warning",
        description: "Storage reads without extend_ttl can expire prematurely.",
        explanation: "missing-ttl-bump: Storage reads that are not followed by TTL extension can expire.\n\
             This rule detects .persistent() or .temporary() reads without .extend_ttl() in the same function.\n\
             Fix: Call .extend_ttl() after reading from storage to prevent premature expiration.\n\
             Reference: https://developers.stellar.org/docs/smart-contracts/storing-data",
        remediation: "Call env.storage().persistent().extend_ttl(...) or temporary().extend_ttl(...) for accessed keys to prevent state expiration before the next interaction.",
    },
    RuleDefinition {
        id: "unchecked-i128-arithmetic",
        severity: "warning",
        description: "Arithmetic on i128 values can silently overflow; use checked/saturating/wrapping variants.",
        explanation: "unchecked-i128-arithmetic: Arithmetic on i128 values can silently overflow.\n\
             This rule detects + - * / operations on i128 values outside of checked/saturating/wrapping variants.\n\
             Fix: Use .checked_add(), .saturating_add(), or .wrapping_add() for safe overflow handling.\n\
             Reference: https://doc.rust-lang.org/std/primitive.i128.html",
        remediation: "Use .checked_add(), .checked_sub(), .checked_mul(), or .checked_div() and handle overflow, or use saturating/wrapping arithmetic if truncation is intended.",
    },
    RuleDefinition {
        id: "unchecked-timestamp-arithmetic",
        severity: "warning",
        description: "Timestamp arithmetic can overflow and cause silent failures.",
        explanation: "unchecked-timestamp-arithmetic: Timestamp arithmetic can overflow and cause silent failures.\n\
             This rule detects + - * / operations on timestamp values without overflow protection.\n\
             Fix: Use checked arithmetic or ensure your timestamps are bounded to valid ranges.\n\
             Reference: https://developers.stellar.org/docs/build/smart-contracts/guides/time",
        remediation: "Use checked arithmetic (.checked_add, .checked_sub) on ledger timestamps and validate bounds to prevent timestamp overflow or underflow.",
    },
];

/// Static metadata for an audit rule, including confidence and verified limitations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleMeta {
    pub id: &'static str,
    pub severity: &'static str,
    pub description: &'static str,
    pub confidence: &'static str,
    pub limitations: &'static [&'static str],
}

/// Static metadata for all audit rules.
pub const RULES: &[RuleMeta] = &[
    RuleMeta {
        id: "missing-require-auth",
        severity: "warning",
        description: "Entry points that accept an Address parameter must validate the caller with require_auth().",
        confidence: "medium",
        limitations: &[
            "Cannot inspect code generated by macros or macro_rules!",
            "Auth validation in private helper functions without recognized auth stems is missed",
            "Does not perform cross-contract or cross-file call graph analysis",
        ],
    },
    RuleMeta {
        id: "unchecked-i128-arithmetic",
        severity: "warning",
        description: "Arithmetic on i128 values can silently overflow; use checked/saturating/wrapping variants.",
        confidence: "medium",
        limitations: &[
            "Only checks i128 bindings declared as function parameters; does not track local let bindings or struct fields",
            "Does not inspect arithmetic inside macro expansions",
        ],
    },
    RuleMeta {
        id: "missing-ttl-bump",
        severity: "warning",
        description: "Storage reads without extend_ttl can expire prematurely.",
        confidence: "low",
        limitations: &[
            "Heuristic token match on body source; does not track storage key equivalence between read and extend_ttl",
            "Does not detect TTL bumps performed in helper functions or separate transactions",
            "Does not check instance storage (.instance().get(...))",
        ],
    },
    RuleMeta {
        id: "broad-mock-all-auths",
        severity: "warning",
        description: "Test functions using mock_all_auths() bypass auth checks entirely.",
        confidence: "high",
        limitations: &[
            "Cannot detect calls generated through external test macros or helper functions outside test modules",
        ],
    },
    RuleMeta {
        id: "ignored-token-transfer-result",
        severity: "warning",
        description: "Token transfer operations can fail; their results must be handled.",
        confidence: "medium",
        limitations: &[
            "Syntactic heuristic matching transfer/transfer_from; does not perform type resolution for non-token types",
            "Assigning result to an unused variable (let _ = ...) bypasses detection",
        ],
    },
    RuleMeta {
        id: "missing-positive-amount-validation",
        severity: "warning",
        description: "Signed amount parameters should be validated against zero.",
        confidence: "low",
        limitations: &[
            "Only inspects parameters containing 'amount' in their identifier name",
            "Token search on body source does not evaluate execution flow or branching",
            "Validation performed in helper functions is not recognized",
        ],
    },
    RuleMeta {
        id: "unchecked-timestamp-arithmetic",
        severity: "warning",
        description: "Timestamp arithmetic can overflow and cause silent failures.",
        confidence: "low",
        limitations: &[
            "Crude substring match on 'timestamp'; flags any arithmetic in a function containing 'timestamp' even on unrelated counters",
            "Does not perform semantic type checking on timestamp variables",
        ],
    },
];

pub fn find_rule(id: &str) -> Option<&'static RuleDefinition> {
    RULE_REGISTRY.iter().find(|r| r.id == id)
}

/// Documented default configuration for a rule: every rule starts enabled,
/// with the severity declared in the central registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleDefaults {
    pub id: &'static str,
    pub enabled: bool,
    pub severity: &'static str,
}

/// Return the documented default for `id`, if it is a registered rule.
pub fn default_for_rule(id: &str) -> Option<RuleDefaults> {
    RULE_REGISTRY
        .iter()
        .find(|rule| rule.id == id)
        .map(|rule| RuleDefaults {
            id: rule.id,
            enabled: true,
            severity: rule.severity,
        })
}

/// Stable machine-readable identifier for a finding's rule.
///
/// Never returns a prose description: consumers may key dashboards, baselines
/// and suppression files on this value across releases.
pub fn rule_identifier(rule: &str) -> &'static str {
    RULE_REGISTRY
        .iter()
        .find(|candidate| candidate.id == rule)
        .map(|candidate| candidate.id)
        .unwrap_or("unknown-rule")
}

fn collect_rust_sources_filtered_with_exclusions(
    root: &Path,
    workspace: &Path,
    exclusions: &[PathBuf],
    warnings: &mut Vec<CliError>,
    include_patterns: &[String],
    exclude_patterns: &[String],
) -> Result<Vec<PathBuf>, CliError> {
    let metadata = fs::metadata(root).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            CliError(format!(
                "path {} does not exist; pass a contract crate directory, a single .rs file, \
                 or `-` to read Rust source from stdin",
                root.display()
            ))
        } else {
            CliError(format!(
                "failed to access scan path {}: {err}; check path permissions and re-run",
                root.display()
            ))
        }
    })?;

    if metadata.is_file() {
        let file_name = root.file_name().unwrap_or_default().to_string_lossy();
        if matches_filter(&file_name, include_patterns, exclude_patterns) {
            return Ok(vec![root.to_path_buf()]);
        } else {
            return Ok(Vec::new());
        }
    }

    let is_root_file = root.is_file();
    let mut sources = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            if !entry.file_type().is_dir() {
                return true;
            }
            if entry.depth() == 0 {
                return true;
            }
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            if name.starts_with('.') || AUDIT_EXCLUDED_DIRS.contains(&name.as_ref()) {
                return false;
            }
            let rel = workspace_relative_path(entry.path(), workspace);
            !exclusions
                .iter()
                .any(|excl| rel == *excl || rel.starts_with(excl))
        })
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                warnings.push(CliError(format!(
                    "failed to scan directory {}: {err}; check path permissions and re-run",
                    err.path().unwrap_or(root).display()
                )));
                continue;
            }
        };
        let is_rust = entry.path().extension().is_some_and(|ext| ext == "rs");
        if entry.file_type().is_file() && is_rust {
            let rel_root = entry.path().strip_prefix(root).unwrap_or(entry.path());
            let rel_str = rel_root.to_string_lossy();
            if !matches_filter(&rel_str, include_patterns, exclude_patterns) {
                continue;
            }
            if entry.depth() == 0 && is_root_file {
                sources.push(entry.path().to_path_buf());
            } else {
                let rel = workspace_relative_path(entry.path(), workspace);
                let is_excluded = exclusions
                    .iter()
                    .any(|excl| rel == *excl || rel.starts_with(excl));
                if !is_excluded {
                    sources.push(entry.path().to_path_buf());
                }
            }
        }
    }
    sources.sort();
    Ok(sources)
}

fn explain_rule(rule: &str) -> Result<(), CliError> {
    let def = find_rule(rule).ok_or_else(|| CliError(format!("unknown rule: {rule}")))?;
    // Every message above describes a syntactic pattern, not a proven
    // defect: state the heuristic nature right next to the rule so the
    // distinction between "flagged" and "broken" is never left to guesswork.
    println!("{}\n\nnote: {FINDING_NATURE}", def.explanation);
    if let Some(defaults) = default_for_rule(def.id) {
        println!(
            "Default: enabled={}, severity={}",
            defaults.enabled, defaults.severity
        );
    }
    Ok(())
}

fn list_rules(format: AuditOutputFormat) -> Result<(), CliError> {
    match format {
        AuditOutputFormat::Text => {
            println!(
                "{:<36} {:<10} {:<12} DESCRIPTION",
                "RULE", "SEVERITY", "CONFIDENCE"
            );
            println!("{}", "-".repeat(100));
            let mut rules: Vec<_> = RULES.iter().collect();
            rules.sort_by(|a, b| a.id.cmp(b.id));
            for rule in rules {
                println!(
                    "{:<36} {:<10} {:<12} {}",
                    rule.id, rule.severity, rule.confidence, rule.description
                );
                for lim in rule.limitations {
                    println!("    * limitation: {lim}");
                }
            }
            println!("note: {FINDING_NATURE}");
            Ok(())
        }
        AuditOutputFormat::Json => {
            let rules: Vec<_> = RULE_REGISTRY
                .iter()
                .map(|rule| {
                    let meta = RULES.iter().find(|m| m.id == rule.id);
                    serde_json::json!({
                        "id": rule.id,
                        "identifier": rule_identifier(rule.id),
                        "severity": rule.severity,
                        "defaultEnabled": true,
                        "defaultSeverity": find_rule(rule.id).map(|r| r.severity).unwrap_or("warning"),
                        "confidence": meta.map(|m| m.confidence).unwrap_or("unknown"),
                        "description": rule.description,
                        "limitations": meta.map(|m| m.limitations).unwrap_or(&[]),
                        "remediation": rule.remediation,
                    })
                })
                .collect();
            let report = serde_json::json!({
                "tool": "soroban-testkit",
                "version": 1,
                "rules": rules,
                "summary": {
                    "rule_count": rules.len(),
                    "limitations": [FINDING_NATURE]
                },
            });
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
            Ok(())
        }
        AuditOutputFormat::Sarif => {
            let rules: Vec<_> = RULE_REGISTRY
                .iter()
                .map(|rule| {
                    let meta = RULES.iter().find(|m| m.id == rule.id);
                    serde_json::json!({
                        "id": rule.id,
                        "shortDescription": { "text": rule.id.replace('-', " ") },
                        "fullDescription": { "text": rule.description },
                        "defaultConfiguration": {
                            "level": sarif_level(rule.severity)
                        },
                        "properties": {
                            "confidence": meta.map(|m| m.confidence).unwrap_or("unknown"),
                            "limitations": meta.map(|m| m.limitations).unwrap_or(&[]),
                        }
                    })
                })
                .collect();
            let report = serde_json::json!({
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [{
                    "tool": { "driver": { "name": "soroban-testkit", "rules": rules } },
                    "results": [],
                    "properties": { "limitations": [FINDING_NATURE] }
                }]
            });
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
            Ok(())
        }
    }
}

/// Count visible character width of a string, ignoring ANSI escape sequences.
/// Wide characters are counted as 1 character width.
pub fn visible_width(s: &str) -> usize {
    let mut count = 0;
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
        } else if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
        } else {
            count += 1;
        }
    }
    count
}

/// Wraps the human-readable message part of a finding at word boundaries,
/// leaving the location prefix intact on line 1, and indenting continuation
/// lines with 4 spaces. Unbreakable tokens longer than the width are not split.
pub fn wrap_finding_message(prefix: &str, message: &str, width: Option<usize>) -> String {
    let Some(max_width) = width else {
        return format!("{prefix}{message}\n");
    };

    let words: Vec<&str> = message.split_whitespace().collect();
    if words.is_empty() {
        return format!("{prefix}\n");
    }

    let prefix_vis = visible_width(prefix);
    let indent = "    ";
    let indent_vis = 4;

    let mut result = String::new();
    let mut current_line = String::new();
    let mut current_vis = 0;

    let first_word = words[0];
    let first_word_vis = visible_width(first_word);

    if prefix_vis + first_word_vis <= max_width {
        current_line.push_str(prefix);
        current_line.push_str(first_word);
        current_vis = prefix_vis + first_word_vis;
    } else {
        result.push_str(prefix.trim_end());
        result.push('\n');
        current_line.push_str(indent);
        current_line.push_str(first_word);
        current_vis = indent_vis + first_word_vis;
    }

    for &word in &words[1..] {
        let w_vis = visible_width(word);
        if current_vis + 1 + w_vis > max_width {
            result.push_str(&current_line);
            result.push('\n');
            current_line.clear();
            current_line.push_str(indent);
            current_line.push_str(word);
            current_vis = indent_vis + w_vis;
        } else {
            current_line.push(' ');
            current_line.push_str(word);
            current_vis += 1 + w_vis;
        }
    }

    if !current_line.is_empty() {
        result.push_str(&current_line);
        result.push('\n');
    }

    result
}

fn validate_width_str(val: &str) -> Result<usize, CliError> {
    match val.parse::<isize>() {
        Ok(n) if n >= 20 && n <= 1000 => Ok(n as usize),
        _ => Err(CliError(format!(
            "invalid width `{val}`: width must be an integer between 20 and 1000 characters; specify a value in that range"
        ))),
    }
}

fn resolve_width(
    cli_width: &Option<String>,
    config: &AuditConfig,
) -> Result<Option<usize>, CliError> {
    if let Some(w) = cli_width {
        return validate_width_str(w).map(Some);
    }
    if let Some(val) = &config.width {
        match val {
            toml::Value::Integer(n) => {
                if *n >= 20 && *n <= 1000 {
                    return Ok(Some(*n as usize));
                } else {
                    return Err(CliError(format!(
                        "invalid width `{n}`: width must be an integer between 20 and 1000 characters; specify a value in that range"
                    )));
                }
            }
            toml::Value::String(s) => {
                return validate_width_str(s).map(Some);
            }
            other => {
                return Err(CliError(format!(
                    "invalid width `{other}`: width must be an integer between 20 and 1000 characters; specify a value in that range"
                )));
            }
        }
    }
    Ok(None)
}

/// Determines whether ANSI color codes should be emitted for text output.
///
/// Precedence:
/// 1. The `--no-color` command line flag (if `true`, color is off).
/// 2. The `NO_COLOR` environment variable (if set and non-empty, color is off).
/// 3. Automatic detection: `CLICOLOR_FORCE` environment variable (if set and != "0",
///    color is forced on), otherwise terminal detection (`std::io::stdout().is_terminal()`).
pub fn should_color(no_color_flag: bool) -> bool {
    if no_color_flag {
        return false;
    }
    if let Ok(val) = std::env::var("NO_COLOR") {
        if !val.is_empty() {
            return false;
        }
    }
    if let Ok(force) = std::env::var("CLICOLOR_FORCE") {
        if force != "0" {
            return true;
        }
    }
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}

/// Counts of findings for a single rule within a severity level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleFindingCount {
    pub rule: String,
    pub count: usize,
}

/// Summary of findings grouped under a specific severity level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeveritySummary {
    pub severity: String,
    pub total: usize,
    pub rules: Vec<RuleFindingCount>,
}

/// Aggregated summary across all findings and scanned files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSummary {
    pub total_findings: usize,
    pub files_scanned: usize,
    pub severities: Vec<SeveritySummary>,
}

/// Priority rank for rule severities: most severe first.
pub fn severity_rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "error" => 0,
        "warning" => 1,
        "note" => 2,
        _ => 3,
    }
}

/// Computes an aggregated audit summary from findings and scanned files.
/// Rule counts are sorted by count descending and then rule id ascending for determinism.
pub fn compute_summary(findings: &[Finding], files_scanned: usize) -> AuditSummary {
    let mut map: HashMap<String, HashMap<String, usize>> = HashMap::new();
    for finding in findings {
        let rule_map = map.entry(finding.severity.clone()).or_default();
        *rule_map.entry(finding.rule.to_string()).or_default() += 1;
    }

    let mut severities: Vec<SeveritySummary> = map
        .into_iter()
        .map(|(severity, rules_map)| {
            let total = rules_map.values().sum();
            let mut rules: Vec<RuleFindingCount> = rules_map
                .into_iter()
                .map(|(rule, count)| RuleFindingCount { rule, count })
                .collect();
            rules.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.rule.cmp(&b.rule)));
            SeveritySummary {
                severity,
                total,
                rules,
            }
        })
        .collect();

    severities.sort_by(|a, b| {
        severity_rank(&a.severity)
            .cmp(&severity_rank(&b.severity))
            .then_with(|| a.severity.cmp(&b.severity))
    });

    AuditSummary {
        total_findings: findings.len(),
        files_scanned,
        severities,
    }
}

/// Output JSON schema for machine-readable audit report format validation.
fn output_schema() -> Result<(), CliError> {
    let schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Soroban Testkit Audit Report",
        "description": "Machine-readable audit report schema for soroban-testkit findings",
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "const": "soroban-testkit",
                "description": "Identifies the tool that produced the report"
            },
            "version": {
                "type": "integer",
                "const": 1,
                "description": "Schema version for future compatibility"
            },
            "findings": {
                "type": "array",
                "description": "List of all audit findings",
                "items": {
                    "type": "object",
                    "properties": {
                        "file": {
                            "type": "string",
                            "description": "Workspace-relative path to the file containing the finding"
                        },
                        "line": {
                            "type": "integer",
                            "description": "Line number where the finding was detected (1-indexed)"
                        },
                        "rule": {
                            "type": "string",
                            "description": "Rule identifier (e.g., 'missing-require-auth')"
                        },
                        "severity": {
                            "type": "string",
                            "description": "Finding severity (e.g., 'warning', 'error')"
                        },
                        "message": {
                            "type": "string",
                            "description": "Human-readable message describing the finding"
                        },
                        "source_snippet": {
                            "type": ["string", "null"],
                            "description": "The source line that triggered the finding (sanitized)"
                        }
                    },
                    "required": ["file", "line", "rule", "severity", "message"]
                }
            },
            "summary": {
                "type": "object",
                "properties": {
                    "finding_count": {
                        "type": "integer",
                        "description": "Total number of findings reported"
                    },
                    "skipped_file_count": {
                        "type": "integer",
                        "description": "Number of files that could not be read or parsed"
                    },
                    "parser_limitations": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "List of parse warnings for files that were skipped"
                    },
                    "limitations": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Known limitations of the audit tool"
                    }
                },
                "required": ["finding_count"]
            }
        },
        "required": ["tool", "version", "findings", "summary"]
    });
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
    Ok(())
}

/// Centralized diagnostic renderer across Text, JSON, and SARIF formats.
pub struct DiagnosticRenderer<'a> {
    findings: &'a [Finding],
    files_scanned: usize,
}

/// Present non-UTF-8 names unambiguously rather than replacing bytes with U+FFFD.
/// The standard Path::display() uses a lossy conversion for such names.
fn display_audit_path(path: &Path) -> String {
    path.to_str()
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{path:?}"))
}

impl<'a> DiagnosticRenderer<'a> {
    /// Create a new diagnostic renderer for the given findings.
    pub fn new(findings: &'a [Finding]) -> Self {
        Self {
            findings,
            files_scanned: 0,
        }
    }

    /// Set the number of scanned files.
    pub fn with_files_scanned(mut self, files_scanned: usize) -> Self {
        self.files_scanned = files_scanned;
        self
    }

    fn effective_files_scanned(&self) -> usize {
        if self.files_scanned > 0 {
            self.files_scanned
        } else {
            let distinct = self
                .findings
                .iter()
                .map(|f| &f.file)
                .collect::<HashSet<_>>()
                .len();
            if distinct > 0 {
                distinct
            } else {
                1
            }
        }
    }

    /// Render diagnostics according to the specified output format.
    pub fn render(&self, format: AuditOutputFormat) -> Result<String, CliError> {
        match format {
            AuditOutputFormat::Text => Ok(self.render_text()),
            AuditOutputFormat::Json => self.render_json(),
            AuditOutputFormat::Sarif => self.render_sarif(),
        }
    }

    /// Render only the summary line and heuristics disclaimer notes.
    pub fn render_text_summary(&self) -> String {
        self.render_text_summary_colored(false)
    }

    /// Render only the summary line and heuristics disclaimer notes with optional ANSI color.
    pub fn render_text_summary_colored(&self, color: bool) -> String {
        if self.findings.is_empty() {
            if color {
                format!(
                    "\x1b[1;32maudit: no findings\x1b[0m\n\x1b[1;36mnote:\x1b[0m {MACRO_SOURCE_LIMITATION}\n\x1b[1;36mnote:\x1b[0m {FINDING_NATURE}\n"
                )
            } else {
                format!(
                    "audit: no findings\nnote: {MACRO_SOURCE_LIMITATION}\nnote: {FINDING_NATURE}\n"
                )
            }
        } else if color {
            format!(
                "\x1b[1m{} finding(s).\x1b[0m soroban-testkit audit is a linter with seven heuristics, not a \
                 security product — a missing finding is not a security guarantee.\n\
                 \x1b[1;36mnote:\x1b[0m {FINDING_NATURE}\n\
                 \x1b[1;36mnote:\x1b[0m {MACRO_SOURCE_LIMITATION}\n",
                self.findings.len()
            )
        } else {
            format!(
                "{} finding(s). soroban-testkit audit is a linter with seven heuristics, not a \
                 security product — a missing finding is not a security guarantee.\n\
                 note: {FINDING_NATURE}\n\
                 note: {MACRO_SOURCE_LIMITATION}\n",
                self.findings.len()
            )
        }
    }

    /// Render the `--summary-only` report, including stable rule identifiers.
    ///
    /// The full text report already prints rule ids on each finding line; the
    /// summary-only mode has no finding lines, so it prints the per-rule
    /// breakdown here to keep stable ids available in every output format.
    pub fn render_summary_only_colored(&self, color: bool) -> String {
        let mut output = self.render_text_summary_colored(color);
        if self.findings.is_empty() {
            return output;
        }
        let summary = compute_summary(self.findings, self.effective_files_scanned());
        output.push_str("Rules:\n");
        for severity in &summary.severities {
            for rule in &severity.rules {
                output.push_str(&format!(
                    "  - {}: {}\n",
                    rule_identifier(&rule.rule),
                    rule.count
                ));
            }
        }
        output.push('\n');
        output.push_str(&format!(
            "  Total: {} finding(s) across {} file(s) scanned\n",
            summary.total_findings, summary.files_scanned
        ));
        output
    }

    /// Render compiler-style human-readable text diagnostics.
    ///
    /// Every finding carries the offending source line (`-->`), with ANSI
    /// escape sequences stripped and control characters collapsed so a
    /// copied snippet can never inject terminal output. Each finding is a
    /// heuristic signal, spelled out in the closing note.
    pub fn render_text(&self) -> String {
        self.render_text_colored(false)
    }

    /// Render compiler-style human-readable text diagnostics with optional ANSI color.
    pub fn render_text_colored(&self, color: bool) -> String {
        self.render_text_colored_with_width(color, None)
    }

    /// Render compiler-style human-readable text diagnostics with optional ANSI color and configurable width.
    pub fn render_text_colored_with_width(&self, color: bool, width: Option<usize>) -> String {
        if self.findings.is_empty() {
            return self.render_text_summary_colored(color);
        }

        let mut output = String::new();
        for finding in self.findings {
            let prefix = if color {
                let sev_str = match finding.severity.as_str() {
                    "error" => "\x1b[1;31m[error]\x1b[0m",
                    "warning" => "\x1b[1;33m[warning]\x1b[0m",
                    _ => &format!("\x1b[1;34m[{}]\x1b[0m", finding.severity),
                };
                format!(
                    "\x1b[1m{}:{}:\x1b[0m {} \x1b[1;36m{}:\x1b[0m ",
                    display_audit_path(&finding.file),
                    finding.line,
                    sev_str,
                    finding.rule,
                )
            } else {
                format!(
                    "{}:{}: [{}] {}: ",
                    display_audit_path(&finding.file),
                    finding.line,
                    finding.severity,
                    finding.rule,
                )
            };

            let loc = match finding.end_line {
                Some(end) if end > finding.line => {
                    format!(
                        "{}:{}:-{}:",
                        display_audit_path(&finding.file),
                        finding.line,
                        end
                    )
                }
                _ => format!("{}:{}:", display_audit_path(&finding.file), finding.line),
            };
            if width.is_some() {
                let wrapped_prefix = if color {
                    format!(
                        "\x1b[1m{}:\x1b[0m \x1b[1;33m[{}]\x1b[0m \x1b[1;36m{}:\x1b[0m ",
                        loc, finding.severity, finding.rule
                    )
                } else {
                    format!("{} [{}] {}: ", loc, finding.severity, finding.rule)
                };
                output.push_str(&wrap_finding_message(
                    &wrapped_prefix,
                    &finding.message,
                    width,
                ));
            } else {
                output.push_str(&format!(
                    "{} [{}] {}: {}\n",
                    loc, finding.severity, finding.rule, finding.message
                ));
            }
            let _ = prefix;
            if let Some(snippet) = &finding.source_snippet {
                if color {
                    output.push_str(&format!(
                        "    \x1b[1;34m-->\x1b[0m {}\n",
                        sanitize_snippet(snippet)
                    ));
                } else {
                    output.push_str(&format!("    --> {}\n", sanitize_snippet(snippet)));
                }
            }
            if let Some(rule) = find_rule(finding.rule) {
                if !rule.remediation.is_empty() {
                    for line in rule.remediation.lines() {
                        output.push_str(&format!("    remediation: {}\n", line));
                    }
                }
            }
        }
        output.push('\n');
        output.push_str(&self.render_text_summary_colored(color));

        let summary = compute_summary(self.findings, self.effective_files_scanned());
        output.push_str("\nSummary:\n");
        for sev in &summary.severities {
            output.push_str(&format!("  {}: {} finding(s)\n", sev.severity, sev.total));
            for rule in &sev.rules {
                output.push_str(&format!("    - {}: {}\n", rule.rule, rule.count));
            }
        }
        output.push_str(&format!(
            "  Total: {} finding(s) across {} file(s) scanned\n",
            summary.total_findings, summary.files_scanned
        ));
        output
    }

    /// Render stable, machine-readable JSON report. Source snippets are
    /// sanitized before serialization so no terminal control sequence
    /// survives transport.
    pub fn render_json(&self) -> Result<String, CliError> {
        self.render_json_with_limitations(&[], 0)
    }

    /// Render the JSON report with parser limitations (inputs that were
    /// skipped) in their own `summary.parser_limitations` list, and the count
    /// of skipped files in `summary.skipped_file_count`. Limitations never
    /// enter `findings` or `finding_count`.
    pub fn render_json_with_limitations(
        &self,
        parser_limitations: &[String],
        skipped_file_count: usize,
    ) -> Result<String, CliError> {
        let findings: Vec<_> = self
            .findings
            .iter()
            .map(|finding| {
                let mut value = serde_json::to_value(finding)
                    .expect("finding serializes despite sanitized snippet");
                if let Some(snippet) = &finding.source_snippet {
                    value["source_snippet"] = serde_json::Value::String(sanitize_snippet(snippet));
                }
                value["rule_id"] =
                    serde_json::Value::String(rule_identifier(finding.rule).to_string());
                if let Some(rule) = find_rule(finding.rule) {
                    value["remediation"] = serde_json::Value::String(rule.remediation.to_string());
                }
                value
            })
            .collect();
        let summary = compute_summary(self.findings, self.effective_files_scanned());
        serde_json::to_string_pretty(&serde_json::json!({
            "tool": "soroban-testkit",
            "version": 1,
            "findings": findings,
            "summary": {
                "finding_count": self.findings.len(),
                "files_scanned": summary.files_scanned,
                "skipped_file_count": skipped_file_count,
                "by_severity": summary.severities,
                "parser_limitations": parser_limitations,
                "limitations": [MACRO_SOURCE_LIMITATION, FINDING_NATURE]
            }
        }))
        .map(|report| format!("{report}\n"))
        .map_err(|err| CliError(format!("failed to serialize JSON audit report: {err}")))
    }

    /// Render SARIF 2.1.0 output for code scanning integration.
    ///
    /// Rule metadata and result levels both map through [`sarif_level`], so
    /// a severity shown in the `rules` section can never disagree with the
    /// `level` on its `results`. Region snippets are sanitized before
    /// embedding.
    pub fn render_sarif(&self) -> Result<String, CliError> {
        self.render_sarif_with_invocation(0)
    }

    /// Render SARIF 2.1.0 output with invocation status and skipped-file metadata.
    pub fn render_sarif_with_invocation(
        &self,
        skipped_file_count: usize,
    ) -> Result<String, CliError> {
        let mut rule_ids: Vec<_> = self.findings.iter().map(|finding| finding.rule).collect();
        rule_ids.sort_unstable();
        rule_ids.dedup();
        let rules: Vec<_> = rule_ids
            .into_iter()
            .map(|rule| {
                let meta = RULES.iter().find(|m| m.id == rule);
                let description = find_rule(rule)
                    .map(|r| r.description)
                    .or_else(|| meta.map(|m| m.description));
                // The metadata level mirrors the level this scan gives the
                // rule's findings: a config override takes effect, and with
                // nothing configured the `RULE_REGISTRY` default applies — both walk
                // through the shared `sarif_level` mapping, so the metadata
                // level always matches how `results` display the same rule.
                let effective_severity = self
                    .findings
                    .iter()
                    .find(|finding| finding.rule == rule)
                    .map(|finding| finding.severity.as_str())
                    .or_else(|| find_rule(rule).map(|r| r.severity))
                    .or_else(|| meta.map(|m| m.severity));
                let mut rule_obj = serde_json::json!({
                    "id": rule,
                    "shortDescription": { "text": rule.replace('-', " ") }
                });
                if let Some(desc) = description {
                    rule_obj["fullDescription"] = serde_json::json!({ "text": desc });
                }
                if let Some(help_uri) = sarif_rule_help_uri(rule) {
                    rule_obj["helpUri"] = serde_json::Value::String(help_uri);
                }
                if let Some(severity) = effective_severity {
                    rule_obj["defaultConfiguration"] =
                        serde_json::json!({ "level": sarif_level(severity) });
                }
                if let Some(m) = meta {
                    rule_obj["properties"] = serde_json::json!({
                        "confidence": m.confidence,
                        "limitations": m.limitations,
                    });
                }
                rule_obj
            })
            .collect();
        let results: Vec<_> = self
            .findings
            .iter()
            .map(|finding| {
                let mut region = match &finding.source_snippet {
                    Some(snippet) => serde_json::json!({
                        "startLine": finding.line.max(1),
                        "snippet": { "text": sanitize_snippet(snippet) }
                    }),
                    None => serde_json::json!({ "startLine": finding.line.max(1) }),
                };
                if let Some(end) = finding.end_line {
                    if end > finding.line {
                        region["endLine"] = serde_json::json!(end);
                    }
                }
                serde_json::json!({
                    "ruleId": finding.rule,
                    "properties": { "stableRuleId": rule_identifier(finding.rule) },
                    "level": sarif_level(&finding.severity),
                    "message": { "text": finding.message },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": finding.file.to_string_lossy() },
                            "region": region
                        }
                    }]
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "soroban-testkit",
                        "version": env!("CARGO_PKG_VERSION"),
                        "semanticVersion": env!("CARGO_PKG_VERSION"),
                        "informationUri": env!("CARGO_PKG_REPOSITORY"),
                        "rules": rules
                    }
                },
                "invocations": [{
                    "executionSuccessful": skipped_file_count == 0,
                    "properties": {
                        "filesScanned": self.effective_files_scanned(),
                        "skippedFileCount": skipped_file_count,
                        "findingCount": self.findings.len()
                    }
                }],
                "results": results,
                "properties": { "limitations": [MACRO_SOURCE_LIMITATION, FINDING_NATURE] }
            }]
        }))
        .map(|report| format!("{report}\n"))
        .map_err(|err| CliError(format!("failed to serialize SARIF audit report: {err}")))
    }
}

pub fn render_findings(
    findings: &[Finding],
    format: AuditOutputFormat,
) -> Result<String, CliError> {
    DiagnosticRenderer::new(findings).render(format)
}

/// Renders the report for `format`. JSON reports also carry the parser
/// limitations (skipped inputs) and the skipped-file count in `summary`;
/// text and SARIF output are unchanged and report those on stderr only.
pub fn render_findings_with_limitations(
    findings: &[Finding],
    format: AuditOutputFormat,
    parser_limitations: &[String],
    skipped_file_count: usize,
) -> Result<String, CliError> {
    render_findings_with_limitations_and_scanned(
        findings,
        format,
        parser_limitations,
        skipped_file_count,
        0,
    )
}

/// Renders the report for `format` with both parser limitations and scanned file count.
pub fn render_findings_with_limitations_and_scanned(
    findings: &[Finding],
    format: AuditOutputFormat,
    parser_limitations: &[String],
    skipped_file_count: usize,
    files_scanned: usize,
) -> Result<String, CliError> {
    let renderer = DiagnosticRenderer::new(findings).with_files_scanned(files_scanned);
    match format {
        AuditOutputFormat::Json => {
            renderer.render_json_with_limitations(parser_limitations, skipped_file_count)
        }
        AuditOutputFormat::Sarif => renderer.render_sarif_with_invocation(skipped_file_count),
        _ => renderer.render(format),
    }
}

pub fn render_text(findings: &[Finding]) -> String {
    DiagnosticRenderer::new(findings).render_text()
}

pub fn render_json(findings: &[Finding]) -> Result<String, CliError> {
    DiagnosticRenderer::new(findings).render_json()
}

pub fn render_sarif(findings: &[Finding]) -> Result<String, CliError> {
    DiagnosticRenderer::new(findings).render_sarif()
}

/// The one canonical path normalization routine for `audit`. The path is
/// resolved through the operating system (symlinks, `.` and `..` components,
/// redundant separators) and rebuilt from its components, so every spelling
/// of one file normalizes to a single value. The scan root, the stdin start
/// directory, finding paths, and baseline entries all normalize here, and a
/// failure carries actionable context for the caller to surface.
fn canonical_path(path: &Path) -> Result<PathBuf, CliError> {
    fs::canonicalize(path)
        .map(|resolved| resolved.components().collect())
        .map_err(|err| {
            CliError(format!(
                "failed to resolve path {}: {err}; verify the path exists and is readable",
                path.display()
            ))
        })
}

// Prefer a Cargo workspace, then a repository root, then the nearest crate.
// Do not cross a repository boundary to discover another project's config.
fn find_workspace_root(source_dir: &Path) -> PathBuf {
    let mut crate_root = None;
    for dir in source_dir.ancestors() {
        if let Ok(manifest) = fs::read_to_string(dir.join("Cargo.toml")) {
            if crate_root.is_none() {
                crate_root = Some(dir.to_path_buf());
            }
            if let Ok(manifest) = toml::from_str::<toml::Value>(&manifest) {
                if manifest.get("workspace").is_some() {
                    return dir.to_path_buf();
                }
            }
        }
        if dir.join(".git").exists() {
            return dir.to_path_buf();
        }
    }
    crate_root.unwrap_or_else(|| source_dir.to_path_buf())
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !out.pop() {
                    out.push(comp);
                }
            }
            _ => out.push(comp),
        }
    }
    out
}

fn workspace_relative_path(path: &Path, workspace: &Path) -> PathBuf {
    let canonical_ws = canonical_path(workspace).unwrap_or_else(|_| normalize_lexical(workspace));
    let absolute = canonical_path(path).unwrap_or_else(|_| normalize_lexical(path));
    absolute
        .strip_prefix(&canonical_ws)
        .or_else(|_| absolute.strip_prefix(workspace))
        .unwrap_or(&absolute)
        .components()
        .collect()
}

/// Extract the source line and TOML table/key from a deserialization error.
/// If the parser cannot identify a key (e.g. an unterminated table), the
/// source line is still helpful alongside the path and parser diagnostic.
fn config_error_context(content: &str, err: &toml::de::Error) -> String {
    let Some(span) = err.span() else {
        return String::new();
    };
    let position = span.start.min(content.len());
    let line_index = content
        .get(..position)
        .unwrap_or("")
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count();
    let line = content.lines().nth(line_index).unwrap_or("");
    let key = line
        .split_once('=')
        .map(|(key, _)| key.trim())
        .filter(|key| !key.is_empty());
    let section = content
        .lines()
        .take(line_index + 1)
        .filter_map(|line| {
            line.trim()
                .strip_prefix('[')
                .and_then(|section| section.strip_suffix(']'))
        })
        .last()
        .unwrap_or("");
    match key {
        Some(key) if !section.is_empty() => {
            format!(" at line {} (key `{section}.{key}`)", line_index + 1)
        }
        Some(key) => format!(" at line {} (key `{key}`)", line_index + 1),
        None => format!(" at line {}", line_index + 1),
    }
}

pub const VALID_RULES: &[&str] = &[
    "broad-mock-all-auths",
    "ignored-contract-call-result",
    "ignored-token-transfer-result",
    "missing-positive-amount-validation",
    "missing-require-auth",
    "missing-ttl-bump",
    "storage-write-missing-ttl",
    "unchecked-amount-division",
    "unchecked-i128-arithmetic",
    "unchecked-narrowing-conversion",
    "unchecked-timestamp-arithmetic",
];

const EXTRA_SELECTABLE_RULES: &[&str] = &[
    "inconsistent-validation-across-entry-points",
    "zero-transfer-amount",
    "arithmetic-before-range-check",
];

fn is_known_rule_id(rule_id: &str) -> bool {
    VALID_RULES.contains(&rule_id) || EXTRA_SELECTABLE_RULES.contains(&rule_id)
}

/// Validates `--rule` selections and restricts `config.rules` to only the
/// requested stable rule identifiers while preserving configured severities.
fn apply_selected_rules(selected: &[String], config: &mut AuditConfig) -> Result<(), CliError> {
    if selected.is_empty() {
        return Ok(());
    }
    let mut chosen = HashSet::new();
    for raw in selected {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(CliError(
                "rule identifier cannot be empty; run `soroban-testkit audit rules` to list valid rule identifiers"
                    .to_string(),
            ));
        }
        if !is_known_rule_id(trimmed) {
            return Err(CliError(format!(
                "unknown audit rule `{trimmed}`; run `soroban-testkit audit rules` to list valid rule identifiers"
            )));
        }
        chosen.insert(trimmed.to_string());
    }
    for &rule_id in VALID_RULES.iter().chain(EXTRA_SELECTABLE_RULES.iter()) {
        let entry = config.rules.entry(rule_id.to_string()).or_default();
        entry.enabled = chosen.contains(rule_id);
    }
    Ok(())
}

pub const VALID_SEVERITIES: &[&str] = &["error", "warning", "note"];

/// Known sections for other commands or tooling in a shared configuration file.
const KNOWN_OTHER_SECTIONS: &[&str] = &[
    "coverage",
    "limits",
    "completion",
    "release_verify",
    "release-verify",
    "workspace",
    "package",
    "dependencies",
    "dev-dependencies",
    "profile",
    "other",
    "other_section",
    "other-section",
];

struct ConfigValidationError {
    line: usize,
    key_path: String,
    message: String,
}

fn find_line_for_key(content: &str, key_path: &str) -> usize {
    let parts: Vec<&str> = key_path.split('.').collect();
    if parts.is_empty() {
        return 1;
    }

    let mut current_section = "";
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = &trimmed[1..trimmed.len() - 1].trim();
            if current_section == key_path {
                return idx + 1;
            }
            if parts.len() >= 2 && current_section == format!("{}.{}", parts[0], parts[1]) {
                if parts.len() == 2 {
                    return idx + 1;
                }
            }
        }
        if let Some((k, _)) = trimmed.split_once('=') {
            let k = k.trim();
            if parts.len() == 1 && k == parts[0] {
                return idx + 1;
            }
            if parts.len() == 2 && current_section == parts[0] && k == parts[1] {
                return idx + 1;
            }
            if parts.len() == 3
                && current_section == format!("{}.{}", parts[0], parts[1])
                && k == parts[2]
            {
                return idx + 1;
            }
            if let Some(last) = parts.last() {
                if k == *last {
                    return idx + 1;
                }
            }
        }
    }
    1
}

fn validate_audit_config_table(
    table: &toml::Table,
    content: &str,
    prefix: &str,
    errors: &mut Vec<ConfigValidationError>,
) {
    let has_audit_table = table.contains_key("audit");

    for (key, val) in table {
        let full_key = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };

        if prefix.is_empty() {
            if key == "audit" {
                if let toml::Value::Table(sub_table) = val {
                    validate_audit_config_table(sub_table, content, "audit", errors);
                } else {
                    let line = find_line_for_key(content, &full_key);
                    errors.push(ConfigValidationError {
                        line,
                        key_path: full_key,
                        message: "key `audit` must be a table".to_string(),
                    });
                }
                continue;
            }

            if key == "rules" {
                validate_rules_table(val, content, "rules", errors);
                continue;
            }

            if key == "width" {
                let rendered = match val {
                    toml::Value::Integer(value) if *value >= 0 => value.to_string(),
                    toml::Value::String(value) => value.clone(),
                    _ => {
                        let line = find_line_for_key(content, &full_key);
                        errors.push(ConfigValidationError {
                            line,
                            key_path: full_key,
                            message: "key `width` must be a positive integer or width string"
                                .to_string(),
                        });
                        continue;
                    }
                };
                if let Err(message) = validate_width_str(&rendered) {
                    let line = find_line_for_key(content, &full_key);
                    errors.push(ConfigValidationError {
                        line,
                        key_path: full_key,
                        message: message.0,
                    });
                }
                continue;
            }

            if key == "exclude" {
                match val {
                    toml::Value::String(_) => {}
                    toml::Value::Array(arr) => {
                        for item in arr {
                            if !item.is_str() {
                                let line = find_line_for_key(content, &full_key);
                                errors.push(ConfigValidationError {
                                    line,
                                    key_path: full_key.clone(),
                                    message:
                                        "key `exclude` elements must be directory path strings"
                                            .to_string(),
                                });
                                break;
                            }
                        }
                    }
                    _ => {
                        let line = find_line_for_key(content, &full_key);
                        errors.push(ConfigValidationError {
                            line,
                            key_path: full_key,
                            message:
                                "key `exclude` must be a string or list of directory path strings"
                                    .to_string(),
                        });
                    }
                }
                continue;
            }

            if has_audit_table || KNOWN_OTHER_SECTIONS.contains(&key.as_str()) {
                continue;
            }

            let line = find_line_for_key(content, &full_key);
            errors.push(ConfigValidationError {
                line,
                key_path: full_key,
                message:
                    "unknown configuration key; valid audit keys are: audit, exclude, rules, width"
                        .to_string(),
            });
        } else if prefix == "audit" {
            if key == "width" {
                let rendered = match val {
                    toml::Value::Integer(value) if *value >= 0 => value.to_string(),
                    toml::Value::String(value) => value.clone(),
                    _ => {
                        let line = find_line_for_key(content, &full_key);
                        errors.push(ConfigValidationError {
                            line,
                            key_path: full_key,
                            message: "key `width` must be a positive integer or width string"
                                .to_string(),
                        });
                        continue;
                    }
                };
                if let Err(message) = validate_width_str(&rendered) {
                    let line = find_line_for_key(content, &full_key);
                    errors.push(ConfigValidationError {
                        line,
                        key_path: full_key,
                        message: message.0,
                    });
                }
                continue;
            }
            if key == "rules" {
                validate_rules_table(val, content, "audit.rules", errors);
                continue;
            }
            if key == "exclude" {
                match val {
                    toml::Value::String(_) => {}
                    toml::Value::Array(arr) => {
                        for item in arr {
                            if !item.is_str() {
                                let line = find_line_for_key(content, &full_key);
                                errors.push(ConfigValidationError {
                                    line,
                                    key_path: full_key.clone(),
                                    message: "key `audit.exclude` elements must be directory path strings".to_string(),
                                });
                                break;
                            }
                        }
                    }
                    _ => {
                        let line = find_line_for_key(content, &full_key);
                        errors.push(ConfigValidationError {
                            line,
                            key_path: full_key,
                            message: "key `audit.exclude` must be a string or list of directory path strings".to_string(),
                        });
                    }
                }
                continue;
            }
            let line = find_line_for_key(content, &full_key);
            errors.push(ConfigValidationError {
                line,
                key_path: full_key,
                message: "unknown configuration key; valid audit keys are: exclude, rules, width"
                    .to_string(),
            });
        }
    }
}

fn validate_rules_table(
    val: &toml::Value,
    content: &str,
    rules_path: &str,
    errors: &mut Vec<ConfigValidationError>,
) {
    let rules_table = match val {
        toml::Value::Table(t) => t,
        _ => {
            let line = find_line_for_key(content, rules_path);
            errors.push(ConfigValidationError {
                line,
                key_path: rules_path.to_string(),
                message: format!("key `{rules_path}` must be a table"),
            });
            return;
        }
    };

    let valid_rules_list = VALID_RULES.join(", ");

    for (rule_name, rule_val) in rules_table {
        let rule_key_path = format!("{rules_path}.{rule_name}");
        let line = find_line_for_key(content, &rule_key_path);

        if !VALID_RULES.contains(&rule_name.as_str()) {
            errors.push(ConfigValidationError {
                line,
                key_path: rule_key_path,
                message: format!("unknown rule `{rule_name}`; valid rules are: {valid_rules_list}"),
            });
            continue;
        }

        if let toml::Value::Table(rule_props) = rule_val {
            for (prop_key, prop_val) in rule_props {
                let prop_key_path = format!("{rule_key_path}.{prop_key}");
                if prop_key == "severity" {
                    if let toml::Value::String(sev) = prop_val {
                        let normalized = sev.to_ascii_lowercase();
                        if !VALID_SEVERITIES.contains(&normalized.as_str()) {
                            let prop_line = find_line_for_key(content, &prop_key_path);
                            let allowed = VALID_SEVERITIES.join(", ");
                            errors.push(ConfigValidationError {
                                line: prop_line,
                                key_path: prop_key_path,
                                message: format!(
                                    "invalid severity `{sev}` for rule `{rule_name}`; allowed values are: {allowed}"
                                ),
                            });
                        }
                    } else {
                        let prop_line = find_line_for_key(content, &prop_key_path);
                        errors.push(ConfigValidationError {
                            line: prop_line,
                            key_path: prop_key_path,
                            message: "severity must be a string".to_string(),
                        });
                    }
                } else if prop_key != "enabled" {
                    let prop_line = find_line_for_key(content, &prop_key_path);
                    errors.push(ConfigValidationError {
                        line: prop_line,
                        key_path: prop_key_path,
                        message: "unknown configuration key; valid keys are: enabled, severity"
                            .to_string(),
                    });
                }
            }
        } else {
            errors.push(ConfigValidationError {
                line,
                key_path: rule_key_path,
                message: "rule configuration must be a table".to_string(),
            });
        }
    }
}

fn load_config(
    source_dir: &Path,
    workspace: &Path,
    explicit_config: Option<&Path>,
) -> Result<AuditConfig, CliError> {
    let explicit_path = explicit_config.map(Path::to_path_buf);
    if let Some(path) = &explicit_path {
        if !path.exists() {
            return Err(CliError(format!(
                "audit config {} does not exist; pass a readable .soroban-testkit.toml path",
                path.display()
            )));
        }
    }
    let config_names: Vec<String> = match &explicit_path {
        Some(path) => vec![path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()],
        None => vec![
            ".soroban-testkit.toml".to_string(),
            "soroban-testkit.toml".to_string(),
        ],
    };
    for dir in source_dir.ancestors() {
        for name in &config_names {
            let path = match &explicit_path {
                Some(path) => path.clone(),
                None => dir.join(name),
            };
            let content = match fs::read_to_string(&path) {
                Ok(content) => content,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(CliError(format!(
                        "failed to read audit config {}: {err}; check file permissions and UTF-8 encoding",
                        path.display()
                    )));
                }
            };

            let table: toml::Table = toml::from_str(&content).map_err(|err| {
                CliError(format!(
                    "failed to parse audit config {}{} as TOML: {err}; fix the configuration syntax",
                    path.display(),
                    config_error_context(&content, &err)
                ))
            })?;

            let mut validation_errors = Vec::new();
            validate_audit_config_table(&table, &content, "", &mut validation_errors);

            if !validation_errors.is_empty() {
                validation_errors
                    .sort_by(|a, b| a.line.cmp(&b.line).then(a.key_path.cmp(&b.key_path)));
                let formatted_errors: Vec<String> = validation_errors
                    .into_iter()
                    .map(|e| format!("at line {} (key `{}`): {}", e.line, e.key_path, e.message))
                    .collect();
                return Err(CliError(format!(
                    "failed to validate audit config {}:\n  - {}",
                    path.display(),
                    formatted_errors.join("\n  - ")
                )));
            }

            let mut config: AuditConfig = toml::from_str(&content).map_err(|err| {
                CliError(format!(
                    "failed to parse audit config {}{} as TOML: {err}; fix the configuration syntax",
                    path.display(),
                    config_error_context(&content, &err)
                ))
            })?;

            // Normalize severity strings to lowercase
            for rule_cfg in config.rules.values_mut() {
                if let Some(sev) = &rule_cfg.severity {
                    rule_cfg.severity = Some(sev.to_ascii_lowercase());
                }
            }

            // If [audit.rules] or [audit.exclude] was used, merge them into config
            if let Some(toml::Value::Table(audit_tbl)) = table.get("audit") {
                if let Some(toml::Value::Table(rules_tbl)) = audit_tbl.get("rules") {
                    for (k, v) in rules_tbl {
                        if !config.rules.contains_key(k) {
                            if let Ok(mut rule_cfg) = v.clone().try_into::<RuleConfig>() {
                                if let Some(sev) = &rule_cfg.severity {
                                    rule_cfg.severity = Some(sev.to_ascii_lowercase());
                                }
                                config.rules.insert(k.clone(), rule_cfg);
                            }
                        }
                    }
                }
                if let Some(audit_excl) = audit_tbl.get("exclude") {
                    match audit_excl {
                        toml::Value::String(s) => config.exclude.push(PathBuf::from(s)),
                        toml::Value::Array(arr) => {
                            for item in arr {
                                if let toml::Value::String(s) = item {
                                    config.exclude.push(PathBuf::from(s));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            return Ok(config);
        }
        if explicit_path.is_some() {
            break;
        }
        if dir == workspace {
            break;
        }
    }

    Ok(AuditConfig::default())
}

fn load_baseline(baseline_path: &Option<PathBuf>) -> Result<Vec<BaselineEntry>, CliError> {
    match baseline_path {
        Some(path) => {
            let content = fs::read_to_string(path).map_err(|err| {
                CliError(format!(
                    "failed to read baseline file {}: {err}; check the path, permissions and UTF-8 encoding",
                    path.display()
                ))
            })?;
            let entries: Vec<BaselineEntry> = serde_json::from_str(&content).map_err(|err| {
                CliError(format!(
                    "failed to parse baseline JSON {}: {err}; expected an array of file, line and rule entries",
                    path.display()
                ))
            })?;
            for (index, entry) in entries.iter().enumerate() {
                let entry_num = index + 1;
                if entry.file.trim().is_empty() {
                    return Err(CliError(format!(
                        "invalid baseline entry #{entry_num} in {}: `file` must not be empty",
                        path.display()
                    )));
                }
                if entry.rule.trim().is_empty() {
                    return Err(CliError(format!(
                        "invalid baseline entry #{entry_num} in {}: `rule` must not be empty",
                        path.display()
                    )));
                }
                if entry.line == 0 {
                    return Err(CliError(format!(
                        "invalid baseline entry #{entry_num} in {}: `line` must be >= 1",
                        path.display()
                    )));
                }
            }
            Ok(entries)
        }
        None => Ok(Vec::new()),
    }
}

/// Normalizes baseline entry paths relative to `workspace`, preserving `<stdin>`
/// and resolving `.` / `..` components even when a referenced file no longer exists.
fn normalize_baseline_entries(
    entries: &mut [BaselineEntry],
    workspace: &Path,
) -> Result<(), CliError> {
    for entry in entries {
        if entry.file == "<stdin>" {
            continue;
        }
        let raw_forward = entry.file.replace('\\', "/");
        let raw_path = Path::new(&raw_forward);
        if raw_path.is_absolute() {
            entry.file = workspace_relative_path(raw_path, workspace)
                .to_string_lossy()
                .into_owned();
            continue;
        }
        let joined = workspace.join(raw_path);
        if let Ok(canonical) = canonical_path(&joined) {
            entry.file = canonical
                .strip_prefix(workspace)
                .unwrap_or(&canonical)
                .to_string_lossy()
                .into_owned();
            continue;
        }
        // Lexical fallback when the file does not exist on disk.
        let mut clean = Vec::new();
        for comp in raw_path.components() {
            match comp {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    if clean.pop().is_none() {
                        return Err(CliError(format!(
                            "baseline entry path `{}` escapes the workspace root {}",
                            entry.file,
                            workspace.display()
                        )));
                    }
                }
                std::path::Component::Normal(c) => clean.push(c),
                _ => {}
            }
        }
        let normalized: PathBuf = clean.into_iter().collect();
        entry.file = normalized.to_string_lossy().into_owned();
    }
    Ok(())
}

/// Converts normalized findings into deduplicated baseline entries.
fn build_baseline_entries(findings: &[Finding]) -> Vec<BaselineEntry> {
    let mut entries: Vec<BaselineEntry> = findings
        .iter()
        .map(|finding| BaselineEntry {
            file: finding.file.to_string_lossy().into_owned(),
            line: finding.line,
            rule: finding.rule.to_string(),
        })
        .collect();
    entries.dedup();
    entries
}

/// Writes a finding baseline JSON file to `target`, creating parent directories
/// if needed and returning the written entries.
fn write_baseline_file(
    target: &Path,
    findings: &[Finding],
) -> Result<Vec<BaselineEntry>, CliError> {
    if target.is_dir() {
        return Err(CliError(format!(
            "baseline path {} is a directory; pass a file path such as baseline.json",
            target.display()
        )));
    }
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|err| {
                CliError(format!(
                    "failed to create parent directory for baseline {}: {err}; check path permissions",
                    target.display()
                ))
            })?;
        }
    }
    let entries = build_baseline_entries(findings);
    let json = serde_json::to_string_pretty(&entries).map_err(|err| {
        CliError(format!(
            "failed to serialize baseline {}: {err}",
            target.display()
        ))
    })?;
    fs::write(target, format!("{json}\n")).map_err(|err| {
        CliError(format!(
            "failed to write baseline file {}: {err}; check path permissions",
            target.display()
        ))
    })?;
    Ok(entries)
}

/// The one canonical ordering for findings: file, then line, then rule,
/// Sorts findings by file, line, rule, and message, then collapses exact
/// duplicates. Every report path funnels through this routine, in `audit_source`
/// per parsed file and again in `run` after paths are rewritten workspace-relative,
/// so text, JSON and SARIF always list a finding in the same place regardless
/// of scan order. File paths use lossy comparison to ensure deterministic ordering
/// across platforms (e.g., case-insensitive file systems).
fn normalize_findings(findings: &mut Vec<Finding>) {
    findings.sort_by(|left, right| {
        let left_file = left.file.to_string_lossy();
        let right_file = right.file.to_string_lossy();
        left_file
            .cmp(&right_file)
            .then(left.line.cmp(&right.line))
            .then(left.end_line.cmp(&right.end_line))
            .then(left.rule.cmp(right.rule))
            .then(left.message.cmp(&right.message))
    });
    findings.dedup_by(|left, right| {
        let left_file = left.file.to_string_lossy();
        let right_file = right.file.to_string_lossy();
        left_file == right_file
            && left.line == right.line
            && left.end_line == right.end_line
            && left.rule == right.rule
            && left.message == right.message
    });
}

fn read_stdin_source<R: Read>(mut reader: R) -> Result<String, CliError> {
    let mut source = String::new();
    reader.read_to_string(&mut source).map_err(|err| {
        CliError(format!(
            "failed to read Rust source from stdin: {err}; ensure stdin provides valid UTF-8 Rust source"
        ))
    })?;
    Ok(source)
}

fn audit_file(
    path: &Path,
    findings: &mut Vec<Finding>,
    config: &AuditConfig,
) -> Result<(), CliError> {
    let src = std::fs::read_to_string(path).map_err(|err| {
        CliError(format!(
            "failed to read Rust source {}: {err}; check file permissions and UTF-8 encoding",
            path.display()
        ))
    })?;
    audit_source(path, &src, findings, config, &src)
}

fn audit_source(
    path: &Path,
    src: &str,
    findings: &mut Vec<Finding>,
    config: &AuditConfig,
    full_src: &str,
) -> Result<(), CliError> {
    let file = syn::parse_file(src).map_err(|err| {
        let start = err.span().start();
        CliError(format!(
            "failed to parse Rust source {}:{}:{}: {err}; expected a complete Rust source file",
            path.display(),
            start.line,
            start.column + 1
        ))
    })?;

    let suppressions = extract_suppressions(full_src);
    let source_lines = SourceLines::new(full_src);

    let findings_before = findings.len();
    let mut suppression_list = suppressions;
    let mut visitor = FunctionVisitor {
        path: path.to_path_buf(),
        findings,
        config,
        suppressions: &mut suppression_list,
        test_context: path
            .components()
            .any(|part| part.as_os_str() == "tests" || part.as_os_str() == "benches"),
        source: &source_lines,
    };
    visitor.visit_file(&file);

    // Issue #351: duplicate/stale suppressions are stale configuration.
    let mut seen: HashSet<(String, usize)> = HashSet::new();
    for suppression in &suppression_list {
        let mut sorted_rules = suppression.rules.clone();
        sorted_rules.sort();
        let key = (sorted_rules.join(","), suppression.line);
        let is_duplicate = !seen.insert(key);
        if !suppression.used || is_duplicate {
            findings.truncate(findings_before);
            let reason = if is_duplicate {
                "duplicate suppression"
            } else {
                "suppression does not apply to any finding"
            };
            return Err(CliError(format!(
                "stale suppression at {}:{}: {reason}; remove or update it",
                path.display(),
                suppression.line
            )));
        }
    }

    normalize_findings(findings);
    Ok(())
}

/// Line-indexed view of the scanned source, used to attach the offending
/// line to each finding. Lines are stored exactly as written off disk or
/// stdin; sanitizing (ANSI/control-character stripping) happens at render
/// time so the stored form can still round-trip in tests of the renderer.
pub struct SourceLines(Vec<String>);

impl SourceLines {
    fn new(src: &str) -> Self {
        Self(src.lines().map(str::to_string).collect())
    }

    /// 1-based accessor matching compiler-style line numbers. Returns
    /// `None` for line 0 (when token spans are unavailable) or any line
    /// past the end of the file.
    pub fn get(&self, line: usize) -> Option<&String> {
        self.0.get(line.checked_sub(1)?)
    }
}

struct Suppression {
    line: usize,
    rules: Vec<String>,
    #[allow(dead_code)]
    reason: Option<String>,
    used: bool,
}

fn find_audit_directive(line: &str) -> Option<&str> {
    // Support multiple suppression comment formats for flexibility
    // Format 1: audit:allow(<rule_id>) or audit:allow_all
    if let Some(pos) = line.to_lowercase().find("audit:allow") {
        let after_audit = &line[pos + "audit:allow".len()..];
        let open_paren = after_audit.find('(')?;
        let close_paren = after_audit.rfind(')')?;
        return Some(&after_audit[open_paren + 1..close_paren]);
    }

    // Format 2: soroban_testkit audit(...) or soroban-testkit audit(...)
    let lower = line.to_lowercase();
    let prefix_pos = lower
        .find("soroban_testkit")
        .or_else(|| lower.find("soroban-testkit"))?;
    let after_prefix = &line[prefix_pos..];
    let audit_pos = after_prefix.to_lowercase().find("audit")?;
    let after_audit = &after_prefix[audit_pos + "audit".len()..];
    let open_paren = after_audit.find('(')?;
    let close_paren = after_audit.rfind(')')?;
    (close_paren > open_paren).then_some(&after_audit[open_paren + 1..close_paren])
}

fn extract_suppressions(src: &str) -> Vec<Suppression> {
    let mut suppressions = Vec::new();
    for (idx, line) in src.lines().enumerate() {
        if let Some(content) = find_audit_directive(line) {
            let mut rules = Vec::new();
            let mut reason = None;

            for part in content.split(',') {
                let part = part.trim();
                let clean = if let Some(stripped) = part
                    .strip_prefix("reason=")
                    .or_else(|| part.strip_prefix("reason ="))
                {
                    reason = Some(
                        stripped
                            .trim()
                            .trim_matches('"')
                            .trim_matches('\'')
                            .to_string(),
                    );
                    continue;
                } else if let Some(stripped) = part
                    .strip_prefix("rule=")
                    .or_else(|| part.strip_prefix("rule ="))
                    .or_else(|| part.strip_prefix("rule:"))
                    .or_else(|| part.strip_prefix("rule :"))
                    .or_else(|| part.strip_prefix("skip-"))
                {
                    stripped
                } else {
                    part
                };

                let clean = clean.trim().trim_matches('"').trim_matches('\'').trim();
                if !clean.is_empty() && clean != "skip" {
                    if clean == "all" || clean == "*" {
                        rules.push("*".to_string());
                    } else {
                        rules.push(clean.to_string());
                    }
                }
            }

            if rules.is_empty() {
                rules.push("*".to_string());
            }

            suppressions.push(Suppression {
                line: idx + 1,
                rules,
                reason,
                used: false,
            });
        }
    }
    suppressions
}

fn item_line_range(node: impl quote::ToTokens) -> (usize, usize) {
    let mut min_line = usize::MAX;
    let mut max_line = 0;
    for token in node.to_token_stream() {
        let span = token.span();
        min_line = min_line.min(span.start().line);
        max_line = max_line.max(span.end().line);
    }
    if min_line == usize::MAX {
        (0, 0)
    } else {
        (min_line, max_line)
    }
}

fn suppression_targets_finding(
    suppression: &Suppression,
    rule: &str,
    finding_line: usize,
    fn_range: Option<(usize, usize)>,
) -> bool {
    let matches_rule = suppression
        .rules
        .iter()
        .any(|item| item == "*" || item == rule);
    matches_rule
        && (suppression.line <= 10
            || suppression.line == finding_line
            || suppression.line + 1 == finding_line
            || fn_range.is_some_and(|(start, end)| {
                suppression.line + 1 >= start && suppression.line <= end
            }))
}

fn is_finding_suppressed(
    suppressions: &mut [Suppression],
    rule: &str,
    finding_line: usize,
    fn_range: Option<(usize, usize)>,
) -> bool {
    let mut suppressed = false;
    for suppression in suppressions.iter_mut() {
        if suppression_targets_finding(suppression, rule, finding_line, fn_range) {
            suppression.used = true;
            suppressed = true;
        }
    }
    suppressed
}

fn is_require_auth_call(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(call) => matches!(
            call.method.unraw().to_string().as_str(),
            "require_auth" | "require_auth_for_args"
        ),
        Expr::Call(call) => match &*call.func {
            Expr::Path(path) => path.path.segments.last().is_some_and(|segment| {
                matches!(
                    segment.ident.unraw().to_string().as_str(),
                    "require_auth" | "require_auth_for_args"
                )
            }),
            _ => false,
        },
        Expr::Paren(paren) => is_require_auth_call(&paren.expr),
        Expr::Group(group) => is_require_auth_call(&group.expr),
        Expr::Try(expr_try) => is_require_auth_call(&expr_try.expr),
        Expr::Await(expr_await) => is_require_auth_call(&expr_await.base),
        _ => false,
    }
}

fn is_negated_condition(expr: &Expr) -> bool {
    match expr {
        Expr::Unary(syn::ExprUnary {
            op: syn::UnOp::Not(_),
            ..
        }) => true,
        Expr::Paren(paren) => is_negated_condition(&paren.expr),
        Expr::Group(group) => is_negated_condition(&group.expr),
        Expr::Binary(syn::ExprBinary {
            left,
            op: BinOp::Eq(_),
            right,
            ..
        }) => is_lit_false(left) || is_lit_false(right),
        Expr::Binary(syn::ExprBinary {
            left,
            op: BinOp::Ne(_),
            right,
            ..
        }) => is_lit_true(left) || is_lit_true(right),
        _ => false,
    }
}

fn is_lit_false(expr: &Expr) -> bool {
    matches!(expr, Expr::Lit(syn::ExprLit { lit: syn::Lit::Bool(value), .. }) if !value.value)
}

fn is_lit_true(expr: &Expr) -> bool {
    matches!(expr, Expr::Lit(syn::ExprLit { lit: syn::Lit::Bool(value), .. }) if value.value)
}

struct AuthVisitor {
    negated_depth: usize,
    has_enforced_auth: bool,
}

impl<'ast> Visit<'ast> for AuthVisitor {
    fn visit_expr(&mut self, expr: &'ast Expr) {
        if is_require_auth_call(expr) && self.negated_depth == 0 {
            self.has_enforced_auth = true;
        }
        visit::visit_expr(self, expr);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        let is_negated = is_negated_condition(&node.cond);
        self.negated_depth += usize::from(is_negated);
        self.visit_block(&node.then_branch);
        self.negated_depth -= usize::from(is_negated);
        if let Some((_, else_branch)) = &node.else_branch {
            self.visit_expr(else_branch);
        }
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        let is_negated = is_negated_condition(&node.cond);
        self.negated_depth += usize::from(is_negated);
        self.visit_block(&node.body);
        self.negated_depth -= usize::from(is_negated);
    }
}

fn has_enforced_require_auth(block: &syn::Block) -> bool {
    let mut visitor = AuthVisitor {
        negated_depth: 0,
        has_enforced_auth: false,
    };
    visitor.visit_block(block);
    visitor.has_enforced_auth
}

/// Returns `true` when the function body contains a call to a helper whose
/// name conventionally signals that it handles authentication or
/// authorization on behalf of the caller (e.g. `check_auth`, `verify_auth`,
/// `assert_authorized`, `require_caller`).  These are heuristic patterns:
/// the check avoids false positives for the common idiom of extracting the
/// `require_auth` call into a shared helper so it cannot be silently omitted
/// at new call sites.
///
/// The rule is intentionally conservative: only function/method calls whose
/// callee name *contains* one of the recognised stems (case-insensitive) are
/// treated as delegated auth.  A call to `check_balance` would not qualify;
/// only calls whose name overlaps with the auth-semantics vocabulary do.
fn calls_auth_helper(block: &syn::Block) -> bool {
    struct AuthHelperVisitor {
        found: bool,
    }

    impl<'ast> Visit<'ast> for AuthHelperVisitor {
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            let name = node.method.unraw().to_string();
            if callee_looks_like_auth_helper(&name) {
                self.found = true;
            }
            visit::visit_expr_method_call(self, node);
        }

        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let Expr::Path(path) = &*node.func {
                if let Some(last) = path.path.segments.last() {
                    let name = last.ident.unraw().to_string();
                    if callee_looks_like_auth_helper(&name) {
                        self.found = true;
                    }
                }
            }
            visit::visit_expr_call(self, node);
        }
    }

    let mut visitor = AuthHelperVisitor { found: false };
    visitor.visit_block(block);
    visitor.found
}

/// Stems that, when present in a callee name, indicate the callee is
/// responsible for verifying the caller's identity or permission.
const AUTH_HELPER_STEMS: &[&str] = &[
    "require_auth",
    "check_auth",
    "verify_auth",
    "assert_auth",
    "ensure_auth",
    "validate_auth",
    "assert_authorized",
    "check_authorized",
    "verify_caller",
    "require_caller",
    "assert_caller",
    "check_caller",
];

fn callee_looks_like_auth_helper(name: &str) -> bool {
    let lower = name.to_lowercase();
    AUTH_HELPER_STEMS.iter().any(|stem| lower.contains(stem))
}

/// True only for cfg predicates that *require* `test` to be enabled.
/// `cfg(any(test, feature = "x"))` is not test-only: it can ship in production.
fn cfg_requires_test(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) if list.path.is_ident("all") || list.path.is_ident("any") => {
            let Ok(parts) = list.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            ) else {
                return false;
            };
            if list.path.is_ident("all") {
                parts.iter().any(cfg_requires_test)
            } else {
                !parts.is_empty() && parts.iter().all(cfg_requires_test)
            }
        }
        _ => false,
    }
}

fn is_test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr
                    .parse_args::<syn::Meta>()
                    .is_ok_and(|meta| cfg_requires_test(&meta)))
    })
}

struct FunctionVisitor<'a> {
    path: PathBuf,
    findings: &'a mut Vec<Finding>,
    config: &'a AuditConfig,
    suppressions: &'a mut [Suppression],
    test_context: bool,
    source: &'a SourceLines,
}

impl<'ast> Visit<'ast> for FunctionVisitor<'_> {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let previous = self.test_context;
        self.test_context |= is_test_only(&node.attrs);
        visit::visit_item_mod(self, node);
        self.test_context = previous;
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let previous = self.test_context;
        self.test_context |= is_test_only(&node.attrs);
        if !self.test_context {
            self.audit_inconsistent_validation(node);
        }
        visit::visit_item_impl(self, node);
        self.test_context = previous;
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let line = line_of(node);
        let fn_range = item_line_range(node);
        let fn_name = node.sig.ident.to_string();
        let body_src = normalized_tokens(node.to_token_stream()).to_string();
        let previous = self.test_context;
        self.test_context |= is_test_only(&node.attrs);
        if !self.test_context {
            self.audit_function(&node.sig, &node.block, body_src.clone(), line, fn_range);
            self.audit_i128_arithmetic(&node.sig, &node.block, line, fn_range);
            self.audit_amount_division(&node.sig, &node.block, fn_range);
            self.audit_narrowing_conversions(&node.sig, &node.block, fn_range);
            self.audit_ignored_contract_call_results(&node.sig, &node.block, fn_range);
            self.audit_storage_write_ttl(&node.sig, &node.block, fn_range);
            self.audit_ignored_transfer_results(&node.sig, &node.block, fn_range);
        }
        self.audit_mock_all_auths(&body_src, line, &fn_name, fn_range);
        visit::visit_item_fn(self, node);
        self.test_context = previous;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let line = line_of(node);
        let fn_range = item_line_range(node);
        let fn_name = node.sig.ident.to_string();
        let body_src = normalized_tokens(node.to_token_stream()).to_string();
        let previous = self.test_context;
        self.test_context |= is_test_only(&node.attrs);
        if !self.test_context {
            self.audit_function(&node.sig, &node.block, body_src.clone(), line, fn_range);
            self.audit_i128_arithmetic(&node.sig, &node.block, line, fn_range);
            self.audit_amount_division(&node.sig, &node.block, fn_range);
            self.audit_narrowing_conversions(&node.sig, &node.block, fn_range);
            self.audit_ignored_contract_call_results(&node.sig, &node.block, fn_range);
            self.audit_storage_write_ttl(&node.sig, &node.block, fn_range);
            self.audit_ignored_transfer_results(&node.sig, &node.block, fn_range);
        }
        self.audit_mock_all_auths(&body_src, line, &fn_name, fn_range);
        visit::visit_impl_item_fn(self, node);
        self.test_context = previous;
    }
}

// Raw spelling does not change an identifier's meaning. Normalize identifiers
// for the token-based heuristics without altering literals or source spans.
fn normalized_tokens(tokens: TokenStream) -> TokenStream {
    tokens
        .into_iter()
        .map(|token| match token {
            TokenTree::Ident(ident) => TokenTree::Ident(ident.unraw()),
            TokenTree::Group(group) => {
                let mut normalized =
                    Group::new(group.delimiter(), normalized_tokens(group.stream()));
                normalized.set_span(group.span());
                TokenTree::Group(normalized)
            }
            other => other,
        })
        .collect()
}

impl FunctionVisitor<'_> {
    fn audit_function(
        &mut self,
        sig: &Signature,
        block: &syn::Block,
        body_src: String,
        line: usize,
        fn_range: (usize, usize),
    ) {
        let name = sig.ident.to_string();

        // Rule 1: an Address parameter that's never checked with require_auth.
        //
        // Two sources of evidence are accepted to avoid false positives:
        //   (a) a direct `require_auth` / `require_auth_for_args` call anywhere
        //       in the function body (possibly via `Address::require_auth(&addr)`),
        //   (b) a call to a helper function whose name contains a recognised
        //       auth-semantics stem (e.g. `check_auth`, `verify_caller`) — the
        //       common pattern of extracting auth into a shared helper.
        if self.is_enabled("missing-require-auth") {
            let address_params = address_typed_params(sig);
            if !address_params.is_empty()
                && !has_enforced_require_auth(block)
                && !calls_auth_helper(block)
            {
                self.push_with_range(
                    line,
                    "missing-require-auth",
                    "warning",
                    format!(
                        "fn {name} takes Address parameter(s) {address_params:?} but never calls \
                         require_auth in its body"
                    ),
                    Some(fn_range),
                );
            }
        }

        // Rule 3: a storage read with no extend_ttl anywhere in the function.
        if self.is_enabled("missing-ttl-bump") {
            let reads_persistent = body_src.contains(". persistent () . get (");
            let reads_temporary = body_src.contains(". temporary () . get (");
            if (reads_persistent || reads_temporary) && !body_src.contains(". extend_ttl (") {
                self.push_with_range(
                    line,
                    "missing-ttl-bump",
                    "warning",
                    format!(
                        "fn {name} reads from {} storage but never calls extend_ttl in its body",
                        if reads_persistent {
                            "persistent"
                        } else {
                            "temporary"
                        }
                    ),
                    Some(fn_range),
                );
            }
        }

        if self.is_enabled("missing-positive-amount-validation") {
            for amount_param in signed_amount_params(sig) {
                if !has_positive_amount_validation(&body_src, &amount_param) {
                    self.push_with_range(
                        line,
                        "missing-positive-amount-validation",
                        "warning",
                        format!(
                            "fn {name} takes signed amount parameter `{amount_param}` but never \
                             validates it against zero"
                        ),
                        Some(fn_range),
                    );
                }
            }
        }

        // Rule 7: unchecked timestamp arithmetic
        if self.is_enabled("unchecked-timestamp-arithmetic") {
            let has_timestamp_ops = body_src.contains("timestamp")
                && (body_src.contains("+")
                    || body_src.contains("-")
                    || body_src.contains("*")
                    || body_src.contains("/"));
            let is_checked = body_src.contains("checked_") || body_src.contains("saturating_");

            if has_timestamp_ops && !is_checked && body_src.contains("timestamp") {
                // Check if it's likely timestamp arithmetic
                if body_src.contains("timestamp()") || body_src.contains("timestamp ") {
                    self.push_with_range(
                        line,
                        "unchecked-timestamp-arithmetic",
                        "warning",
                        format!(
                            "fn {name} performs arithmetic on timestamp values; use checked arithmetic to prevent overflow"
                        ),
                        Some(fn_range),
                    );
                }
            }
        }

        // Rule 8 (#345): zero-value transfers — a transfer call with a literal
        // zero amount is almost always a logic error; policies that forbid zero
        // transfers should catch this statically.
        if self.is_enabled("zero-transfer-amount") {
            // Look for transfer( ... , &0 ) or transfer( ... , 0 ) patterns
            // in the normalised body source.
            let has_zero_transfer = (body_src.contains(". transfer (")
                || body_src.contains(". try_transfer ("))
                && (body_src.contains(", & 0 )")
                    || body_src.contains(", 0 )")
                    || body_src.contains(", & 0i128 )")
                    || body_src.contains(", 0i128 )"));
            if has_zero_transfer {
                self.push_with_range(
                    line,
                    "zero-transfer-amount",
                    "warning",
                    format!(
                        "fn {name} calls transfer with a literal zero amount; validate that amounts are non-zero before transferring"
                    ),
                    Some(fn_range),
                );
            }
        }

        // Rule 9 (#347): arithmetic performed before range validation — detects
        // when arithmetic (+ - * /) on a signed i128 binding appears before any
        // comparison of that binding against a bound in the same function body.
        // This catches the common pattern of computing a result and then checking
        // whether it's valid, rather than checking inputs first.
        if self.is_enabled("arithmetic-before-range-check") {
            for amount_param in signed_amount_params(sig) {
                // Check if arithmetic is used before any range comparison
                let arith_before_check =
                    has_arithmetic_before_range_check(&body_src, &amount_param);
                if arith_before_check {
                    self.push_with_range(
                        line,
                        "arithmetic-before-range-check",
                        "warning",
                        format!(
                            "fn {name} performs arithmetic on `{amount_param}` before validating its range; validate inputs before arithmetic"
                        ),
                        Some(fn_range),
                    );
                }
            }
        }
    }

    fn audit_inconsistent_validation(&mut self, node: &syn::ItemImpl) {
        if !self.is_enabled("inconsistent-validation-across-entry-points") {
            return;
        }

        struct FnInfo {
            name: String,
            line: usize,
            range: (usize, usize),
            amount_params: Vec<String>,
            has_validation: bool,
        }

        let mut infos = Vec::new();
        for item in &node.items {
            let syn::ImplItem::Fn(method) = item else {
                continue;
            };
            if self.test_context || is_test_only(&method.attrs) {
                continue;
            }
            let amount_params = signed_amount_params(&method.sig);
            if amount_params.is_empty() {
                continue;
            }
            let body_src = normalized_tokens(method.to_token_stream()).to_string();
            let has_validation = amount_params
                .iter()
                .all(|p| has_positive_amount_validation(&body_src, p));
            infos.push(FnInfo {
                name: method.sig.ident.to_string(),
                line: line_of(method),
                range: item_line_range(method),
                amount_params,
                has_validation,
            });
        }

        let any_validated = infos.iter().any(|i| i.has_validation);
        let any_unvalidated = infos.iter().any(|i| !i.has_validation);
        if !(any_validated && any_unvalidated) {
            return;
        }

        for info in infos.iter().filter(|i| !i.has_validation) {
            let params = info.amount_params.join(", ");
            self.push_with_range(
                info.line,
                "inconsistent-validation-across-entry-points",
                "warning",
                format!(
                    "fn {} takes signed amount parameter(s) [{params}] without positive validation, \
                     but other related entry points in the same impl validate amount inputs",
                    info.name
                ),
                Some(info.range),
            );
        }
    }

    fn audit_mock_all_auths(
        &mut self,
        body_src: &str,
        line: usize,
        fn_name: &str,
        fn_range: (usize, usize),
    ) {
        if !self.is_enabled("broad-mock-all-auths") {
            return;
        }

        let is_test = fn_name.contains("test") || body_src.contains("#[test]");
        if !is_test {
            return;
        }

        if body_src.contains("mock_all_auths") {
            self.push_with_range(
                line,
                "broad-mock-all-auths",
                "warning",
                format!(
                    "test function {fn_name} uses mock_all_auths; prefer granular auth checks per caller"
                ),
                Some(fn_range),
            );
        }
    }

    fn is_enabled(&self, rule: &str) -> bool {
        self.config
            .rules
            .get(rule)
            .map(|r| r.enabled)
            .unwrap_or(true)
    }

    fn push_with_range(
        &mut self,
        line: usize,
        rule: &'static str,
        default_severity: &'static str,
        message: String,
        fn_range: Option<(usize, usize)>,
    ) {
        if !self.is_enabled(rule) {
            return;
        }

        if is_finding_suppressed(self.suppressions, rule, line, fn_range) {
            return;
        }

        let severity = self
            .config
            .rules
            .get(rule)
            .and_then(|r| r.severity.as_deref())
            .unwrap_or(default_severity);

        // Attach the offending source line before any render step, so every
        // output format gets the same verified context. Lines that carry
        // ANSI codes or control characters stay in this raw form on the
        // struct; sanitizing happens in the renderer.
        let source_snippet = self.source.get(line).cloned();

        let end_line = fn_range.map(|(_, end)| end).filter(|&end| end > line);

        self.findings.push(Finding {
            file: self.path.clone(),
            line,
            end_line,
            rule,
            severity: severity.to_string(),
            message,
            source_snippet,
        });
    }

    fn audit_i128_arithmetic(
        &mut self,
        sig: &Signature,
        body: &syn::Block,
        line: usize,
        fn_range: (usize, usize),
    ) {
        if !self.is_enabled("unchecked-i128-arithmetic") {
            return;
        }

        let mut i128_bindings: HashSet<String> = HashSet::new();
        for arg in &sig.inputs {
            if let FnArg::Typed(pat_type) = arg {
                if type_is_i128(&pat_type.ty) {
                    if let Pat::Ident(ident) = &*pat_type.pat {
                        i128_bindings.insert(ident.ident.unraw().to_string());
                    }
                }
            }
        }

        let mut visitor = I128ArithmeticVisitor {
            path: self.path.clone(),
            fn_name: sig.ident.to_string(),
            fn_line: line,
            fn_range,
            i128_bindings,
            findings: self.findings,
            config: self.config,
            suppressions: self.suppressions,
            source: self.source,
        };
        visitor.visit_block(body);
    }

    fn audit_ignored_contract_call_results(
        &mut self,
        sig: &Signature,
        body: &syn::Block,
        fn_range: (usize, usize),
    ) {
        if !self.is_enabled("ignored-contract-call-result") {
            return;
        }

        let mut visitor = IgnoredContractCallVisitor {
            path: self.path.clone(),
            fn_name: sig.ident.to_string(),
            fn_range,
            findings: self.findings,
            config: self.config,
            suppressions: self.suppressions,
            source: self.source,
        };
        visitor.visit_block(body);
    }

    fn audit_storage_write_ttl(
        &mut self,
        sig: &Signature,
        body: &syn::Block,
        fn_range: (usize, usize),
    ) {
        if !self.is_enabled("storage-write-missing-ttl") {
            return;
        }

        let mut visitor = StorageWriteTtlVisitor {
            tier_bindings: HashMap::new(),
            writes: Vec::new(),
            ttl_extensions: Vec::new(),
        };
        visitor.visit_block(body);

        let fn_name = sig.ident.to_string();
        for (line, end_line, tier) in visitor.writes {
            let has_neighboring_ttl = visitor
                .ttl_extensions
                .iter()
                .any(|ext_tier| ext_tier.is_none() || *ext_tier == Some(tier));
            if !has_neighboring_ttl {
                FindingEmitter {
                    path: &self.path,
                    fn_range,
                    findings: self.findings,
                    config: self.config,
                    suppressions: self.suppressions,
                    source: self.source,
                }
                .emit(
                    "storage-write-missing-ttl",
                    line,
                    Some(end_line),
                    format!(
                        "fn {fn_name} writes to {} storage without a neighboring extend_ttl call; state may expire prematurely",
                        tier.as_str()
                    ),
                );
            }
        }
    }

    fn audit_ignored_transfer_results(
        &mut self,
        sig: &Signature,
        body: &syn::Block,
        _fn_range: (usize, usize),
    ) {
        if !self.is_enabled("ignored-token-transfer-result") {
            return;
        }

        let mut visitor = IgnoredTransferVisitor {
            path: self.path.clone(),
            fn_name: sig.ident.to_string(),
            findings: self.findings,
            config: self.config,
            suppressions: self.suppressions,
            source: self.source,
        };
        visitor.visit_block(body);
    }

    fn audit_amount_division(
        &mut self,
        sig: &Signature,
        body: &syn::Block,
        fn_range: (usize, usize),
    ) {
        if !self.is_enabled("unchecked-amount-division") {
            return;
        }

        let mut visitor = AmountDivisionVisitor {
            path: self.path.clone(),
            fn_name: sig.ident.to_string(),
            fn_range,
            in_amount_local: false,
            findings: self.findings,
            config: self.config,
            suppressions: self.suppressions,
            source: self.source,
        };
        visitor.visit_block(body);
    }

    fn audit_narrowing_conversions(
        &mut self,
        sig: &Signature,
        body: &syn::Block,
        fn_range: (usize, usize),
    ) {
        if !self.is_enabled("unchecked-narrowing-conversion") {
            return;
        }

        let mut bindings = HashMap::new();
        for arg in &sig.inputs {
            if let FnArg::Typed(pat_type) = arg {
                if let Some(info) = parse_int_type(&pat_type.ty) {
                    if let Pat::Ident(ident) = &*pat_type.pat {
                        bindings.insert(ident.ident.unraw().to_string(), info);
                    }
                }
            }
        }

        let mut visitor = NarrowingConversionVisitor {
            path: self.path.clone(),
            fn_name: sig.ident.to_string(),
            fn_range,
            bindings,
            findings: self.findings,
            config: self.config,
            suppressions: self.suppressions,
            source: self.source,
        };
        visitor.visit_block(body);
    }
}

fn signed_amount_params(sig: &Signature) -> Vec<String> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            FnArg::Typed(pat_type) if type_is_signed_integer(&pat_type.ty) => {
                match &*pat_type.pat {
                    Pat::Ident(ident) if ident.ident.to_string().contains("amount") => {
                        Some(ident.ident.unraw().to_string())
                    }
                    _ => None,
                }
            }
            _ => None,
        })
        .collect()
}

fn type_is_signed_integer(ty: &Type) -> bool {
    match ty {
        Type::Reference(reference) => type_is_signed_integer(&reference.elem),
        Type::Path(path) => path.path.get_ident().is_some_and(|ident| {
            matches!(
                ident.unraw().to_string().as_str(),
                "i8" | "i16" | "i32" | "i64" | "i128" | "isize"
            )
        }),
        _ => false,
    }
}

fn has_positive_amount_validation(body_src: &str, amount_param: &str) -> bool {
    let compact = body_src.replace(' ', "");
    [
        format!("{amount_param}>0"),
        format!("{amount_param}>=0"),
        format!("{amount_param}<=0"),
        format!("{amount_param}<0"),
        format!("0<{amount_param}"),
        format!("0<={amount_param}"),
        format!("0>{amount_param}"),
        format!("0>={amount_param}"),
        format!("{amount_param}.is_positive()"),
    ]
    .iter()
    .any(|pattern| compact.contains(pattern))
}

/// Returns `true` when the function body performs arithmetic on `param_name`
/// before any range comparison of that parameter.  The heuristic scans the
/// compact (space-stripped) source for the first arithmetic operator involving
/// `param_name` and the first comparison; if the arithmetic position precedes
/// the comparison position, that is flagged.
fn has_arithmetic_before_range_check(body_src: &str, param_name: &str) -> bool {
    let compact = body_src.replace(' ', "");
    // Arithmetic patterns on the parameter
    let arith_patterns = [
        format!("{param_name}+"),
        format!("{param_name}-"),
        format!("{param_name}*"),
        format!("{param_name}/"),
        format!("+{param_name}"),
        format!("*{param_name}"),
    ];
    // Range-check patterns on the parameter
    let check_patterns = [
        format!("{param_name}>0"),
        format!("{param_name}>=0"),
        format!("{param_name}<=0"),
        format!("{param_name}<0"),
        format!("0<{param_name}"),
        format!("0<={param_name}"),
        format!("0>{param_name}"),
        format!("0>={param_name}"),
        format!("{param_name}.is_positive()"),
        format!("{param_name}.is_negative()"),
        format!("assert!({param_name}"),
        format!("require({param_name}"),
        format!("if{param_name}"),
        format!("if!{param_name}"),
    ];

    let first_arith = arith_patterns
        .iter()
        .filter_map(|p| compact.find(p.as_str()))
        .min();
    let first_check = check_patterns
        .iter()
        .filter_map(|p| compact.find(p.as_str()))
        .min();

    match (first_arith, first_check) {
        // Arithmetic exists but no range check at all
        (Some(_), None) => false, // already caught by missing-positive-amount-validation
        // Both exist — flag if arithmetic comes before the check
        (Some(arith_pos), Some(check_pos)) => arith_pos < check_pos,
        _ => false,
    }
}

fn address_typed_params(sig: &Signature) -> Vec<String> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            FnArg::Typed(pat_type) if type_is_address(&pat_type.ty) => match &*pat_type.pat {
                Pat::Ident(ident) => Some(ident.ident.to_string()),
                _ => Some("<pattern>".to_string()),
            },
            _ => None,
        })
        .collect()
}

fn type_is_address(ty: &Type) -> bool {
    match ty {
        Type::Reference(r) => type_is_address(&r.elem),
        Type::Path(p) => p
            .path
            .segments
            .last()
            .is_some_and(|seg| seg.ident.unraw() == "Address"),
        _ => false,
    }
}

fn line_of(node: impl quote::ToTokens) -> usize {
    node.to_token_stream()
        .into_iter()
        .next()
        .map(|token| token.span().start().line)
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StorageTier {
    Persistent,
    Temporary,
}

impl StorageTier {
    fn as_str(self) -> &'static str {
        match self {
            StorageTier::Persistent => "persistent",
            StorageTier::Temporary => "temporary",
        }
    }
}

struct StorageWriteTtlVisitor {
    tier_bindings: HashMap<String, StorageTier>,
    writes: Vec<(usize, usize, StorageTier)>,
    ttl_extensions: Vec<Option<StorageTier>>,
}

impl StorageWriteTtlVisitor {
    fn infer_storage_tier(&self, expr: &Expr) -> Option<StorageTier> {
        match expr {
            Expr::MethodCall(call) => match call.method.unraw().to_string().as_str() {
                "persistent" => Some(StorageTier::Persistent),
                "temporary" => Some(StorageTier::Temporary),
                _ => None,
            },
            Expr::Path(path) => path
                .path
                .get_ident()
                .and_then(|ident| self.tier_bindings.get(&ident.unraw().to_string()).copied()),
            Expr::Paren(p) => self.infer_storage_tier(&p.expr),
            Expr::Group(g) => self.infer_storage_tier(&g.expr),
            _ => None,
        }
    }
}

impl<'ast> Visit<'ast> for StorageWriteTtlVisitor {
    fn visit_local(&mut self, node: &'ast Local) {
        if let Pat::Ident(ident) = &node.pat {
            if let Some(init) = &node.init {
                if let Some(tier) = self.infer_storage_tier(&init.expr) {
                    self.tier_bindings
                        .insert(ident.ident.unraw().to_string(), tier);
                }
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.unraw().to_string();
        match method.as_str() {
            "set" | "update" => {
                if let Some(tier) = self.infer_storage_tier(&node.receiver) {
                    let line = line_of(node);
                    let (_, end) = item_line_range(node);
                    self.writes.push((line, end, tier));
                }
            }
            "extend_ttl" => {
                let tier = self.infer_storage_tier(&node.receiver);
                self.ttl_extensions.push(tier);
            }
            _ => {}
        }
        visit::visit_expr_method_call(self, node);
    }
}

struct IgnoredContractCallVisitor<'a> {
    path: PathBuf,
    fn_name: String,
    fn_range: (usize, usize),
    findings: &'a mut Vec<Finding>,
    config: &'a AuditConfig,
    suppressions: &'a mut [Suppression],
    source: &'a SourceLines,
}

impl<'ast> Visit<'ast> for IgnoredContractCallVisitor<'_> {
    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        let ignored = match node {
            syn::Stmt::Expr(expr, Some(_)) => contract_call_method_name(expr).map(|m| (expr, m)),
            syn::Stmt::Local(local) if pattern_is_wildcard(&local.pat) => local
                .init
                .as_ref()
                .and_then(|init| contract_call_method_name(&init.expr).map(|m| (&*init.expr, m))),
            _ => None,
        };

        if let Some((expr, method)) = ignored {
            let line = line_of(expr);
            let (_, end) = item_line_range(expr);
            FindingEmitter {
                path: &self.path,
                fn_range: self.fn_range,
                findings: self.findings,
                config: self.config,
                suppressions: self.suppressions,
                source: self.source,
            }
            .emit(
                "ignored-contract-call-result",
                line,
                Some(end),
                format!(
                    "fn {} ignores the Result returned by contract call `{method}`; propagate with `?`, match, or handle the error",
                    self.fn_name
                ),
            );
        }

        visit::visit_stmt(self, node);
    }
}

const NON_CONTRACT_TRY_METHODS: &[&str] = &[
    "try_transfer",
    "try_transfer_from",
    "try_into",
    "try_from",
    "try_fold",
    "try_for_each",
    "try_reduce",
    "try_borrow",
    "try_borrow_mut",
    "try_lock",
    "try_read",
    "try_write",
    "try_recv",
    "try_send",
    "try_reserve",
    "try_reserve_exact",
    "try_clone",
    "try_exists",
];

fn contract_call_method_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::MethodCall(call) => {
            let method = call.method.unraw().to_string();
            if matches!(
                method.as_str(),
                "try_invoke_contract" | "try_invoke_contract_check_auth"
            ) {
                return Some(method);
            }
            if method.starts_with("try_") && !NON_CONTRACT_TRY_METHODS.contains(&method.as_str()) {
                return Some(method);
            }
            if matches!(method.as_str(), "ok" | "err") {
                return contract_call_method_name(&call.receiver);
            }
            None
        }
        Expr::Call(call) => match &*call.func {
            Expr::Path(path) => path.path.segments.last().and_then(|seg| {
                let name = seg.ident.unraw().to_string();
                if matches!(
                    name.as_str(),
                    "try_invoke_contract" | "try_invoke_contract_check_auth"
                ) {
                    Some(name)
                } else {
                    None
                }
            }),
            _ => None,
        },
        Expr::Paren(paren) => contract_call_method_name(&paren.expr),
        Expr::Group(group) => contract_call_method_name(&group.expr),
        _ => None,
    }
}

struct IgnoredTransferVisitor<'a> {
    path: PathBuf,
    fn_name: String,
    findings: &'a mut Vec<Finding>,
    config: &'a AuditConfig,
    suppressions: &'a mut [Suppression],
    source: &'a SourceLines,
}

impl<'ast> Visit<'ast> for IgnoredTransferVisitor<'_> {
    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        let ignored_call = match node {
            syn::Stmt::Expr(expr, _) if transfer_method_name(expr).is_some() => Some(expr),
            syn::Stmt::Local(local)
                if pattern_is_wildcard(&local.pat)
                    && local
                        .init
                        .as_ref()
                        .is_some_and(|init| transfer_method_name(&init.expr).is_some()) =>
            {
                local.init.as_ref().map(|init| &*init.expr)
            }
            _ => None,
        };

        if let Some(expr) = ignored_call {
            let line = line_of(expr);
            let is_suppressed = is_finding_suppressed(
                self.suppressions,
                "ignored-token-transfer-result",
                line,
                None,
            );

            if !is_suppressed {
                let severity = self
                    .config
                    .rules
                    .get("ignored-token-transfer-result")
                    .and_then(|rule| rule.severity.as_deref())
                    .unwrap_or("warning");
                let method = transfer_method_name(expr).unwrap_or("transfer");
                let (_, end) = item_line_range(expr);
                let end_line = if end > line { Some(end) } else { None };
                self.findings.push(Finding {
                    file: self.path.clone(),
                    line,
                    end_line,
                    rule: "ignored-token-transfer-result",
                    severity: severity.to_string(),
                    message: format!(
                        "fn {} ignores the result of token `{method}`; propagate, match, or bind the result",
                        self.fn_name
                    ),
                    source_snippet: self.source.get(line).cloned(),
                });
            }
        }

        visit::visit_stmt(self, node);
    }
}

fn transfer_method_name(expr: &Expr) -> Option<&'static str> {
    match expr {
        Expr::MethodCall(call)
            if matches!(
                call.method.unraw().to_string().as_str(),
                "transfer" | "transfer_from" | "try_transfer" | "try_transfer_from"
            ) =>
        {
            Some(match call.method.unraw().to_string().as_str() {
                "transfer_from" => "transfer_from",
                "try_transfer" => "try_transfer",
                "try_transfer_from" => "try_transfer_from",
                _ => "transfer",
            })
        }
        Expr::Paren(paren) => transfer_method_name(&paren.expr),
        Expr::Group(group) => transfer_method_name(&group.expr),
        _ => None,
    }
}

fn pattern_is_wildcard(pattern: &Pat) -> bool {
    match pattern {
        Pat::Wild(_) => true,
        Pat::Type(typed) => pattern_is_wildcard(&typed.pat),
        _ => false,
    }
}

/// Rule 2 uses a dedicated AST walk (rather than a text search) because
/// "arithmetic on an i128" needs to know which bindings are actually
/// typed `i128`, and a plain string search over the token stream can't
/// tell an `i128` value from the substring appearing anywhere else.
struct I128ArithmeticVisitor<'a> {
    path: PathBuf,
    fn_name: String,
    fn_line: usize,
    fn_range: (usize, usize),
    i128_bindings: HashSet<String>,
    findings: &'a mut Vec<Finding>,
    config: &'a AuditConfig,
    suppressions: &'a mut [Suppression],
    source: &'a SourceLines,
}

impl<'ast> Visit<'ast> for I128ArithmeticVisitor<'_> {
    fn visit_local(&mut self, node: &'ast Local) {
        if let Pat::Type(pat_type) = &node.pat {
            if type_is_i128(&pat_type.ty) {
                if let Pat::Ident(ident) = &*pat_type.pat {
                    self.i128_bindings.insert(ident.ident.unraw().to_string());
                }
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        let is_arith = matches!(
            node.op,
            BinOp::Add(_) | BinOp::Sub(_) | BinOp::Mul(_) | BinOp::Div(_)
        );
        if is_arith && (self.touches_i128(&node.left) || self.touches_i128(&node.right)) {
            let is_suppressed = is_finding_suppressed(
                self.suppressions,
                "unchecked-i128-arithmetic",
                self.fn_line,
                Some(self.fn_range),
            );

            if !is_suppressed {
                let severity = self
                    .config
                    .rules
                    .get("unchecked-i128-arithmetic")
                    .and_then(|r| r.severity.as_deref())
                    .unwrap_or("warning");

                let end_line = if self.fn_range.1 > self.fn_line {
                    Some(self.fn_range.1)
                } else {
                    None
                };

                self.findings.push(Finding {
                    file: self.path.clone(),
                    line: self.fn_line,
                    end_line,
                    rule: "unchecked-i128-arithmetic",
                    severity: severity.to_string(),
                    message: format!(
                        "fn {} does raw arithmetic on an i128 value; prefer checked_/saturating_/ \
                         wrapping_ variants to avoid silent overflow",
                        self.fn_name
                    ),
                    source_snippet: self.source.get(self.fn_line).cloned(),
                });
            }
        }
        visit::visit_expr_binary(self, node);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IntTypeInfo {
    name: &'static str,
    bits: u8,
    is_pointer_sized: bool,
    max_unsigned: u128,
}

fn parse_int_type_name(name: &str) -> Option<IntTypeInfo> {
    match name {
        "u8" => Some(IntTypeInfo {
            name: "u8",
            bits: 8,
            is_pointer_sized: false,
            max_unsigned: u8::MAX as u128,
        }),
        "i8" => Some(IntTypeInfo {
            name: "i8",
            bits: 8,
            is_pointer_sized: false,
            max_unsigned: i8::MAX as u128,
        }),
        "u16" => Some(IntTypeInfo {
            name: "u16",
            bits: 16,
            is_pointer_sized: false,
            max_unsigned: u16::MAX as u128,
        }),
        "i16" => Some(IntTypeInfo {
            name: "i16",
            bits: 16,
            is_pointer_sized: false,
            max_unsigned: i16::MAX as u128,
        }),
        "u32" => Some(IntTypeInfo {
            name: "u32",
            bits: 32,
            is_pointer_sized: false,
            max_unsigned: u32::MAX as u128,
        }),
        "i32" => Some(IntTypeInfo {
            name: "i32",
            bits: 32,
            is_pointer_sized: false,
            max_unsigned: i32::MAX as u128,
        }),
        "u64" => Some(IntTypeInfo {
            name: "u64",
            bits: 64,
            is_pointer_sized: false,
            max_unsigned: u64::MAX as u128,
        }),
        "i64" => Some(IntTypeInfo {
            name: "i64",
            bits: 64,
            is_pointer_sized: false,
            max_unsigned: i64::MAX as u128,
        }),
        "u128" => Some(IntTypeInfo {
            name: "u128",
            bits: 128,
            is_pointer_sized: false,
            max_unsigned: u128::MAX,
        }),
        "i128" => Some(IntTypeInfo {
            name: "i128",
            bits: 128,
            is_pointer_sized: false,
            max_unsigned: i128::MAX as u128,
        }),
        "usize" => Some(IntTypeInfo {
            name: "usize",
            bits: 32,
            is_pointer_sized: true,
            max_unsigned: u32::MAX as u128,
        }),
        "isize" => Some(IntTypeInfo {
            name: "isize",
            bits: 32,
            is_pointer_sized: true,
            max_unsigned: i32::MAX as u128,
        }),
        _ => None,
    }
}

fn parse_int_type(ty: &Type) -> Option<IntTypeInfo> {
    match ty {
        Type::Reference(r) => parse_int_type(&r.elem),
        Type::Group(g) => parse_int_type(&g.elem),
        Type::Paren(p) => parse_int_type(&p.elem),
        Type::Path(p) => p
            .path
            .get_ident()
            .and_then(|ident| parse_int_type_name(&ident.unraw().to_string())),
        _ => None,
    }
}

fn is_narrowing_cast(src: IntTypeInfo, dst: IntTypeInfo) -> bool {
    if src.is_pointer_sized && dst.is_pointer_sized {
        return false;
    }
    if src.is_pointer_sized {
        // On 64-bit targets `usize`/`isize` is 64 bits, so casting to <=32 bits narrows.
        return dst.bits <= 32;
    }
    if dst.is_pointer_sized {
        // On wasm32 (Soroban's target) `usize`/`isize` is 32 bits, so >=64 bits narrows.
        return src.bits >= 64;
    }
    src.bits > dst.bits
}

struct NarrowingConversionVisitor<'a> {
    path: PathBuf,
    fn_name: String,
    fn_range: (usize, usize),
    bindings: HashMap<String, IntTypeInfo>,
    findings: &'a mut Vec<Finding>,
    config: &'a AuditConfig,
    suppressions: &'a mut [Suppression],
    source: &'a SourceLines,
}

impl NarrowingConversionVisitor<'_> {
    fn infer_expr_int_type(&self, expr: &Expr) -> Option<IntTypeInfo> {
        match expr {
            Expr::Paren(p) => self.infer_expr_int_type(&p.expr),
            Expr::Group(g) => self.infer_expr_int_type(&g.expr),
            Expr::Path(p) => p
                .path
                .get_ident()
                .and_then(|ident| self.bindings.get(&ident.unraw().to_string()).copied()),
            Expr::Cast(cast) => parse_int_type(&cast.ty),
            Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(lit),
                ..
            }) => {
                let suffix = lit.suffix();
                if suffix.is_empty() {
                    None
                } else {
                    parse_int_type_name(suffix)
                }
            }
            _ => None,
        }
    }
}

impl<'ast> Visit<'ast> for NarrowingConversionVisitor<'_> {
    fn visit_local(&mut self, node: &'ast Local) {
        if let Pat::Type(pat_type) = &node.pat {
            if let Some(info) = parse_int_type(&pat_type.ty) {
                if let Pat::Ident(ident) = &*pat_type.pat {
                    self.bindings.insert(ident.ident.unraw().to_string(), info);
                }
            }
        } else if let Pat::Ident(ident) = &node.pat {
            if let Some(init) = &node.init {
                if let Some(info) = self.infer_expr_int_type(&init.expr) {
                    self.bindings.insert(ident.ident.unraw().to_string(), info);
                }
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_cast(&mut self, node: &'ast syn::ExprCast) {
        if let Some(dst) = parse_int_type(&node.ty) {
            let is_unsuffixed_fitting_lit = matches!(
                &*node.expr,
                Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(lit), .. })
                    if lit.suffix().is_empty()
                        && lit.base10_parse::<u128>().is_ok_and(|v| v <= dst.max_unsigned)
            );
            if !is_unsuffixed_fitting_lit {
                let should_flag = match self.infer_expr_int_type(&node.expr) {
                    Some(src) => is_narrowing_cast(src, dst),
                    None => dst.bits < 128,
                };
                if should_flag {
                    let line = line_of(node);
                    let (_, end) = item_line_range(node);
                    FindingEmitter {
                        path: &self.path,
                        fn_range: self.fn_range,
                        findings: self.findings,
                        config: self.config,
                        suppressions: self.suppressions,
                        source: self.source,
                    }
                    .emit(
                        "unchecked-narrowing-conversion",
                        line,
                        Some(end),
                        format!(
                            "fn {} performs unchecked narrowing cast `as {}`; use try_into() or TryFrom to avoid silent truncation",
                            self.fn_name, dst.name
                        ),
                    );
                }
            }
        }
        visit::visit_expr_cast(self, node);
    }
}

impl I128ArithmeticVisitor<'_> {
    fn touches_i128(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Path(p) => p
                .path
                .get_ident()
                .is_some_and(|ident| self.i128_bindings.contains(&ident.unraw().to_string())),
            Expr::Lit(lit) => matches!(&lit.lit, syn::Lit::Int(i) if i.suffix() == "i128"),
            Expr::Paren(p) => self.touches_i128(&p.expr),
            Expr::Group(g) => self.touches_i128(&g.expr),
            _ => false,
        }
    }
}

fn type_is_i128(ty: &Type) -> bool {
    matches!(ty, Type::Path(p) if p.path.get_ident().is_some_and(|ident| ident.unraw() == "i128"))
}

struct FindingEmitter<'a> {
    path: &'a Path,
    fn_range: (usize, usize),
    findings: &'a mut Vec<Finding>,
    config: &'a AuditConfig,
    suppressions: &'a mut [Suppression],
    source: &'a SourceLines,
}

impl FindingEmitter<'_> {
    fn emit(&mut self, rule: &'static str, line: usize, end_line: Option<usize>, message: String) {
        if is_finding_suppressed(self.suppressions, rule, line, Some(self.fn_range)) {
            return;
        }
        let severity = self
            .config
            .rules
            .get(rule)
            .and_then(|r| r.severity.as_deref())
            .unwrap_or("warning");
        self.findings.push(Finding {
            file: self.path.to_path_buf(),
            line,
            end_line: end_line.filter(|&end| end > line),
            rule,
            severity: severity.to_string(),
            message,
            source_snippet: self.source.get(line).cloned(),
        });
    }
}

const AMOUNT_STEMS: &[&str] = &[
    "amount",
    "amt",
    "balance",
    "fee",
    "price",
    "rate",
    "reward",
    "payout",
    "share",
    "deposit",
    "withdraw",
    "collateral",
    "principal",
    "interest",
    "supply",
    "total",
    "reserve",
    "mint",
    "burn",
    "swap",
    "liquidity",
];

fn ident_is_amount_related(ident: &str) -> bool {
    let lower = ident.to_ascii_lowercase();
    AMOUNT_STEMS.iter().any(|stem| lower.contains(stem))
}

fn pat_touches_amount(pat: &Pat) -> bool {
    match pat {
        Pat::Ident(ident) => ident_is_amount_related(&ident.ident.unraw().to_string()),
        Pat::Type(typed) => pat_touches_amount(&typed.pat),
        Pat::Tuple(tuple) => tuple.elems.iter().any(pat_touches_amount),
        Pat::Reference(r) => pat_touches_amount(&r.pat),
        _ => false,
    }
}

fn expr_touches_amount(expr: &Expr) -> bool {
    match expr {
        Expr::Path(path) => path
            .path
            .segments
            .iter()
            .any(|seg| ident_is_amount_related(&seg.ident.unraw().to_string())),
        Expr::Field(field) => {
            expr_touches_amount(&field.base)
                || match &field.member {
                    syn::Member::Named(ident) => {
                        ident_is_amount_related(&ident.unraw().to_string())
                    }
                    syn::Member::Unnamed(_) => false,
                }
        }
        Expr::MethodCall(call) => {
            ident_is_amount_related(&call.method.unraw().to_string())
                || expr_touches_amount(&call.receiver)
                || call.args.iter().any(expr_touches_amount)
        }
        Expr::Call(call) => {
            expr_touches_amount(&call.func) || call.args.iter().any(expr_touches_amount)
        }
        Expr::Binary(bin) => expr_touches_amount(&bin.left) || expr_touches_amount(&bin.right),
        Expr::Unary(un) => expr_touches_amount(&un.expr),
        Expr::Cast(cast) => expr_touches_amount(&cast.expr),
        Expr::Reference(r) => expr_touches_amount(&r.expr),
        Expr::Index(idx) => expr_touches_amount(&idx.expr) || expr_touches_amount(&idx.index),
        Expr::Paren(p) => expr_touches_amount(&p.expr),
        Expr::Group(g) => expr_touches_amount(&g.expr),
        _ => false,
    }
}

fn is_nonzero_positive_int_literal(expr: &Expr) -> bool {
    match expr {
        Expr::Paren(p) => is_nonzero_positive_int_literal(&p.expr),
        Expr::Group(g) => is_nonzero_positive_int_literal(&g.expr),
        Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(lit),
            ..
        }) => lit.base10_parse::<u128>().is_ok_and(|v| v > 0),
        _ => false,
    }
}

struct AmountDivisionVisitor<'a> {
    path: PathBuf,
    fn_name: String,
    fn_range: (usize, usize),
    in_amount_local: bool,
    findings: &'a mut Vec<Finding>,
    config: &'a AuditConfig,
    suppressions: &'a mut [Suppression],
    source: &'a SourceLines,
}

impl<'ast> Visit<'ast> for AmountDivisionVisitor<'_> {
    fn visit_local(&mut self, node: &'ast Local) {
        let prev = self.in_amount_local;
        if pat_touches_amount(&node.pat) {
            self.in_amount_local = true;
        }
        visit::visit_local(self, node);
        self.in_amount_local = prev;
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        let is_div = matches!(node.op, BinOp::Div(_) | BinOp::DivAssign(_));
        if is_div
            && !is_nonzero_positive_int_literal(&node.right)
            && (self.in_amount_local
                || expr_touches_amount(&node.left)
                || expr_touches_amount(&node.right))
        {
            let line = line_of(node);
            let (_, end) = item_line_range(node);
            FindingEmitter {
                path: &self.path,
                fn_range: self.fn_range,
                findings: self.findings,
                config: self.config,
                suppressions: self.suppressions,
                source: self.source,
            }
            .emit(
                "unchecked-amount-division",
                line,
                Some(end),
                format!(
                    "fn {} performs unchecked division in amount calculation; use checked_div() to handle division by zero and overflow",
                    self.fn_name
                ),
            );
        }
        visit::visit_expr_binary(self, node);
    }
}

mod tests {
    use super::*;

    fn audit_source_for_test(source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        audit_source(
            Path::new("<test>"),
            source,
            &mut findings,
            &AuditConfig::default(),
            source,
        )
        .unwrap();
        findings
    }

    /// Runs the [`FunctionVisitor`] over `code` once; the handful of
    /// visitor-level tests share it so a visitor change cannot silently
    /// update five different call sites.
    fn unit_findings(code: &str, config: &AuditConfig) -> Vec<Finding> {
        let mut findings = Vec::new();
        let file = syn::parse_file(code).unwrap();
        let mut suppressions = Vec::new();
        let source_lines = SourceLines::new(code);
        let mut visitor = FunctionVisitor {
            path: PathBuf::from("test.rs"),
            findings: &mut findings,
            config,
            suppressions: &mut suppressions,
            source: &source_lines,
            test_context: false,
        };
        visitor.visit_file(&file);
        findings
    }

    #[test]
    fn macro_expanded_entry_point_is_scanned() {
        let findings = audit_source_for_test(
            r#"
            #[contract]
            pub struct Contract;
            #[contractimpl]
            impl Contract {
                pub fn transfer(env: Env, from: Address) {
                    env.storage().instance().set(&from, &1i128);
                }
            }
            "#,
        );
        assert!(findings
            .iter()
            .any(|finding| finding.rule == "missing-require-auth"));
    }

    #[test]
    fn authorized_macro_entry_point_has_no_auth_finding() {
        let findings = audit_source_for_test(
            r#"
            #[contractimpl]
            impl Contract {
                pub fn transfer(env: Env, from: Address) {
                    from.require_auth();
                }
            }
            "#,
        );
        assert!(!findings
            .iter()
            .any(|finding| finding.rule == "missing-require-auth"));
    }

    #[test]
    fn helper_function_performing_auth_suppresses_false_positive() {
        // The entry point delegates require_auth to a helper — a very common
        // pattern for sharing auth logic across entry points.  The scanner
        // must not flag the entry point as missing auth.
        let findings = audit_source_for_test(
            r#"
            fn check_auth(caller: &Address) {
                caller.require_auth();
            }

            #[contractimpl]
            impl Contract {
                pub fn withdraw(env: Env, from: Address) {
                    check_auth(&from);
                    let balance: i128 = env.storage().instance().get(&"bal").unwrap_or(0);
                    env.storage().instance().set(&"bal", &(balance - 1));
                }
            }
            "#,
        );
        assert!(
            !findings.iter().any(|f| f.rule == "missing-require-auth"),
            "false positive: entry point delegates to check_auth helper but was still flagged; \
             findings: {findings:?}"
        );
    }

    #[test]
    fn auth_helper_stems_are_recognised_for_various_naming_conventions() {
        // Covers verify_auth, assert_authorized, require_caller, etc.
        for helper_call in &[
            "verify_auth(&from);",
            "assert_authorized(&from);",
            "require_caller(&from);",
            "self.verify_caller(&from);",
            "ctx.check_auth(&from);",
        ] {
            let source = format!(
                r#"
                #[contractimpl]
                impl Contract {{
                    pub fn transfer(env: Env, from: Address) {{
                        {helper_call}
                    }}
                }}
                "#
            );
            let findings = audit_source_for_test(&source);
            assert!(
                !findings.iter().any(|f| f.rule == "missing-require-auth"),
                "false positive for helper call `{helper_call}`; findings: {findings:?}"
            );
        }
    }

    #[test]
    fn unrelated_helper_call_does_not_suppress_missing_auth_finding() {
        // Calling a helper named `process_payment` must NOT suppress the
        // missing-require-auth finding; only auth-semantics helpers qualify.
        let findings = audit_source_for_test(
            r#"
            #[contractimpl]
            impl Contract {
                pub fn withdraw(env: Env, from: Address) {
                    process_payment(&from);
                }
            }
            "#,
        );
        assert!(
            findings.iter().any(|f| f.rule == "missing-require-auth"),
            "missing-require-auth should still fire when only an unrelated helper is called; \
             findings: {findings:?}"
        );
    }

    #[test]
    fn empty_source_is_a_clean_edge_case() {
        assert!(audit_source_for_test("").is_empty());
    }

    #[test]
    fn test_config_default_enabled() {
        let config = AuditConfig::default();
        assert!(config.rules.is_empty());
    }

    #[test]
    fn test_config_rule_disabled() {
        let mut rules = HashMap::new();
        rules.insert(
            "missing-require-auth".to_string(),
            RuleConfig {
                enabled: false,
                severity: None,
            },
        );
        let config = AuditConfig {
            rules,
            ..Default::default()
        };
        assert!(!config.rules["missing-require-auth"].enabled);
    }

    #[test]
    fn test_config_severity_override() {
        let mut rules = HashMap::new();
        rules.insert(
            "missing-require-auth".to_string(),
            RuleConfig {
                enabled: true,
                severity: Some("error".to_string()),
            },
        );
        let config = AuditConfig {
            rules,
            ..Default::default()
        };
        assert_eq!(
            config.rules["missing-require-auth"].severity,
            Some("error".to_string())
        );
    }

    #[test]
    fn test_missing_require_auth_detected() {
        let findings = unit_findings(
            r#"
            pub fn withdraw(env: &Env, caller: &Address, amount: i128) {
                env.storage().persistent().set(&"amount", &amount);
            }
        "#,
            &AuditConfig::default(),
        );
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule, "missing-require-auth");
    }

    #[test]
    fn test_mock_all_auths_detected() {
        let findings = unit_findings(
            r#"
            #[test]
            fn test_broad_auth() {
                let env = Env::default();
                env.mock_all_auths();
                env.invoke_contract(&contract, &Symbol::new(&env, "transfer"), &args);
            }
        "#,
            &AuditConfig::default(),
        );
        assert!(
            findings.iter().any(|f| f.rule == "broad-mock-all-auths"),
            "Expected to find broad-mock-all-auths finding"
        );
    }

    #[test]
    fn test_rule_disabled_skips_check() {
        let mut rules = HashMap::new();
        rules.insert(
            "missing-require-auth".to_string(),
            RuleConfig {
                enabled: false,
                severity: None,
            },
        );
        let config = AuditConfig {
            rules,
            ..Default::default()
        };
        let findings = unit_findings(
            r#"
            pub fn withdraw(env: &Env, caller: &Address, amount: i128) {
                env.storage().persistent().set(&"amount", &amount);
            }
        "#,
            &config,
        );
        assert!(
            findings.iter().all(|f| f.rule != "missing-require-auth"),
            "Expected no missing-require-auth findings when disabled"
        );
    }

    #[test]
    fn test_severity_override_applied() {
        let mut rules = HashMap::new();
        rules.insert(
            "missing-require-auth".to_string(),
            RuleConfig {
                enabled: true,
                severity: Some("error".to_string()),
            },
        );
        let config = AuditConfig {
            rules,
            ..Default::default()
        };
        let findings = unit_findings(
            r#"
            pub fn withdraw(env: &Env, caller: &Address, amount: i128) {
                env.storage().persistent().set(&"amount", &amount);
            }
        "#,
            &config,
        );
        let auth_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule == "missing-require-auth")
            .collect();
        assert!(!auth_findings.is_empty());
        assert_eq!(auth_findings[0].severity, "error");
    }

    #[test]
    fn test_i128_arithmetic_detection() {
        let findings = unit_findings(
            r#"
            pub fn calculate(amount: i128) -> i128 {
                amount + 100
            }
        "#,
            &AuditConfig::default(),
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == "unchecked-i128-arithmetic"),
            "Expected to find unchecked-i128-arithmetic finding"
        );
    }

    #[test]
    fn missing_positive_amount_validation_is_reported() {
        let findings = audit_source_for_test(
            r#"
            pub fn deposit(amount: i128) {
                save(amount);
            }
            "#,
        );
        assert!(findings
            .iter()
            .any(|finding| finding.rule == "missing-positive-amount-validation"));
    }

    #[test]
    fn comparison_against_zero_satisfies_positive_amount_rule() {
        let findings = audit_source_for_test(
            r#"
            pub fn deposit(amount: i128) {
                assert!(amount > 0);
                save(amount);
            }
            "#,
        );
        assert!(!findings
            .iter()
            .any(|finding| finding.rule == "missing-positive-amount-validation"));
    }

    #[test]
    fn unsigned_amount_is_not_flagged_by_positive_amount_rule() {
        let findings = audit_source_for_test("pub fn deposit(amount: u128) { save(amount); }");
        assert!(!findings
            .iter()
            .any(|finding| finding.rule == "missing-positive-amount-validation"));
    }

    #[test]
    fn ignored_transfer_result_is_reported() {
        let findings = audit_source_for_test(
            r#"
            pub fn pay(token: TokenClient, to: Address, amount: i128) {
                assert!(amount > 0);
                token.try_transfer(&to, &amount);
            }
            "#,
        );
        assert!(findings
            .iter()
            .any(|finding| finding.rule == "ignored-token-transfer-result"));
    }

    #[test]
    fn explicitly_discarded_transfer_result_is_reported() {
        let findings =
            audit_source_for_test("pub fn pay(token: TokenClient) { let _ = token.transfer(); }");
        assert!(findings
            .iter()
            .any(|finding| finding.rule == "ignored-token-transfer-result"));
    }

    #[test]
    fn propagated_or_bound_transfer_results_are_not_reported() {
        let findings = audit_source_for_test(
            r#"
            pub fn pay(token: TokenClient) -> Result<(), Error> {
                token.try_transfer()?;
                let result = token.transfer();
                consume(result);
                Ok(())
            }
            "#,
        );
        assert!(!findings
            .iter()
            .any(|finding| finding.rule == "ignored-token-transfer-result"));
    }

    #[test]
    fn json_output_is_stable_and_machine_readable() {
        let findings = audit_source_for_test("pub fn deposit(amount: i128) { save(amount); }");
        let output = render_findings(&findings, AuditOutputFormat::Json).unwrap();
        let report: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(report["tool"], "soroban-testkit");
        assert_eq!(report["version"], 1);
        assert_eq!(report["summary"]["finding_count"], findings.len());
        assert!(report["findings"].is_array());
    }

    #[test]
    fn json_findings_escape_every_control_character_without_double_escaping() {
        let controls: String = (0..=0x1f).map(char::from).collect();
        let value = format!("{controls}\"\\雪 literal \\n and \\u0000");
        let findings = [Finding {
            file: PathBuf::from(&value),
            line: 1,
            end_line: None,
            rule: "missing-require-auth",
            severity: value.clone(),
            message: value.clone(),
            source_snippet: None,
        }];
        let output = render_findings(&findings, AuditOutputFormat::Json).unwrap();
        let report: serde_json::Value = serde_json::from_str(&output).unwrap();
        for field in ["file", "severity", "message"] {
            assert_eq!(report["findings"][0][field], value);
        }
        assert!(!output.chars().any(|c| c < ' ' && c != '\n'));
        assert!(output.contains("\\u0000"));
        assert!(output.contains("\\t"));
        assert!(output.contains("\\r"));
    }

    #[test]
    fn json_report_lists_parser_limitations_apart_from_findings() {
        let findings = audit_source_for_test("pub fn deposit(amount: i128) { save(amount); }");
        let limitations = vec!["failed to parse Rust source broken.rs:1:8".to_string()];
        let output =
            render_findings_with_limitations(&findings, AuditOutputFormat::Json, &limitations, 1)
                .unwrap();
        let report: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(report["summary"]["finding_count"], findings.len());
        assert_eq!(report["findings"].as_array().unwrap().len(), findings.len());
        assert_eq!(report["summary"]["parser_limitations"][0], limitations[0]);
        assert_eq!(report["summary"]["skipped_file_count"], 1);
    }

    #[test]
    fn sarif_output_contains_code_scanning_location() {
        let findings = audit_source_for_test("pub fn deposit(amount: i128) { save(amount); }");
        let output = render_findings(&findings, AuditOutputFormat::Sarif).unwrap();
        let report: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(report["version"], "2.1.0");
        assert_eq!(
            report["runs"][0]["tool"]["driver"]["name"],
            "soroban-testkit"
        );
        assert_eq!(
            report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "<test>"
        );
    }

    // ---- #489: documented scan roots and exclusions ----

    #[test]
    fn collect_rust_sources_excludes_build_vendor_and_hidden_directories() {
        let root = std::env::temp_dir().join(format!("stk-audit-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("target/debug")).unwrap();
        std::fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        std::fs::create_dir_all(root.join(".git/objects")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn a() {}").unwrap();
        std::fs::write(root.join("target/debug/generated.rs"), "pub fn b() {}").unwrap();
        std::fs::write(root.join("node_modules/pkg/dep.rs"), "pub fn c() {}").unwrap();
        std::fs::write(root.join(".git/objects/blob.rs"), "pub fn d() {}").unwrap();

        let sources = collect_rust_sources(&root, &mut Vec::new()).unwrap();
        assert_eq!(sources, vec![root.join("src/lib.rs")]);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn collect_rust_sources_accepts_a_single_file_root() {
        let root = std::env::temp_dir().join(format!("stk-audit-file-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("only.rs");
        std::fs::write(&file, "pub fn a() {}").unwrap();

        let sources = collect_rust_sources(&file, &mut Vec::new()).unwrap();
        assert_eq!(sources, vec![file]);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn collect_rust_sources_reports_a_missing_root_actionably() {
        let missing = std::env::temp_dir().join("stk-audit-root-that-does-not-exist-anywhere");
        let err = collect_rust_sources(&missing, &mut Vec::new()).unwrap_err();
        assert!(err.0.contains("does not exist"), "{}", err.0);
        assert!(err.0.contains("stdin"), "{}", err.0);
    }

    // ---- #482: findings disclose when they are heuristic, not definitive ----

    #[test]
    fn rendered_outputs_document_the_heuristic_nature_of_findings() {
        let findings = audit_source_for_test("pub fn deposit(amount: i128) { save(amount); }");
        let text = render_findings(&findings, AuditOutputFormat::Text).unwrap();
        assert!(text.contains("note: heuristic"), "{text}");

        let json = render_findings(&findings, AuditOutputFormat::Json).unwrap();
        let report: serde_json::Value = serde_json::from_str(&json).unwrap();
        let limitations = report["summary"]["limitations"].as_array().unwrap();
        assert!(
            limitations
                .iter()
                .any(|l| l.as_str().unwrap().contains("heuristic")),
            "{limitations:?}"
        );

        let sarif = render_findings(&findings, AuditOutputFormat::Sarif).unwrap();
        let report: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let limitations = report["runs"][0]["properties"]["limitations"]
            .as_array()
            .unwrap();
        assert!(
            limitations
                .iter()
                .any(|l| l.as_str().unwrap().contains("heuristic")),
            "{limitations:?}"
        );
    }

    #[test]
    fn clean_reports_still_disclose_the_heuristic_limitation() {
        let text = render_text(&[]);
        assert!(text.contains("audit: no findings"), "{text}");
        assert!(text.contains("macro_rules!"), "{text}");
        assert!(text.contains("heuristic"), "{text}");
    }

    // ---- #483: severity mapping is identical across output formats ----

    #[test]
    fn sarif_level_mapping_is_total_and_shared() {
        assert_eq!(sarif_level("error"), "error");
        assert_eq!(sarif_level("warning"), "warning");
        assert_eq!(sarif_level("note"), "note");
        assert_eq!(sarif_level(""), "note");
        assert_eq!(sarif_level("critical"), "note");
    }

    #[test]
    fn rule_metadata_and_results_agree_for_unconfigured_rules() {
        let findings = audit_source_for_test("pub fn deposit(amount: i128) { save(amount); }");
        for severity in findings.iter().map(|f| f.severity.as_str()) {
            assert_eq!(severity, "warning");
            assert_eq!(sarif_level(severity), "warning");
        }
    }

    // ---- #484: source snippets without terminal control sequences ----

    #[test]
    fn text_and_json_render_snippets_that_stripped_terminal_escapes() {
        let source = "pub fn deposit(env: &Env, from: &Address, amount: i128) { \
                      save(from, amount); } // \u{1b}[31mbold\u{1b}[0m";
        let findings = audit_source_for_test(source);

        let text = render_findings(&findings, AuditOutputFormat::Text).unwrap();
        assert!(
            text.contains("    --> pub fn deposit(env: &Env, from: &Address, amount: i128)"),
            "{text}"
        );
        assert!(text.contains("// bold"), "{text}");
        assert!(!text.contains('\u{1b}'), "{text}");

        let json = render_findings(&findings, AuditOutputFormat::Json).unwrap();
        let report: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            report["findings"][0]["source_snippet"],
            "pub fn deposit(env: &Env, from: &Address, amount: i128) { save(from, amount); } // bold"
        );
    }

    #[test]
    fn snippets_sanitize_without_losing_surrounding_text() {
        // Tab, BEL and DEL collapse; CSI sequences disappear entirely.
        let dirty = "let x = 1;\t\u{7}let y = 2;\u{7f}";
        let clean = sanitize_snippet(dirty);
        assert_eq!(clean, "let x = 1; let y = 2;");
        assert!(!clean.chars().any(char::is_control));
    }

    #[test]
    fn sarif_region_snippets_carry_only_printable_text() {
        let findings = audit_source_for_test("pub fn deposit(amount: i128) { save(amount); }");
        let sarif = render_findings(&findings, AuditOutputFormat::Sarif).unwrap();
        let report: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let snippet = report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
            ["snippet"]["text"]
            .as_str()
            .unwrap();
        assert_eq!(snippet, "pub fn deposit(amount: i128) { save(amount); }");
        assert!(!snippet.chars().any(char::is_control));
    }

    #[test]
    fn snippets_match_the_reported_line_across_rules() {
        let source =
            "pub fn tokenbridge(token: TokenClient) { token.transfer(); token.transfer_from(); }";
        let findings = audit_source_for_test(source);
        for finding in findings
            .iter()
            .filter(|f| f.rule == "ignored-token-transfer-result")
        {
            assert_eq!(finding.source_snippet.as_deref(), Some(source));
        }
    }

    // ---- #488: one canonical path normalization routine ----

    #[test]
    fn canonical_path_maps_equivalent_spellings_to_one_value() {
        let root = std::env::temp_dir().join(format!("stk-audit-canonical-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "").unwrap();

        let expected = fs::canonicalize(root.join("src/lib.rs")).unwrap();
        assert!(expected.is_absolute());
        assert_eq!(canonical_path(&root.join("src/lib.rs")).unwrap(), expected);
        assert_eq!(
            canonical_path(&root.join("src/../src/lib.rs")).unwrap(),
            expected
        );
        assert_eq!(
            canonical_path(&root.join("./src/./lib.rs")).unwrap(),
            expected
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn canonical_path_follows_symlinks_before_comparing() {
        let root = std::env::temp_dir().join(format!("stk-audit-symlink-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("real")).unwrap();
        fs::write(root.join("real/lib.rs"), "").unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();

        assert_eq!(
            canonical_path(&root.join("link/lib.rs")).unwrap(),
            canonical_path(&root.join("real/lib.rs")).unwrap()
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn canonical_path_failure_names_the_path_and_the_check_to_make() {
        let missing = std::env::temp_dir()
            .join(format!(
                "stk-audit-canonical-missing-{}",
                std::process::id()
            ))
            .join("nope.rs");
        let message = canonical_path(&missing).unwrap_err().0;
        assert!(message.contains("failed to resolve path"), "{message}");
        assert!(message.contains("nope.rs"), "{message}");
        assert!(message.contains("verify the path exists"), "{message}");
    }

    #[test]
    fn workspace_relative_path_normalizes_before_stripping_the_root() {
        let root =
            std::env::temp_dir().join(format!("stk-audit-ws-relative-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "").unwrap();
        let workspace = fs::canonicalize(&root).unwrap();

        assert_eq!(
            workspace_relative_path(&workspace.join("src/../src/lib.rs"), &workspace),
            PathBuf::from("src/lib.rs")
        );
        assert_eq!(
            workspace_relative_path(&workspace.join("src/lib.rs"), &workspace),
            PathBuf::from("src/lib.rs")
        );

        // A file outside the workspace keeps its full canonical path instead
        // of a misleading stripped one.
        let outside =
            std::env::temp_dir().join(format!("stk-audit-outside-{}", std::process::id()));
        fs::write(&outside, "").unwrap();
        assert_eq!(
            workspace_relative_path(&outside, &workspace),
            fs::canonicalize(&outside).unwrap()
        );

        let _ = fs::remove_file(&outside);
        let _ = fs::remove_dir_all(&root);
    }

    // ---- #485: findings sort by file, line, rule, and message ----

    fn sample_finding(file: &str, line: usize, rule: &'static str, message: &str) -> Finding {
        Finding {
            file: PathBuf::from(file),
            line,
            end_line: None,
            rule,
            severity: "warning".to_string(),
            message: message.to_string(),
            source_snippet: None,
        }
    }

    #[test]
    fn normalize_findings_orders_by_file_line_rule_and_message() {
        let mut findings = vec![
            sample_finding("b.rs", 9, "missing-ttl-bump", "later file"),
            sample_finding("a.rs", 9, "missing-require-auth", "second message"),
            sample_finding("a.rs", 2, "missing-require-auth", "first line"),
            sample_finding("a.rs", 9, "missing-require-auth", "another message"),
            // The rule sorts before the message does, so a lexicographically
            // later message still lands first when its rule is smaller.
            sample_finding("a.rs", 9, "missing-positive-amount-validation", "z message"),
        ];

        normalize_findings(&mut findings);

        let ordered: Vec<_> = findings
            .iter()
            .map(|f| (f.file.to_str().unwrap(), f.line, f.message.as_str()))
            .collect();
        assert_eq!(
            ordered,
            vec![
                ("a.rs", 2, "first line"),
                ("a.rs", 9, "z message"),
                ("a.rs", 9, "another message"),
                ("a.rs", 9, "second message"),
                ("b.rs", 9, "later file"),
            ]
        );
    }

    #[test]
    fn normalize_findings_collapses_only_exact_duplicates() {
        let mut findings = vec![
            sample_finding(
                "a.rs",
                1,
                "missing-positive-amount-validation",
                "fn f takes `amount1`",
            ),
            sample_finding(
                "a.rs",
                1,
                "missing-positive-amount-validation",
                "fn f takes `amount2`",
            ),
            sample_finding(
                "a.rs",
                1,
                "missing-positive-amount-validation",
                "fn f takes `amount1`",
            ),
        ];

        normalize_findings(&mut findings);

        let messages: Vec<_> = findings.iter().map(|f| f.message.as_str()).collect();
        assert_eq!(
            messages,
            vec!["fn f takes `amount1`", "fn f takes `amount2`"]
        );
    }

    #[test]
    fn test_renderer_color_and_no_color() {
        let findings = vec![sample_finding(
            "a.rs",
            10,
            "missing-require-auth",
            "fn withdraw needs auth",
        )];
        let renderer = DiagnosticRenderer::new(&findings);
        let colored = renderer.render_text_colored(true);
        let plain = renderer.render_text_colored(false);

        assert!(
            colored.contains("\x1b["),
            "colored text must contain ANSI escape codes"
        );
        assert!(
            !plain.contains("\x1b["),
            "plain text must not contain ANSI escape codes"
        );

        let summary_colored = renderer.render_text_summary_colored(true);
        let summary_plain = renderer.render_text_summary_colored(false);

        assert!(
            summary_colored.contains("\x1b["),
            "colored summary must contain ANSI escape codes"
        );
        assert!(
            !summary_plain.contains("\x1b["),
            "plain summary must not contain ANSI escape codes"
        );

        let empty_renderer = DiagnosticRenderer::new(&[]);
        assert!(empty_renderer
            .render_text_summary_colored(true)
            .contains("\x1b["));
        assert!(!empty_renderer
            .render_text_summary_colored(false)
            .contains("\x1b["));
    }

    #[test]
    fn test_should_color_flag_precedence() {
        assert!(!should_color(true));
    }

    #[test]
    fn test_width_wrapping_and_validation() {
        let prefix = "src/lib.rs:1: [warning] rule: "; // 30 chars
        let message = "one two three four five six seven";

        // No width: single line
        let no_wrap = wrap_finding_message(prefix, message, None);
        assert_eq!(no_wrap, format!("{prefix}{message}\n"));

        // Width 40: "src/lib.rs:1: [warning] rule: one two\n    three four\n    five six\n    seven\n"
        let wrapped_40 = wrap_finding_message(prefix, message, Some(40));
        for line in wrapped_40.lines() {
            assert!(visible_width(line) <= 40, "line exceeds width 40: {line}");
        }

        // Exact fit vs one character over
        // prefix is 30. "hello" is 5. Total = 35.
        let fit = wrap_finding_message(prefix, "hello", Some(35));
        assert_eq!(fit.lines().count(), 1, "exact fit must not wrap: {fit}");

        // "hello!" is 6. Total = 36. At width 35, it wraps!
        let one_over = wrap_finding_message(prefix, "hello!", Some(35));
        assert_eq!(
            one_over.lines().count(),
            2,
            "one over must wrap: {one_over}"
        );

        // Unbreakable token longer than width is not split
        let long_token = "verylongunbreakabletokenlongerthanwidth";
        let wrapped_token = wrap_finding_message(prefix, long_token, Some(25));
        assert!(
            wrapped_token.contains(long_token),
            "token must not be split: {wrapped_token}"
        );

        // Width smaller than prefix
        let small_width = wrap_finding_message(prefix, "a b c", Some(20));
        let lines: Vec<_> = small_width.lines().collect();
        assert_eq!(
            lines[0],
            prefix.trim_end(),
            "prefix must remain intact on line 1"
        );
        assert!(
            lines[1].starts_with("    "),
            "continuation line must be indented"
        );

        // Colored prefix wraps at identical word boundaries
        let colored_prefix = "\x1b[1msrc/lib.rs:1:\x1b[0m \x1b[1;33m[warning]\x1b[0m rule: ";
        let wrapped_colored = wrap_finding_message(colored_prefix, message, Some(40));
        let plain_lines: Vec<_> = wrapped_40.lines().collect();
        let colored_lines: Vec<_> = wrapped_colored.lines().collect();
        assert_eq!(plain_lines.len(), colored_lines.len());

        // Multi-byte Unicode characters counted as 1
        assert_eq!(visible_width("雪花"), 2);

        // Validation of invalid width values
        assert!(validate_width_str("0").is_err());
        assert!(validate_width_str("-5").is_err());
        assert!(validate_width_str("abc").is_err());
        assert!(validate_width_str("10000").is_err());
        assert!(validate_width_str("80").is_ok());
    }

    #[test]
    fn test_rule_registry_confidence_and_limitations() {
        let valid_confidence = ["high", "medium", "low", "not assessed"];
        for rule in RULES {
            assert!(
                valid_confidence.contains(&rule.confidence),
                "rule {} has invalid confidence level '{}'",
                rule.id,
                rule.confidence
            );
            assert!(
                !rule.limitations.is_empty(),
                "rule {} must have at least one limitation or 'none known'",
                rule.id
            );
            for lim in rule.limitations {
                assert!(
                    !lim.trim().is_empty(),
                    "rule {} has empty limitation string",
                    rule.id
                );
            }
        }
    }

    #[test]
    fn sarif_rule_help_uri_builds_valid_anchors_and_rejects_empty_ids() {
        assert_eq!(sarif_rule_help_uri(""), None);
        assert_eq!(sarif_rule_help_uri("   "), None);
        let uri = sarif_rule_help_uri("missing-require-auth").unwrap();
        assert!(uri.starts_with("https://"), "{uri}");
        assert!(uri.ends_with("#missing-require-auth"), "{uri}");
    }

    #[test]
    fn sarif_output_includes_rule_help_uris() {
        let findings = audit_source_for_test(
            "pub fn deposit(from: Address, amount: i128) { let _ = amount + 1; }",
        );
        let sarif = render_findings(&findings, AuditOutputFormat::Sarif).unwrap();
        let report: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let rules = report["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert!(rules.len() >= 2, "{rules:?}");
        let mut seen_uris = HashSet::new();
        for rule in rules {
            let id = rule["id"].as_str().unwrap();
            let help_uri = rule["helpUri"].as_str().unwrap();
            assert!(help_uri.starts_with("https://"), "{help_uri}");
            assert!(help_uri.ends_with(&format!("#{id}")), "{help_uri}");
            assert!(
                seen_uris.insert(help_uri.to_string()),
                "duplicate {help_uri}"
            );
        }
    }

    #[test]
    fn apply_selected_rules_filters_to_requested_identifiers_and_preserves_severity() {
        let mut config = AuditConfig::default();
        config.rules.insert(
            "missing-require-auth".to_string(),
            RuleConfig {
                enabled: false,
                severity: Some("error".to_string()),
            },
        );
        apply_selected_rules(&["missing-require-auth".to_string()], &mut config).unwrap();
        assert!(config.rules["missing-require-auth"].enabled);
        assert_eq!(
            config.rules["missing-require-auth"].severity.as_deref(),
            Some("error")
        );
        assert!(!config.rules["unchecked-i128-arithmetic"].enabled);

        let mut findings = Vec::new();
        audit_source(
            Path::new("<test>"),
            "pub fn withdraw(env: Env, from: Address, amount: i128) { let _ = amount + 1; }",
            &mut findings,
            &config,
            "pub fn withdraw(env: Env, from: Address, amount: i128) { let _ = amount + 1; }",
        )
        .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "missing-require-auth");
        assert_eq!(findings[0].severity, "error");
    }

    #[test]
    fn apply_selected_rules_rejects_empty_and_unknown_identifiers() {
        let mut config = AuditConfig::default();
        let empty_err = apply_selected_rules(&["".to_string()], &mut config).unwrap_err();
        assert!(empty_err.0.contains("cannot be empty"), "{}", empty_err.0);

        let unknown_err =
            apply_selected_rules(&["not-a-real-rule".to_string()], &mut config).unwrap_err();
        assert!(
            unknown_err
                .0
                .contains("unknown audit rule `not-a-real-rule`"),
            "{}",
            unknown_err.0
        );
        assert!(unknown_err.0.contains("audit rules"), "{}", unknown_err.0);
    }

    #[test]
    fn sarif_includes_tool_version_and_invocation_metadata() {
        let findings = audit_source_for_test("pub fn deposit(amount: i128) { save(amount); }");
        let sarif = render_findings_with_limitations_and_scanned(
            &findings,
            AuditOutputFormat::Sarif,
            &[],
            0,
            2,
        )
        .unwrap();
        let report: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let driver = &report["runs"][0]["tool"]["driver"];
        assert_eq!(driver["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(driver["semanticVersion"], env!("CARGO_PKG_VERSION"));
        assert_eq!(driver["informationUri"], env!("CARGO_PKG_REPOSITORY"));

        let invocation = &report["runs"][0]["invocations"][0];
        assert_eq!(invocation["executionSuccessful"], true);
        assert_eq!(invocation["properties"]["filesScanned"], 2);
        assert_eq!(invocation["properties"]["skippedFileCount"], 0);
        assert_eq!(invocation["properties"]["findingCount"], findings.len());

        let failed_sarif = render_findings_with_limitations_and_scanned(
            &findings,
            AuditOutputFormat::Sarif,
            &["failed to parse broken.rs".to_string()],
            1,
            1,
        )
        .unwrap();
        let failed_report: serde_json::Value = serde_json::from_str(&failed_sarif).unwrap();
        assert_eq!(
            failed_report["runs"][0]["invocations"][0]["executionSuccessful"],
            false
        );
        assert_eq!(
            failed_report["runs"][0]["invocations"][0]["properties"]["skippedFileCount"],
            1
        );
    }

    #[test]
    fn build_baseline_entries_deduplicates_same_file_line_and_rule() {
        let mut findings = vec![
            sample_finding("src/lib.rs", 4, "unchecked-i128-arithmetic", "msg 1"),
            sample_finding("src/lib.rs", 4, "unchecked-i128-arithmetic", "msg 2"),
            sample_finding("src/lib.rs", 10, "missing-require-auth", "msg 3"),
        ];
        normalize_findings(&mut findings);
        let entries = build_baseline_entries(&findings);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].file, "src/lib.rs");
        assert_eq!(entries[0].line, 4);
        assert_eq!(entries[0].rule, "unchecked-i128-arithmetic");
        assert_eq!(entries[1].line, 10);
    }

    #[test]
    fn write_baseline_file_writes_valid_json_and_rejects_directory() {
        let root = std::env::temp_dir().join(format!("stk-baseline-unit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let dir_err = write_baseline_file(&root, &[]).unwrap_err();
        assert!(dir_err.0.contains("is a directory"), "{}", dir_err.0);

        let target = root.join("nested/baseline.json");
        let findings = vec![sample_finding(
            "crates/vault/src/lib.rs",
            3,
            "missing-require-auth",
            "missing auth",
        )];
        let written = write_baseline_file(&target, &findings).unwrap();
        assert_eq!(written.len(), 1);
        let loaded = load_baseline(&Some(target.clone())).unwrap();
        assert_eq!(loaded, written);

        let _ = std::fs::remove_dir_all(&root);
    }
}
