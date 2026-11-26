//! Integration tests for `soroban-testkit audit`.
//!
//! Exercises the CLI binary's documented scan roots (directory, single file,
//! and stdin) and its directory exclusions (`target/`, `vendor/`,
//! `node_modules/`, and hidden directories), plus the actionable error for
//! a missing path.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn run(args: &[&str]) -> Output {
    run_from(&workspace_root(), args)
}

fn run_from(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-testkit"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("failed to run soroban-testkit")
}

fn run_from_with_env(
    dir: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
    remove_envs: &[&str],
) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_soroban-testkit"));
    cmd.args(args).current_dir(dir);
    for var in remove_envs {
        cmd.env_remove(var);
    }
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run soroban-testkit")
}

struct AuditFixture(PathBuf);

impl AuditFixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("stk-audit-{name}-{}", std::process::id()));
        std::fs::create_dir_all(root.join("crates/vault/src")).unwrap();
        std::fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
        Self(root)
    }

    fn write(&self, path: &str, content: impl AsRef<[u8]>) -> PathBuf {
        let path = self.0.join(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, content).unwrap();
        path
    }

    fn scan(&self, args: &[&str]) -> Output {
        let mut scan_args = vec!["audit", "."];
        if !args.contains(&"--format") {
            scan_args.extend_from_slice(&["--format", "json"]);
        }
        scan_args.extend_from_slice(args);
        run_from(&self.0, &scan_args)
    }
}

impl Drop for AuditFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_with_stdin(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_soroban-testkit"))
        .args(args)
        .current_dir(workspace_root())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to run soroban-testkit");
    std::io::Write::write_all(child.stdin.as_mut().unwrap(), stdin).unwrap();
    child.wait_with_output().unwrap()
}

/// A source snippet that trips `missing-require-auth`.
const UNAUTHORIZED_ENTRY_POINT: &str = r#"
#[contractimpl]
impl Contract {
    pub fn withdraw(env: Env, from: Address) {
        env.storage().instance().set(&from, &1i128);
    }
}
"#;

#[test]
fn audit_help_documents_supported_scan_roots_and_exclusions() {
    let output = run(&["audit", "--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Scan roots.
    assert!(stdout.contains("stdin"), "{stdout}");
    assert!(stdout.contains("directory"), "{stdout}");
    // Documented exclusions.
    assert!(stdout.contains("target/"), "{stdout}");
    assert!(stdout.contains("vendor/"), "{stdout}");
    assert!(stdout.contains("node_modules/"), "{stdout}");
    assert!(stdout.contains("hidden"), "{stdout}");
    // Standard options remain documented.
    assert!(stdout.contains("--format"), "{stdout}");
    assert!(stdout.contains("--strict"), "{stdout}");
}

#[test]
fn audit_scans_a_directory_recursively() {
    let root = std::env::temp_dir().join(format!("stk-audit-dir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src/nested")).unwrap();
    std::fs::write(root.join("src/lib.rs"), UNAUTHORIZED_ENTRY_POINT).unwrap();
    std::fs::write(root.join("src/nested/more.rs"), UNAUTHORIZED_ENTRY_POINT).unwrap();

    let output = run(&["audit", root.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("src/lib.rs"), "{stdout}");
    assert!(stdout.contains("src/nested/more.rs"), "{stdout}");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn audit_skips_excluded_directories() {
    let root = std::env::temp_dir().join(format!("stk-audit-exclude-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("target/debug")).unwrap();
    std::fs::create_dir_all(root.join("vendor/dep/src")).unwrap();
    std::fs::create_dir_all(root.join("src/nested/target/debug")).unwrap();
    std::fs::create_dir_all(root.join("src/nested/vendor/dep")).unwrap();
    std::fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
    std::fs::create_dir_all(root.join(".git/objects")).unwrap();
    std::fs::write(root.join("src/vault.rs"), UNAUTHORIZED_ENTRY_POINT).unwrap();
    std::fs::write(
        root.join("target/debug/generated.rs"),
        UNAUTHORIZED_ENTRY_POINT,
    )
    .unwrap();
    std::fs::write(
        root.join("node_modules/pkg/dep.rs"),
        UNAUTHORIZED_ENTRY_POINT,
    )
    .unwrap();
    std::fs::write(root.join(".git/objects/blob.rs"), UNAUTHORIZED_ENTRY_POINT).unwrap();
    for path in [
        "vendor/dep/src/vendored.rs",
        "src/nested/target/debug/generated_nested.rs",
        "src/nested/vendor/dep/vendored_nested.rs",
    ] {
        // Prune the whole tree: even invalid Rust must not cause a scan error.
        std::fs::write(root.join(path), "fn invalid(").unwrap();
    }

    let output = run(&["audit", root.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("src/vault.rs"), "{stdout}");
    // Excluded trees must never be scanned.
    assert!(!stdout.contains("generated.rs"), "{stdout}");
    assert!(!stdout.contains("dep.rs"), "{stdout}");
    assert!(!stdout.contains("blob.rs"), "{stdout}");
    assert!(!stdout.contains("vendored"), "{stdout}");
    assert!(output.stderr.is_empty(), "{output:?}");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn audit_scans_explicitly_selected_excluded_roots_and_similarly_named_directories() {
    let fixture = AuditFixture::new("explicit-exclusions");
    for directory in ["target", "vendor", "vendors", "target_contract"] {
        std::fs::create_dir_all(fixture.0.join(directory)).unwrap();
        let file = fixture.write(&format!("{directory}/lib.rs"), UNAUTHORIZED_ENTRY_POINT);
        for root in [file.parent().unwrap(), file.as_path()] {
            let output = run_from(
                &fixture.0,
                &[
                    "audit",
                    root.to_str().unwrap(),
                    "--format",
                    "json",
                    "--strict",
                ],
            );
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert!(!output.status.success(), "{output:?}");
            assert_eq!(report["summary"]["finding_count"], 1, "{report}");
            assert_eq!(report["findings"][0]["rule"], "missing-require-auth");
        }
    }

    let output = fixture.scan(&[]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 2, "{report}");
}

#[test]
fn audit_raw_identifiers_report_the_same_rules_as_ordinary_identifiers() {
    let fixture = AuditFixture::new("raw-identifiers");
    let ordinary = r#"
        fn withdraw(env: Env, caller: &sdk::Address, amount: i128, client: Client) {
            let balance: i128 = 10;
            let _ = balance + 1;
            let _ = amount + 1;
            env.storage().persistent().get(&"balance");
            client.try_transfer(&caller, &caller, &amount);
        }
    "#;
    let raw = r#"
        fn r#type(r#env: Env, r#caller: &sdk::r#Address, r#amount: r#i128, client: Client) {
            let r#balance: r#i128 = 10;
            let _ = balance + 1;
            let _ = amount + 1;
            env.r#storage().r#persistent().r#get(&"balance");
            client.r#try_transfer(&caller, &caller, &amount);
        }
    "#;
    let mut reports = Vec::new();
    for source in [ordinary, raw] {
        fixture.write("crates/vault/src/lib.rs", source);
        let output = fixture.scan(&["--strict"]);
        assert!(!output.status.success(), "{output:?}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let findings = report["findings"].as_array().unwrap();
        let mut rules: Vec<_> = findings
            .iter()
            .map(|f| f["rule"].as_str().unwrap().to_owned())
            .collect();
        rules.sort();
        reports.push(rules);
        for finding in findings {
            assert!(finding["line"].as_u64().unwrap() > 0, "{finding}");
            if source == raw {
                assert!(
                    finding["message"].as_str().unwrap().contains("fn r#type"),
                    "{finding}"
                );
            }
        }
    }
    // Six raw findings fire (require-auth, ttl, positive-amount, transfer,
    // and two i128 additions), but the two i128 findings share a
    // file/line/column/rule and collapse, so both spellings report five.
    assert_eq!(reports[0].len(), 5, "{reports:?}");
    assert_eq!(reports[0], reports[1]);
}

#[test]
fn audit_raw_identifiers_preserve_checked_operations() {
    let fixture = AuditFixture::new("raw-identifiers-checked");
    fixture.write(
        "crates/vault/src/lib.rs",
        r#"
        impl Contract {
            fn r#type(env: Env, caller: &r#Address, r#amount: r#i128, client: Client) {
                caller.r#require_auth();
                assert!(amount > 0);
                let balance: i128 = 10;
                let _ = r#balance.r#checked_add(r#amount);
                env.r#storage().r#persistent().r#get(&"balance");
                env.r#storage().r#persistent().r#extend_ttl(&"balance", 1, 2);
                let _result = client.r#try_transfer(&caller, &caller, &amount);
            }
        }
    "#,
    );
    let output = fixture.scan(&["--strict"]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 0, "{report}");
}

#[test]
fn audit_accepts_empty_files_and_stdin_in_every_format() {
    let fixture = AuditFixture::new("empty-source");
    for source in ["", " \n\t\r\n", "// no items\n/* still empty */\n"] {
        let file = fixture.write("crates/vault/src/lib.rs", source);
        for format in ["text", "json", "sarif"] {
            let outputs = [
                fixture.scan(&["--format", format, "--strict"]),
                run_from(
                    &fixture.0,
                    &[
                        "audit",
                        file.to_str().unwrap(),
                        "--format",
                        format,
                        "--strict",
                    ],
                ),
                run_with_stdin(
                    &["audit", "-", "--format", format, "--strict"],
                    source.as_bytes(),
                ),
            ];
            for output in outputs {
                assert!(output.status.success(), "{format}: {output:?}");
                assert!(output.stderr.is_empty(), "{format}: {output:?}");
                match format {
                    "text" => assert!(
                        String::from_utf8_lossy(&output.stdout).contains("audit: no findings")
                    ),
                    "json" => {
                        let report: serde_json::Value =
                            serde_json::from_slice(&output.stdout).unwrap();
                        assert_eq!(report["summary"]["finding_count"], 0);
                    }
                    "sarif" => {
                        let report: serde_json::Value =
                            serde_json::from_slice(&output.stdout).unwrap();
                        assert_eq!(report["runs"][0]["results"].as_array().unwrap().len(), 0);
                    }
                    _ => unreachable!(),
                }
            }
        }
    }
}

#[test]
fn audit_empty_file_does_not_hide_findings_in_other_files() {
    let fixture = AuditFixture::new("empty-with-findings");
    fixture.write("crates/vault/src/empty.rs", "");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let output = fixture.scan(&["--strict"]);
    assert!(!output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 1, "{report}");
    assert_eq!(report["findings"][0]["rule"], "missing-require-auth");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("audit incomplete"),
        "{output:?}"
    );
}

#[test]
fn audit_scans_a_single_file_root() {
    let root = std::env::temp_dir().join(format!("stk-audit-single-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let file = root.join("only.rs");
    std::fs::write(&file, UNAUTHORIZED_ENTRY_POINT).unwrap();

    let output = run(&["audit", file.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("only.rs"), "{stdout}");
    assert!(stdout.contains("missing-require-auth"), "{stdout}");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn audit_scans_stdin_with_dash() {
    let output = run_with_stdin(&["audit", "-"], UNAUTHORIZED_ENTRY_POINT.as_bytes());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("<stdin>"), "{stdout}");
    assert!(stdout.contains("missing-require-auth"), "{stdout}");
}

#[test]
fn audit_reports_a_missing_path_actionably() {
    let missing = std::env::temp_dir()
        .join("stk-audit-path-that-does-not-exist")
        .join("nope");
    let output = run(&["audit", missing.to_str().unwrap()]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does not exist"), "{stderr}");
    assert!(stderr.contains("stdin"), "{stderr}");
}

#[test]
fn audit_json_output_reports_findings_in_a_temp_crate() {
    let root = std::env::temp_dir().join(format!("stk-audit-json-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/vault.rs"), UNAUTHORIZED_ENTRY_POINT).unwrap();

    let output = run(&["audit", root.to_str().unwrap(), "--format", "json"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["tool"], "soroban-testkit");
    assert!(report["summary"]["finding_count"].as_u64().unwrap() >= 1);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn audit_sarif_output_reports_findings_and_rules() {
    let root = std::env::temp_dir().join(format!("stk-audit-sarif-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/vault.rs"), UNAUTHORIZED_ENTRY_POINT).unwrap();

    let output = run(&["audit", root.to_str().unwrap(), "--format", "sarif"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["version"], "2.1.0");
    assert_eq!(
        report["runs"][0]["tool"]["driver"]["name"],
        "soroban-testkit"
    );
    let results = report["runs"][0]["results"].as_array().unwrap();
    assert!(!results.is_empty());
    assert_eq!(results[0]["ruleId"], "missing-require-auth");
    assert!(
        results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap()
            .contains("vault.rs")
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn audit_diagnostic_formats_agree_on_finding_counts() {
    let root = std::env::temp_dir().join(format!("stk-audit-diag-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/vault.rs"), UNAUTHORIZED_ENTRY_POINT).unwrap();

    let text_out = run(&["audit", root.to_str().unwrap(), "--format", "text"]);
    let json_out = run(&["audit", root.to_str().unwrap(), "--format", "json"]);
    let sarif_out = run(&["audit", root.to_str().unwrap(), "--format", "sarif"]);

    assert!(text_out.status.success());
    assert!(json_out.status.success());
    assert!(sarif_out.status.success());

    let json_report: serde_json::Value = serde_json::from_slice(&json_out.stdout).unwrap();
    let json_count = json_report["summary"]["finding_count"].as_u64().unwrap();

    let sarif_report: serde_json::Value = serde_json::from_slice(&sarif_out.stdout).unwrap();
    let sarif_count = sarif_report["runs"][0]["results"].as_array().unwrap().len() as u64;

    assert_eq!(json_count, sarif_count);

    let text_str = String::from_utf8_lossy(&text_out.stdout);
    assert!(text_str.contains(&format!("{json_count} finding(s)")));

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn audit_formats_handle_clean_crate_consistently() {
    let root = std::env::temp_dir().join(format!("stk-audit-clean-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src/clean.rs"),
        "// clean code with no findings\n",
    )
    .unwrap();

    let text_out = run(&["audit", root.to_str().unwrap(), "--format", "text"]);
    let json_out = run(&["audit", root.to_str().unwrap(), "--format", "json"]);
    let sarif_out = run(&["audit", root.to_str().unwrap(), "--format", "sarif"]);

    assert!(text_out.status.success());
    assert!(json_out.status.success());
    assert!(sarif_out.status.success());

    let text_str = String::from_utf8_lossy(&text_out.stdout);
    assert!(text_str.contains("audit: no findings"));

    let json_report: serde_json::Value = serde_json::from_slice(&json_out.stdout).unwrap();
    assert_eq!(json_report["summary"]["finding_count"], 0);

    let sarif_report: serde_json::Value = serde_json::from_slice(&sarif_out.stdout).unwrap();
    assert_eq!(
        sarif_report["runs"][0]["results"].as_array().unwrap().len(),
        0
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn audit_reports_macro_generated_source_caveat_in_all_formats() {
    let source = br#"
        macro_rules! generated_vault {
            () => {
                pub fn withdraw(from: Address) { debit(from); }
            };
        }
        generated_vault!();
    "#;
    let text = run_with_stdin(&["audit", "-", "--format", "text"], source);
    assert!(text.status.success());
    let report = String::from_utf8_lossy(&text.stdout);
    assert!(report.contains("audit: no findings"), "{report}");
    assert!(report.contains("macro_rules!"), "{report}");
    assert!(report.contains("not expanded"), "{report}");

    let json = run_with_stdin(&["audit", "-", "--format", "json"], source);
    assert!(json.status.success());
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 0);
    assert!(report["summary"]["limitations"][0]
        .as_str()
        .unwrap()
        .contains("not expanded"));

    let sarif = run_with_stdin(&["audit", "-", "--format", "sarif"], source);
    assert!(sarif.status.success());
    let report: serde_json::Value = serde_json::from_slice(&sarif.stdout).unwrap();
    assert_eq!(report["runs"][0]["results"].as_array().unwrap().len(), 0);
    assert!(report["runs"][0]["properties"]["limitations"][0]
        .as_str()
        .unwrap()
        .contains("generated entry points"));
}

#[test]
fn audit_reports_written_contractimpl_functions_but_not_generated_bodies() {
    let text = run_with_stdin(
        &["audit", "-", "--format", "text"],
        UNAUTHORIZED_ENTRY_POINT.as_bytes(),
    );
    assert!(text.status.success());
    let report = String::from_utf8_lossy(&text.stdout);
    assert!(report.contains("missing-require-auth"), "{report}");
    assert!(report.contains("source-only scan"), "{report}");
}

#[test]
fn audit_help_explains_macro_expansion_boundary() {
    let output = run(&["audit", "--help"]);
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("macro_rules!"), "{help}");
    assert!(help.contains("generated code"), "{help}");
}

#[test]
fn audit_json_round_trips_control_characters_in_findings() {
    let fixture = AuditFixture::new("json-controls");
    // Windows forbids these characters in file names. All finding fields,
    // including the complete control range, are also covered by a unit test.
    #[cfg(unix)]
    let name = "crates/vault/src/quote\"-slash\\-tab\t-newline\n-return\r-escape\u{1b}-雪.rs";
    #[cfg(not(unix))]
    let name = "crates/vault/src/unicode-雪.rs";
    fixture.write(name, UNAUTHORIZED_ENTRY_POINT);
    fixture.write(
        ".soroban-testkit.toml",
        "[rules.missing-require-auth]\nseverity = 'error'\n",
    );
    let output = fixture.scan(&["--strict"]);
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["findings"][0]["file"], name);
    assert_eq!(report["findings"][0]["severity"], "error");
    // The snippet quoted from the file body carries no control sequences of
    // its own, so it round-trips verbatim even though the file path does not.
    assert_eq!(
        report["findings"][0]["source_snippet"],
        "    pub fn withdraw(env: Env, from: Address) {"
    );
    assert_eq!(report["summary"]["finding_count"], 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("1 audit finding(s)"));
}

#[test]
fn audit_continues_after_read_and_parse_errors_in_every_format() {
    let fixture = AuditFixture::new("incomplete");
    fixture.write("a-unreadable.rs", [0xff, 0xfe]);
    fixture.write("b-invalid.rs", "fn broken( {\n");
    fixture.write("z-valid.rs", UNAUTHORIZED_ENTRY_POINT);
    for format in ["text", "json", "sarif"] {
        let output = fixture.scan(&["--format", format]);
        assert!(!output.status.success());
        let errors = String::from_utf8_lossy(&output.stderr);
        assert!(errors.contains("failed to read Rust source"), "{errors}");
        assert!(errors.contains("a-unreadable.rs"), "{errors}");
        assert!(errors.contains("failed to parse Rust source"), "{errors}");
        assert!(errors.contains("b-invalid.rs:1:"), "{errors}");
        assert!(
            errors.contains("audit incomplete: 2 parse warning(s)"),
            "{errors}"
        );
        assert!(errors.contains("audit: warning:"), "{errors}");
        let findings = String::from_utf8_lossy(&output.stdout);
        assert!(findings.contains("z-valid.rs"), "{findings}");
        assert!(findings.contains("missing-require-auth"), "{findings}");
        if format != "text" {
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap();
        }
    }
}

#[test]
fn audit_reports_parse_errors_for_single_files_and_stdin() {
    let fixture = AuditFixture::new("parse-errors");
    let path = fixture.write("invalid.rs", "fn broken() {\n    let = ;\n}\n");
    for output in [
        run(&["audit", path.to_str().unwrap()]),
        run_with_stdin(&["audit", "-"], b"fn broken() {\n    let = ;\n}\n"),
    ] {
        assert!(!output.status.success());
        let errors = String::from_utf8_lossy(&output.stderr);
        assert!(errors.contains("failed to parse Rust source"), "{errors}");
        assert!(errors.contains(":2:9:"), "{errors}");
        assert!(!errors.contains("failed to read"), "{errors}");
    }
}

#[cfg(unix)]
#[test]
fn audit_continues_past_permission_denied_files_and_directories() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = AuditFixture::new("permissions");
    let file = fixture.write("a-denied.rs", UNAUTHORIZED_ENTRY_POINT);
    let dir = fixture.0.join("b-denied");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("hidden.rs"), UNAUTHORIZED_ENTRY_POINT).unwrap();
    fixture.write("z-readable.rs", UNAUTHORIZED_ENTRY_POINT);
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o0)).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o0)).unwrap();
    let access_denied = std::fs::File::open(&file).is_err();
    let output = fixture.scan(&[]);
    // Restore access before any assertions so a failure still cleans up.
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    // A root test runner can read mode-000 files; exercise actual EACCES
    // when the process lacks that privilege.
    if access_denied {
        assert!(!output.status.success());
        let errors = String::from_utf8_lossy(&output.stderr);
        assert!(errors.contains("failed to read Rust source"), "{errors}");
        assert!(errors.contains("a-denied.rs"), "{errors}");
        assert!(errors.contains("failed to scan directory"), "{errors}");
        assert!(errors.contains("b-denied"), "{errors}");
        assert!(errors.contains("2 parse warning(s)"), "{errors}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["findings"][0]["file"], "z-readable.rs");
        assert_eq!(report["summary"]["finding_count"], 1);
    }
}

#[test]
fn audit_config_errors_distinguish_io_from_toml_syntax() {
    let fixture = AuditFixture::new("config-errors");
    fixture.write("valid.rs", UNAUTHORIZED_ENTRY_POINT);
    for (content, kind) in [
        (b"[rules".as_slice(), "parse"),
        (b"\xff".as_slice(), "read"),
    ] {
        let path = fixture.write(".soroban-testkit.toml", content);
        let output = fixture.scan(&[]);
        assert!(!output.status.success());
        let errors = String::from_utf8_lossy(&output.stderr);
        assert!(
            errors.contains(&format!("failed to {kind} audit config")),
            "{errors}"
        );
        assert!(errors.contains(path.to_str().unwrap()), "{errors}");
    }
}

#[test]
fn audit_baseline_errors_include_the_path_and_error_kind() {
    let fixture = AuditFixture::new("baseline-errors");
    for (content, kind) in [
        (Some(b"[invalid".as_slice()), "parse baseline JSON"),
        (Some(b"\xff".as_slice()), "read baseline file"),
        (None, "read baseline file"),
    ] {
        let path = fixture.0.join("baseline.json");
        if let Some(content) = content {
            std::fs::write(&path, content).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
        }
        let output = fixture.scan(&["--baseline", "baseline.json"]);
        assert!(!output.status.success());
        let errors = String::from_utf8_lossy(&output.stderr);
        assert!(errors.contains(&format!("failed to {kind}")), "{errors}");
        assert!(errors.contains("baseline.json"), "{errors}");
    }
}

#[test]
fn audit_workspace_paths_and_config_are_independent_of_cwd_and_scan_root() {
    let fixture = AuditFixture::new("workspace-paths");
    let file = fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write(
        "crates/vault/Cargo.toml",
        "[package]\nname = 'vault'\nversion = '0.1.0'\n",
    );
    fixture.write(
        "soroban-testkit.toml",
        "[rules.missing-require-auth]\nseverity = 'error'\n",
    );
    let expected = fixture.scan(&["--strict"]);
    assert!(!expected.status.success());
    let expected: serde_json::Value = serde_json::from_slice(&expected.stdout).unwrap();
    assert_eq!(expected["findings"][0]["file"], "crates/vault/src/lib.rs");
    assert_eq!(expected["findings"][0]["severity"], "error");

    for (dir, target) in [
        (fixture.0.clone(), "./crates/vault/src/../src"),
        (fixture.0.join("crates/vault"), "src/lib.rs"),
        (fixture.0.join("crates/vault/src"), "."),
        (std::env::temp_dir(), file.to_str().unwrap()),
    ] {
        let output = run_from(&dir, &["audit", target, "--format", "json", "--strict"]);
        assert!(!output.status.success());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            expected
        );
    }

    // A baseline generated at the workspace root works from a member crate,
    // with both workspace-relative and absolute paths inside the baseline.
    for baseline_file in ["./crates/vault/src/../src/lib.rs", file.to_str().unwrap()] {
        fixture.write(
            "baseline.json",
            serde_json::to_vec(&serde_json::json!([{
                "file": baseline_file,
                "line": expected["findings"][0]["line"],
                "rule": "missing-require-auth"
            }]))
            .unwrap(),
        );
        let output = run_from(
            &fixture.0.join("crates/vault"),
            &[
                "audit",
                "src/lib.rs",
                "--format",
                "json",
                "--strict",
                "--baseline",
                "../../baseline.json",
            ],
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["summary"]["finding_count"], 0);
    }
}

#[test]
fn audit_nearest_config_wins_without_leaking_across_project_boundaries() {
    let fixture = AuditFixture::new("config-boundaries");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write(
        ".soroban-testkit.toml",
        "[rules.missing-require-auth]\nenabled = false\n",
    );
    fixture.write("soroban-testkit.toml", "invalid TOML");
    let output = fixture.scan(&["--strict"]);
    assert!(output.status.success());
    // The nearest config overrides the workspace config, and the dotted
    // config wins over the non-dotted config within one directory.
    fixture.write(
        "crates/vault/soroban-testkit.toml",
        "[rules.missing-require-auth]\nseverity = 'error'\n",
    );
    let output = run_from(
        &fixture.0,
        &["audit", "crates/vault/src", "--format", "json"],
    );
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["findings"][0]["severity"], "error");

    // An independent nested workspace must not inherit the outer config.
    fixture.write("crates/vault/Cargo.toml", "[workspace]\nmembers = []\n");
    std::fs::remove_file(fixture.0.join("crates/vault/soroban-testkit.toml")).unwrap();
    let output = run_from(
        &fixture.0,
        &["audit", "crates/vault/src", "--format", "json"],
    );
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["findings"][0]["severity"], "warning");
    assert_eq!(report["findings"][0]["file"], "src/lib.rs");
}

#[test]
fn audit_stdin_discovers_config_from_the_current_workspace() {
    let fixture = AuditFixture::new("stdin-config");
    fixture.write(
        ".soroban-testkit.toml",
        "[rules.missing-require-auth]\nenabled = false\n",
    );
    let path = fixture.write("source.txt", UNAUTHORIZED_ENTRY_POINT);
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-testkit"))
        .args(["audit", "-", "--strict", "--format", "json"])
        .current_dir(fixture.0.join("crates/vault/src"))
        .stdin(std::fs::File::open(path).unwrap())
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 0);
}

#[test]
fn audit_strict_mode_exits_zero_when_findings_are_suppressed() {
    let root = std::env::temp_dir().join(format!(
        "stk-audit-strict-suppressed-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src/lib.rs"),
        r#"
        #[contractimpl]
        impl Contract {
            // soroban_testkit::audit(skip, rule = "missing-require-auth")
            pub fn withdraw(env: Env, from: Address) {
                env.storage().instance().set(&from, &1i128);
            }
        }
        "#,
    )
    .unwrap();

    let output = run(&["audit", root.to_str().unwrap(), "--strict"]);
    assert!(
        output.status.success(),
        "strict exit status should be 0 when findings are suppressed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("audit: no findings"), "{stdout}");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn audit_recognizes_qualified_require_auth_calls() {
    let root = std::env::temp_dir().join(format!("stk-audit-qual-auth-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src/lib.rs"),
        r#"
        #[contractimpl]
        impl Contract {
            pub fn withdraw(env: Env, from: Address) {
                Address::require_auth(&from);
            }
        }
        "#,
    )
    .unwrap();

    let output = run(&["audit", root.to_str().unwrap()]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("missing-require-auth"), "{stdout}");
    assert!(stdout.contains("audit: no findings"), "{stdout}");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn audit_negated_auth_branch_is_not_treated_as_enforced_in_cli() {
    let root = std::env::temp_dir().join(format!("stk-audit-negated-auth-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src/lib.rs"),
        r#"
        #[contractimpl]
        impl Contract {
            pub fn withdraw(env: Env, from: Address) {
                if !is_admin {
                    from.require_auth();
                }
            }
        }
        "#,
    )
    .unwrap();

    let output = run(&["audit", root.to_str().unwrap(), "--strict"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("audit finding(s)"), "{stderr}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("missing-require-auth"), "{stdout}");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn audit_runs_are_byte_for_byte_deterministic_across_repeated_invocations() {
    let root = std::env::temp_dir().join(format!("stk-audit-deterministic-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src/z_file.rs"),
        r#"
        #[contractimpl]
        impl ContractZ {
            pub fn withdraw(env: Env, from: Address) {}
        }
        "#,
    )
    .unwrap();
    std::fs::write(
        root.join("src/a_file.rs"),
        r#"
        #[contractimpl]
        impl ContractA {
            pub fn deposit(amount: i128) -> i128 {
                amount + 10
            }
        }
        "#,
    )
    .unwrap();

    for format in ["text", "json", "sarif"] {
        let run1 = run(&["audit", root.to_str().unwrap(), "--format", format]);
        let run2 = run(&["audit", root.to_str().unwrap(), "--format", format]);
        assert!(run1.status.success());
        assert!(run2.status.success());
        assert_eq!(
            run1.stdout, run2.stdout,
            "repeated audit run with format '{format}' must be byte-for-byte identical"
        );
    }

    let _ = std::fs::remove_dir_all(&root);
}

// ---- #481: focused fixtures, one per supported Rust syntax form ----

/// Every syntactic shape the audit visitor supports, in its own file so a
/// per-file assertion points at the exact form. Except for the test fixture,
/// every function takes an Address parameter and never calls require_auth,
/// so each trips `missing-require-auth` and only that rule.
const SYNTAX_FORM_FIXTURES: &[(&str, &str)] = &[
    (
        "form_free_item_fn.rs",
        "pub fn withdraw(env: Env, from: Address) { let _ = &from; }",
    ),
    (
        "form_const_item_fn.rs",
        "pub const fn withdraw(env: Env, from: Address) { let _ = &from; }",
    ),
    (
        "form_impl_method.rs",
        "impl Vault { pub fn withdraw(env: Env, from: Address) { let _ = &from; } }",
    ),
    (
        "form_contractimpl_method.rs",
        "#[contractimpl] impl Vault { pub fn withdraw(env: Env, from: Address) { let _ = &from; } }",
    ),
    (
        "form_trait_impl_method.rs",
        "trait Vault { fn withdraw(env: Env, from: Address); } impl Vault for Vault2 { pub fn withdraw(env: Env, from: Address) { let _ = &from; } }",
    ),
    (
        "form_nested_module_fn.rs",
        "mod treasury { pub fn withdraw(env: Env, from: Address) { let _ = &from; } }",
    ),
    (
        "form_test_item_fn.rs",
        "#[test] fn test_reset_all_auths(env: Env) { env.mock_all_auths(); }",
    ),
];

#[test]
fn audit_reports_a_finding_for_each_supported_syntax_form() {
    let fixture = AuditFixture::new("syntax-forms");
    for (name, source) in SYNTAX_FORM_FIXTURES {
        fixture.write(name, source);
    }

    let output = fixture.scan(&["--strict"]);
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(
        report["summary"]["finding_count"],
        SYNTAX_FORM_FIXTURES.len(),
        "{findings:?}"
    );

    for (name, source) in SYNTAX_FORM_FIXTURES {
        let expected_rule = if name.contains("test") {
            "broad-mock-all-auths"
        } else {
            "missing-require-auth"
        };
        let matching: Vec<_> = findings
            .iter()
            .filter(|finding| {
                finding["file"]
                    .as_str()
                    .is_some_and(|file| file.ends_with(name))
            })
            .collect();
        assert_eq!(matching.len(), 1, "fixture {name}: {findings:?}");
        let finding = matching[0];
        assert_eq!(finding["rule"], expected_rule, "fixture {name}");
        assert_eq!(finding["severity"], "warning", "fixture {name}");
        assert_eq!(finding["line"], 1, "fixture {name}");
        // Every fixture is a single physical line, so the reported snippet is
        // the fixture text itself.
        assert_eq!(finding["source_snippet"], *source, "fixture {name}");
    }
}

// ---- #482: findings disclose that they are heuristic, not definitive ----

#[test]
fn audit_explain_rules_document_the_heuristic_nature_of_findings() {
    for rule in [
        "missing-require-auth",
        "unchecked-i128-arithmetic",
        "missing-ttl-bump",
        "broad-mock-all-auths",
        "ignored-token-transfer-result",
        "missing-positive-amount-validation",
        "unchecked-timestamp-arithmetic",
    ] {
        let output = run(&["audit", "explain", rule]);
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(rule), "{stdout}");
        assert!(stdout.contains("heuristic"), "{stdout}");
        assert!(
            stdout.contains("not a definitive defect report"),
            "{stdout}"
        );
    }
}

#[test]
fn audit_rules_listing_documents_the_heuristic_nature_of_findings() {
    let text = run(&["audit", "rules", "--format", "text"]);
    assert!(text.status.success());
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(stdout.contains("missing-require-auth"), "{stdout}");
    assert!(stdout.contains("note: heuristic"), "{stdout}");

    let json = run(&["audit", "rules", "--format", "json"]);
    assert!(json.status.success());
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let limitations = report["summary"]["limitations"].as_array().unwrap();
    assert!(
        limitations
            .iter()
            .any(|l| l.as_str().unwrap().contains("heuristic")),
        "{limitations:?}"
    );
}

// ---- #483: rule severity mapping is consistent across output formats ----

#[test]
fn audit_sarif_levels_match_the_severity_shown_in_text_and_json() {
    let fixture = AuditFixture::new("severity-consistency");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    for (configured, sarif_level) in [("warning", "warning"), ("error", "error"), ("note", "note")]
    {
        fixture.write(
            ".soroban-testkit.toml",
            format!("[rules.missing-require-auth]\nseverity = '{configured}'\n"),
        );
        let text = fixture.scan(&["--format", "text"]);
        assert!(text.status.success());
        let stdout = String::from_utf8_lossy(&text.stdout);
        assert!(stdout.contains(&format!("[{configured}]")), "{stdout}");

        let json = fixture.scan(&["--format", "json"]);
        assert!(json.status.success());
        let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        assert_eq!(report["findings"][0]["severity"], configured, "{report}");

        let sarif = fixture.scan(&["--format", "sarif"]);
        assert!(sarif.status.success());
        let report: serde_json::Value = serde_json::from_slice(&sarif.stdout).unwrap();
        assert_eq!(
            report["runs"][0]["results"][0]["level"], sarif_level,
            "{report}"
        );
        assert_eq!(
            report["runs"][0]["tool"]["driver"]["rules"][0]["defaultConfiguration"]["level"],
            sarif_level,
            "{report}"
        );
    }
}

// ---- #484: source snippets without terminal control sequences ----

#[test]
fn audit_reports_source_snippets_without_leaking_terminal_control_sequences() {
    let fixture = AuditFixture::new("snippet-controls");
    fixture.write(
        "crates/vault/src/lib.rs",
        "pub fn withdraw(env: Env, from: Address) { let _ = &from; } // \u{1b}[31mred\u{1b}[0m",
    );

    let text = fixture.scan(&["--format", "text"]);
    assert!(text.status.success());
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(
        stdout
            .contains("    --> pub fn withdraw(env: Env, from: Address) { let _ = &from; } // red"),
        "{stdout}"
    );
    assert!(!stdout.contains('\u{1b}'), "{stdout}");

    let json = fixture.scan(&["--format", "json"]);
    assert!(json.status.success());
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        report["findings"][0]["source_snippet"],
        "pub fn withdraw(env: Env, from: Address) { let _ = &from; } // red"
    );

    let sarif = fixture.scan(&["--format", "sarif"]);
    assert!(sarif.status.success());
    let report: serde_json::Value = serde_json::from_slice(&sarif.stdout).unwrap();
    assert_eq!(
        report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["snippet"]
            ["text"],
        "pub fn withdraw(env: Env, from: Address) { let _ = &from; } // red"
    );
}

// ---- #485: findings sort by file, line, rule, and message ----

#[test]
fn audit_orders_findings_by_rule_rather_than_scan_order_or_column() {
    let fixture = AuditFixture::new("finding-order");
    // Both functions sit on one physical line: `alpha` starts at column 1
    // and is visited first, but `missing-positive-amount-validation` sorts
    // before `missing-require-auth`, so the report follows the rule — not
    // the scan order or the column.
    fixture.write(
        "crates/vault/src/lib.rs",
        "pub fn alpha(env: Env, from: Address) { let _ = &from; } \
         pub fn beta(amount: i128) { save(amount); }\n",
    );

    let first = fixture.scan(&["--strict"]);
    assert!(!first.status.success(), "{first:?}");
    let report: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 2, "{report}");
    let rules: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["rule"].as_str().unwrap())
        .collect();
    assert_eq!(
        rules,
        vec!["missing-positive-amount-validation", "missing-require-auth"],
        "{report}"
    );

    // The order is deterministic across runs.
    let second = fixture.scan(&["--strict"]);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&second.stdout).unwrap(),
        report
    );
}

// ---- #488: one canonical path normalization routine ----

#[test]
fn audit_normalizes_equivalent_spellings_of_one_scan_root() {
    let fixture = AuditFixture::new("canonical-roots");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);

    let mut reports = Vec::new();
    for root in [
        "crates/vault/src/lib.rs",
        "./crates/vault/./src/../src/lib.rs",
        "crates/vault/src/../../vault/src/lib.rs",
    ] {
        let output = run_from(&fixture.0, &["audit", root, "--format", "json"]);
        assert!(output.status.success(), "root {root}: {output:?}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            report["findings"][0]["file"], "crates/vault/src/lib.rs",
            "root {root}: {report}"
        );
        reports.push(report);
    }
    assert_eq!(reports[0], reports[1]);
    assert_eq!(reports[1], reports[2]);
}

// ---- #487: a parse warning is not a finding ----

#[test]
fn audit_reports_parse_warnings_on_stderr_and_findings_in_the_report() {
    let fixture = AuditFixture::new("finding-vs-warning");
    fixture.write("broken.rs", "fn broken( {\n");
    fixture.write("good.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--format", "json", "--strict"]);
    assert!(!output.status.success(), "{output:?}");

    // The report counts only parsed source; the skipped file never becomes
    // a finding.
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 1, "{report}");
    let files: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["file"].as_str().unwrap())
        .collect();
    assert_eq!(files, vec!["good.rs"], "{report}");

    // The warning lives only on stderr, labelled as a warning, with the
    // finding/warning distinction stated alongside it.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("audit: warning: failed to parse Rust source"),
        "{stderr}"
    );
    assert!(
        stderr.contains("parse warnings are not findings"),
        "{stderr}"
    );
    assert!(
        stderr.contains("audit incomplete: 1 parse warning(s)"),
        "{stderr}"
    );
    // The incomplete audit — not --strict — is what failed this run.
    assert!(!stderr.contains("(--strict)"), "{stderr}");
}

#[test]
fn audit_parse_warnings_fail_the_run_without_acting_like_strict_findings() {
    let fixture = AuditFixture::new("warnings-not-findings");
    fixture.write("clean.rs", "// nothing to scan\n");
    fixture.write("broken.rs", "fn broken( {\n");

    let output = fixture.scan(&["--format", "json", "--strict"]);
    assert!(!output.status.success(), "{output:?}");

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 0, "{report}");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("audit incomplete: 1 parse warning(s)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("parse warnings are not findings"),
        "{stderr}"
    );
    // No heuristic finding existed, so the strict-failure wording must not
    // appear: parse warnings never reach --strict.
    assert!(!stderr.contains("audit finding(s)"), "{stderr}");
}

#[test]
fn audit_strict_failure_reports_findings_and_no_parse_warnings() {
    let fixture = AuditFixture::new("strict-findings-only");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--format", "json", "--strict"]);
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("1 audit finding(s) (--strict)"), "{stderr}");
    assert!(!stderr.contains("parse warning"), "{stderr}");
    assert!(!stderr.contains("audit: warning:"), "{stderr}");
}

// ---- #354: parser limitations are a separate list in JSON reports ----

#[test]
fn audit_json_lists_parser_limitations_separately_from_findings() {
    let fixture = AuditFixture::new("parser-limitations");
    fixture.write("broken.rs", "fn broken( {\n");
    fixture.write("good.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--format", "json"]);
    assert!(!output.status.success(), "{output:?}");

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 1, "{report}");
    assert_eq!(report["findings"].as_array().unwrap().len(), 1, "{report}");
    let limitations = report["summary"]["parser_limitations"].as_array().unwrap();
    assert_eq!(limitations.len(), 1, "{report}");
    assert!(
        limitations[0].as_str().unwrap().contains("broken.rs"),
        "{report}"
    );
}

#[test]
fn audit_clean_json_report_has_no_parser_limitations() {
    let fixture = AuditFixture::new("no-parser-limitations");
    fixture.write("good.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--format", "json"]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["summary"]["parser_limitations"],
        serde_json::json!([]),
        "{report}"
    );
}

// ---- #353: summary count of skipped files ----

#[test]
fn audit_summary_counts_skipped_files_in_json_and_stderr() {
    let fixture = AuditFixture::new("skipped-count");
    fixture.write("a-unreadable.rs", [0xff, 0xfe]);
    fixture.write("b-invalid.rs", "fn broken( {\n");
    fixture.write("z-valid.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--format", "json"]);
    assert!(!output.status.success(), "{output:?}");

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["skipped_file_count"], 2, "{report}");
    assert_eq!(report["summary"]["finding_count"], 1, "{report}");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("audit: summary: 1 input(s) scanned, 2 skipped"),
        "{stderr}"
    );
}

// ---- #352: parse errors fail the run, with and without --strict ----

#[test]
fn audit_parse_errors_fail_the_run_without_strict() {
    let fixture = AuditFixture::new("parse-error-default");
    fixture.write("broken.rs", "fn broken( {\n");

    let output = fixture.scan(&["--format", "json"]);
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("audit incomplete: 1 parse warning(s)"),
        "{stderr}"
    );
}

#[test]
fn audit_strict_mode_fails_on_parse_errors_with_clean_findings() {
    let fixture = AuditFixture::new("parse-error-strict");
    fixture.write("broken.rs", "fn broken( {\n");

    let output = fixture.scan(&["--format", "json", "--strict"]);
    assert!(!output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 0, "{report}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("audit incomplete: 1 parse warning(s)"),
        "{stderr}"
    );
}

// ---- #355: a workspace-root scan covers every member crate ----

#[test]
fn audit_workspace_root_scan_covers_every_member_crate() {
    let fixture = AuditFixture::new("workspace-members");
    fixture.write(
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/vault\", \"crates/token\"]\n",
    );
    fixture.write("crates/token/Cargo.toml", "[package]\nname = \"token\"\n");
    std::fs::create_dir_all(fixture.0.join("crates/token/src")).unwrap();
    fixture.write("crates/token/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--format", "json"]);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let files: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["file"].as_str().unwrap())
        .collect();
    assert_eq!(files, vec!["crates/token/src/lib.rs"], "{report}");

    // Starting from a member crate resolves the same workspace root, so the
    // finding keeps its workspace-relative spelling.
    let member = fixture.0.join("crates/token");
    let from_member = run_from(&member, &["audit", ".", "--format", "json"]);
    let member_report: serde_json::Value = serde_json::from_slice(&from_member.stdout).unwrap();
    assert_eq!(
        member_report["findings"][0]["file"], "crates/token/src/lib.rs",
        "{member_report}"
    );
}

// ---- #486: regression snapshots for strict and report-only modes ----

/// The exact report both modes must print. `--strict` changes only the exit
/// status and the error on stderr — never a byte of the report itself.
const FINDINGS_REPORT_SNAPSHOT: &str = include_str!("snapshots/audit_findings_report.txt");
const CLEAN_REPORT_SNAPSHOT: &str = include_str!("snapshots/audit_clean_report.txt");
const STRICT_ERROR_SNAPSHOT: &str = include_str!("snapshots/audit_strict_error.txt");

/// One physical line, exactly one finding: the source both mode snapshots
/// scan, so the snapshot pins report shape rather than scan ordering.
const SNAPSHOT_ENTRY_POINT: &str = "pub fn withdraw(env: Env, from: Address) { let _ = &from; }\n";

#[test]
fn audit_report_only_mode_matches_its_regression_snapshot() {
    let fixture = AuditFixture::new("snapshot-report-only");
    fixture.write("crates/vault/src/lib.rs", SNAPSHOT_ENTRY_POINT);

    let output = fixture.scan(&["--format", "text"]);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        FINDINGS_REPORT_SNAPSHOT,
        "report-only snapshot changed"
    );
}

#[test]
fn audit_strict_mode_matches_its_regression_snapshot() {
    let fixture = AuditFixture::new("snapshot-strict");
    fixture.write("crates/vault/src/lib.rs", SNAPSHOT_ENTRY_POINT);

    let output = fixture.scan(&["--format", "text", "--strict"]);
    assert!(!output.status.success(), "{output:?}");
    // Strict fails the run without changing a single byte of the report.
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        FINDINGS_REPORT_SNAPSHOT,
        "strict-mode report snapshot changed"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        STRICT_ERROR_SNAPSHOT,
        "strict-mode error snapshot changed"
    );
}

#[test]
fn audit_clean_report_is_snapshotted_in_both_modes() {
    let fixture = AuditFixture::new("snapshot-clean");
    fixture.write("crates/vault/src/lib.rs", "// nothing to flag\n");
    let modes: &[&[&str]] = &[&["--format", "text"], &["--format", "text", "--strict"]];
    for args in modes {
        let output = fixture.scan(args);
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            CLEAN_REPORT_SNAPSHOT,
            "clean-report snapshot changed for {args:?}"
        );
    }
}

// #436: Unix paths may contain non-UTF-8 bytes; text output must be legible.
#[cfg(unix)]
#[test]
fn audit_text_escapes_invalid_utf8_path_without_loss() {
    use std::os::unix::ffi::OsStringExt;
    let root = std::env::temp_dir().join(format!("stk-audit-invalid-path-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let filename = std::ffi::OsString::from_vec(b"invalid-\xff.rs".to_vec());
    let path = root.join(filename);
    std::fs::write(&path, UNAUTHORIZED_ENTRY_POINT).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_soroban-testkit"))
        .arg("audit")
        .arg(&path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success(), "{stdout}");
    assert!(
        stdout.to_ascii_lowercase().contains(r"\xff"),
        "expected escaped original byte: {stdout}"
    );
    assert!(!stdout.contains('\u{fffd}'), "path was lossy: {stdout}");
    assert!(stdout.contains("missing-require-auth"), "{stdout}");
    let _ = std::fs::remove_dir_all(&root);
}

// #438: show file, table/key and line for a wrongly-typed rule option.
#[test]
fn audit_config_error_names_path_and_setting() {
    let root = std::env::temp_dir().join(format!("stk-audit-bad-config-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("src.rs"), UNAUTHORIZED_ENTRY_POINT).unwrap();
    std::fs::write(
        root.join(".soroban-testkit.toml"),
        "[rules.missing-require-auth]\nenabled = 'definitely'\n",
    )
    .unwrap();
    let output = run(&["audit", root.to_str().unwrap()]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(".soroban-testkit.toml"), "{stderr}");
    assert!(stderr.contains("enabled"), "{stderr}");
    assert!(stderr.contains("line 2"), "{stderr}");
    let _ = std::fs::remove_dir_all(&root);
}

// #432: helper methods compiled only in tests must not raise production warnings.
#[test]
fn audit_skips_test_only_helpers_but_checks_production_methods() {
    let source = r#"
struct Vault;
impl Vault {
    pub fn live(&self, from: Address) { let _ = from; }
}
#[cfg(test)]
mod tests {
    pub fn helper(from: Address) { let _ = from; }
    struct Helpers;
    impl Helpers { pub fn internal(&self, from: Address) { let _ = from; } }
}
#[cfg(test)]
pub fn another_helper(from: Address) { let _ = from; }
#[cfg(not(test))]
pub fn production_only(from: Address) { let _ = from; }
#[cfg(any(test, feature = "logging"))]
pub fn also_production(from: Address) { let _ = from; }
#[cfg(all(test, feature = "logging"))]
pub fn helper_with_feature(from: Address) { let _ = from; }
"#;
    let output = run_with_stdin(&["audit", "-", "--format", "json"], source.as_bytes());
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert!(findings
        .iter()
        .any(|finding| finding["message"].as_str().unwrap().contains("live")));
    assert!(findings.iter().any(|finding| finding["message"]
        .as_str()
        .unwrap()
        .contains("production_only")));
    assert!(findings.iter().any(|finding| finding["message"]
        .as_str()
        .unwrap()
        .contains("also_production")));
    assert!(!findings.iter().any(|finding| {
        let msg = finding["message"].as_str().unwrap();
        msg.contains("helper") || msg.contains("internal")
    }));
}

#[test]
fn audit_does_not_treat_integration_test_files_as_production() {
    let root = std::env::temp_dir().join(format!("stk-audit-test-tree-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("tests/helpers.rs"),
        "fn helper(from: Address) { let _ = from; }",
    )
    .unwrap();
    std::fs::write(
        root.join("src/lib.rs"),
        "fn live(from: Address) { let _ = from; }",
    )
    .unwrap();
    let output = run(&["audit", root.to_str().unwrap(), "--format", "json"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert!(findings
        .iter()
        .any(|finding| finding["file"].as_str().unwrap().ends_with("src/lib.rs")));
    assert!(!findings.iter().any(|finding| finding["file"]
        .as_str()
        .unwrap()
        .ends_with("tests/helpers.rs")));
    let _ = std::fs::remove_dir_all(&root);
}

// ---- #419: no false positives for auth checks delegated to helper functions ----

/// An entry point that delegates `require_auth` to a private helper must not
/// be flagged as missing auth.  This is the most common pattern for sharing
/// auth logic across multiple entry points in a contract.
#[test]
fn audit_does_not_flag_entry_points_that_delegate_auth_to_a_helper() {
    let source = br#"
fn check_auth(caller: &Address) {
    caller.require_auth();
}

#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, from: Address) {
        check_auth(&from);
        let balance: i128 = env.storage().instance().get(&"bal").unwrap_or(0);
        env.storage().instance().set(&"bal", &(balance - 1i128));
    }
}
"#;
    let output = run_with_stdin(&["audit", "-", "--format", "json", "--strict"], source);
    // strict must not fail — the entry point is auth-protected via helper
    assert!(
        output.status.success(),
        "false positive: delegated auth helper still triggered missing-require-auth; \
         stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let auth_findings: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule"] == "missing-require-auth")
        .collect();
    assert!(
        auth_findings.is_empty(),
        "unexpected missing-require-auth findings: {auth_findings:?}"
    );
}

/// Various naming conventions for auth helpers — all should suppress the finding.
#[test]
fn audit_recognises_multiple_auth_helper_naming_conventions() {
    for (helper_decl, helper_call) in &[
        (
            "fn verify_auth(a: &Address) { a.require_auth(); }",
            "verify_auth(&from);",
        ),
        (
            "fn assert_authorized(a: &Address) { a.require_auth(); }",
            "assert_authorized(&from);",
        ),
        (
            "fn require_caller(a: &Address) { a.require_auth(); }",
            "require_caller(&from);",
        ),
    ] {
        let source = format!(
            r#"
{helper_decl}
#[contractimpl]
impl Vault {{
    pub fn withdraw(env: Env, from: Address) {{
        {helper_call}
    }}
}}
"#
        );
        let output = run_with_stdin(
            &["audit", "-", "--format", "json", "--strict"],
            source.as_bytes(),
        );
        assert!(
            output.status.success(),
            "false positive for helper `{helper_call}`; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let auth_findings: Vec<_> = report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["rule"] == "missing-require-auth")
            .collect();
        assert!(
            auth_findings.is_empty(),
            "unexpected findings for helper `{helper_call}`: {auth_findings:?}"
        );
    }
}

/// An unrelated helper (not auth-semantics) must not suppress the finding.
#[test]
fn audit_still_flags_entry_points_when_only_unrelated_helpers_are_called() {
    let source = br#"
fn process_payment(from: &Address) { /* no auth */ }

#[contractimpl]
impl Vault {
    pub fn withdraw(env: Env, from: Address) {
        process_payment(&from);
    }
}
"#;
    let output = run_with_stdin(&["audit", "-", "--format", "json"], source);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let auth_findings: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule"] == "missing-require-auth")
        .collect();
    assert!(
        !auth_findings.is_empty(),
        "missing-require-auth should fire when only an unrelated helper is called"
    );
}

// ---- #336: summary-only output mode ----

#[test]
fn audit_summary_only_with_findings_prints_only_summary_and_preserves_exit_code() {
    let fixture = AuditFixture::new("summary-only-findings");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    // Findings present with --strict: exit code must fail.
    let output = run_from(&fixture.0, &["audit", ".", "--strict", "--summary-only"]);
    assert!(
        !output.status.success(),
        "exit code must indicate failure when findings exist under --strict"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("1 finding(s)"),
        "stdout must contain summary count: {stdout}"
    );
    assert!(
        stdout.contains("soroban-testkit audit is a linter"),
        "stdout must contain linter disclaimer: {stdout}"
    );
    assert!(
        stdout.contains("note:"),
        "stdout must contain notes: {stdout}"
    );

    // Assert individual finding text is absent:
    assert!(
        stdout.contains("missing-require-auth"),
        "stable rule ID must appear in summary-only: {stdout}"
    );
    assert!(
        !stdout.contains("fn withdraw"),
        "individual finding message must not appear in summary-only: {stdout}"
    );
    assert!(
        !stdout.contains("-->"),
        "source snippet pointer must not appear in summary-only: {stdout}"
    );
    assert!(
        !stdout.contains("crates/vault/src/lib.rs:"),
        "file location must not appear in summary-only: {stdout}"
    );
}

#[test]
fn audit_summary_only_zero_findings_prints_zero_summary_and_succeeds() {
    let fixture = AuditFixture::new("summary-only-zero");
    fixture.write("crates/vault/src/lib.rs", "// empty file\n");
    let output = run_from(&fixture.0, &["audit", ".", "--summary-only"]);
    assert!(output.status.success(), "clean run must succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("audit: no findings"),
        "zero findings must print zero summary: {stdout}"
    );
    assert!(
        stdout.contains("note:"),
        "must print note disclaimers: {stdout}"
    );
}

#[test]
fn audit_summary_only_matches_summary_section_of_full_output() {
    let fixture = AuditFixture::new("summary-only-matches");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);

    let full_output = run_from(&fixture.0, &["audit", "."]);
    let summary_output = run_from(&fixture.0, &["audit", ".", "--summary-only"]);

    let full_stdout = String::from_utf8_lossy(&full_output.stdout);
    let summary_stdout = String::from_utf8_lossy(&summary_output.stdout);

    // Summary lines in summary-only output must match the summary lines at the bottom of full output
    let full_summary_start = full_stdout
        .find("1 finding(s)")
        .expect("full output must contain summary");
    let full_summary = &full_stdout[full_summary_start..];

    // #319: summary-only additionally lists stable rule ids; strip that
    // additive block before comparing with the full report's summary section.
    let summary_without_ids = summary_stdout
        .split("Rules:\n")
        .next()
        .unwrap_or(&summary_stdout);
    assert_eq!(
        summary_without_ids.trim(),
        full_summary.trim(),
        "summary-only output must match full output's summary section"
    );
}

#[test]
fn audit_summary_only_rejected_with_structured_formats() {
    let fixture = AuditFixture::new("summary-only-formats");
    let json_output = run_from(
        &fixture.0,
        &["audit", ".", "--summary-only", "--format", "json"],
    );
    assert!(
        !json_output.status.success(),
        "--summary-only with --format json must fail"
    );
    let json_stderr = String::from_utf8_lossy(&json_output.stderr);
    assert!(
        json_stderr.contains("--summary-only is only supported for text output"),
        "stderr must contain actionable error: {json_stderr}"
    );

    let sarif_output = run_from(
        &fixture.0,
        &["audit", ".", "--summary-only", "--format", "sarif"],
    );
    assert!(
        !sarif_output.status.success(),
        "--summary-only with --format sarif must fail"
    );
    let sarif_stderr = String::from_utf8_lossy(&sarif_output.stderr);
    assert!(
        sarif_stderr.contains("--summary-only is only supported for text output"),
        "stderr must contain actionable error: {sarif_stderr}"
    );
}

#[test]
fn audit_summary_only_default_output_unchanged_regression() {
    let fixture = AuditFixture::new("summary-only-regression");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let default_output = run_from(&fixture.0, &["audit", "."]);
    let stdout = String::from_utf8_lossy(&default_output.stdout);
    assert!(
        stdout.contains("crates/vault/src/lib.rs:"),
        "default output must still include finding locations"
    );
    assert!(
        stdout.contains("missing-require-auth"),
        "default output must still include rule name"
    );
    assert!(
        stdout.contains("1 finding(s)"),
        "default output must still include summary count"
    );
}

// ---- #337: no-color option and NO_COLOR convention ----

#[test]
fn audit_color_positive_control_forced_color_produces_ansi_codes() {
    let fixture = AuditFixture::new("color-positive");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let output = run_from_with_env(
        &fixture.0,
        &["audit", "."],
        &[("CLICOLOR_FORCE", "1")],
        &["NO_COLOR"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\x1b["),
        "positive control: forced color with CLICOLOR_FORCE=1 must produce ANSI escape codes: {stdout}"
    );
}

#[test]
fn audit_color_no_color_flag_removes_ansi_codes() {
    let fixture = AuditFixture::new("color-flag-removes");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let output = run_from_with_env(
        &fixture.0,
        &["audit", ".", "--no-color"],
        &[("CLICOLOR_FORCE", "1")],
        &["NO_COLOR"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("\x1b["),
        "--no-color flag must eliminate all ANSI escape codes even when CLICOLOR_FORCE=1: {stdout}"
    );
}

// ---- #324: explicit rule listing command ----

#[test]
fn audit_list_rules_subcommand_and_flag_list_all_registered_rules() {
    let expected_rules = [
        "broad-mock-all-auths",
        "ignored-token-transfer-result",
        "missing-positive-amount-validation",
        "missing-require-auth",
        "missing-ttl-bump",
        "unchecked-i128-arithmetic",
        "unchecked-timestamp-arithmetic",
    ];
    // Exact count check to prevent silent rule additions/removals without test updates
    assert_eq!(expected_rules.len(), 7);

    for invocation in [&["audit", "list-rules"][..], &["audit", "--list-rules"][..]] {
        let output = run(invocation);
        assert!(
            output.status.success(),
            "invocation {:?} failed with {:?}",
            invocation,
            output
        );
        let stdout = String::from_utf8_lossy(&output.stdout);

        for rule in expected_rules {
            assert!(
                stdout.contains(rule),
                "listing missing expected rule '{rule}' in output: {stdout}"
            );
        }

        // Verify sorted ordering in table output
        let mut last_index = 0;
        for rule in expected_rules {
            let index = stdout.find(rule).expect("rule must be in output");
            assert!(
                index >= last_index,
                "rule '{rule}' out of sorted order in listing: {stdout}"
            );
            last_index = index;
        }

        assert!(stdout.contains("RULE"));
        assert!(stdout.contains("SEVERITY"));
        assert!(stdout.contains("DESCRIPTION"));
    }
}

#[test]
fn audit_list_rules_structured_formats() {
    let expected_rules = [
        "broad-mock-all-auths",
        "ignored-token-transfer-result",
        "missing-positive-amount-validation",
        "missing-require-auth",
        "missing-ttl-bump",
        "unchecked-i128-arithmetic",
        "unchecked-timestamp-arithmetic",
    ];

    // JSON format
    let json_output = run(&["audit", "list-rules", "--format", "json"]);
    assert!(json_output.status.success(), "{json_output:?}");
    let report: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(report["tool"], "soroban-testkit");
    assert_eq!(report["summary"]["rule_count"], 7);
    let rules = report["rules"].as_array().expect("rules array");
    assert_eq!(rules.len(), 7);
    for (i, expected_id) in expected_rules.iter().enumerate() {
        assert_eq!(rules[i]["id"], *expected_id);
        assert!(!rules[i]["description"].as_str().unwrap().is_empty());
        assert!(!rules[i]["severity"].as_str().unwrap().is_empty());
    }

    // SARIF format
    let sarif_output = run(&["audit", "list-rules", "--format", "sarif"]);
    assert!(sarif_output.status.success(), "{sarif_output:?}");
    let sarif: serde_json::Value = serde_json::from_slice(&sarif_output.stdout).unwrap();
    let sarif_rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("sarif rules array");
    assert_eq!(sarif_rules.len(), 7);
    for (i, expected_id) in expected_rules.iter().enumerate() {
        assert_eq!(sarif_rules[i]["id"], *expected_id);
    }
}

#[test]
fn audit_list_rules_does_not_require_path_or_filesystem() {
    let output = run(&["audit", "list-rules"]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
}

#[test]
fn audit_normal_scan_unaffected_by_list_rules_capability() {
    let fixture = AuditFixture::new("list-rules-unaffected");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let output = fixture.scan(&["--format", "json"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 1);
    assert_eq!(report["findings"][0]["rule"], "missing-require-auth");
}

// ---- #326: remediation guidance in findings ----

#[test]
fn audit_all_registered_rules_have_non_empty_remediation() {
    let json_output = run(&["audit", "list-rules", "--format", "json"]);
    assert!(json_output.status.success(), "{json_output:?}");
    let report: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    let rules = report["rules"].as_array().expect("rules array");
    assert_eq!(rules.len(), 7);
    for rule in rules {
        let id = rule["id"].as_str().unwrap();
        let remediation = rule["remediation"]
            .as_str()
            .unwrap_or_else(|| panic!("rule '{id}' missing remediation in JSON"));
        assert!(
            remediation.len() >= 20,
            "rule '{id}' has too short remediation: '{remediation}'"
        );
    }
}

#[test]
fn audit_finding_human_readable_prints_remediation_label_and_indentation() {
    let fixture = AuditFixture::new("remediation-human-readable");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let output = fixture.scan(&["--format", "text"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify finding header line is unchanged
    assert!(
        stdout.contains("crates/vault/src/lib.rs:1: [warning] missing-require-auth: fn withdraw takes Address parameter(s) [\"from\"] but never calls require_auth in its body"),
        "missing finding line in: {stdout}"
    );
    // Verify snippet line is unchanged
    assert!(
        stdout.contains("    --> pub fn withdraw(env: Env, from: Address) { let _ = &from; }"),
        "missing snippet line in: {stdout}"
    );
    // Verify remediation label and 4-space indentation
    assert!(
        stdout.contains("    remediation: Call address.require_auth() or address.require_auth_for_args(...) at the start of the function body to verify that the transaction signer authorized the operation."),
        "missing remediation line in: {stdout}"
    );
}

#[test]
fn audit_color_no_color_env_var_removes_ansi_codes() {
    let fixture = AuditFixture::new("color-env-removes");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let output = run_from_with_env(
        &fixture.0,
        &["audit", "."],
        &[("CLICOLOR_FORCE", "1"), ("NO_COLOR", "1")],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("\x1b["),
        "non-empty NO_COLOR must eliminate all ANSI escape codes: {stdout}"
    );
}

#[test]
fn audit_color_empty_no_color_does_not_disable_color() {
    let fixture = AuditFixture::new("color-empty-env");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let output = run_from_with_env(
        &fixture.0,
        &["audit", "."],
        &[("CLICOLOR_FORCE", "1"), ("NO_COLOR", "")],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\x1b["),
        "empty NO_COLOR=\"\" must not disable color: {stdout}"
    );
}

#[test]
fn audit_color_precedence_flag_overrides_no_color_and_force() {
    let fixture = AuditFixture::new("color-precedence");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    // Flag takes precedence over everything
    let output = run_from_with_env(
        &fixture.0,
        &["audit", ".", "--no-color"],
        &[("CLICOLOR_FORCE", "1"), ("NO_COLOR", "")],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("\x1b["),
        "--no-color flag must take precedence over CLICOLOR_FORCE: {stdout}"
    );
}

#[test]
fn audit_color_summary_only_mode_respects_no_color() {
    let fixture = AuditFixture::new("color-summary-only");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    // Forced color with summary-only produces ANSI
    let colored_output = run_from_with_env(
        &fixture.0,
        &["audit", ".", "--summary-only"],
        &[("CLICOLOR_FORCE", "1")],
        &["NO_COLOR"],
    );
    let colored_stdout = String::from_utf8_lossy(&colored_output.stdout);
    assert!(
        colored_stdout.contains("\x1b["),
        "summary-only with forced color must contain ANSI codes: {colored_stdout}"
    );

    // Summary-only with --no-color contains no ANSI
    let plain_output = run_from_with_env(
        &fixture.0,
        &["audit", ".", "--summary-only", "--no-color"],
        &[("CLICOLOR_FORCE", "1")],
        &["NO_COLOR"],
    );
    let plain_stdout = String::from_utf8_lossy(&plain_output.stdout);
    assert!(
        !plain_stdout.contains("\x1b["),
        "summary-only with --no-color must contain no ANSI codes: {plain_stdout}"
    );
}

#[test]
fn audit_color_default_regression_plain_in_non_terminal() {
    let fixture = AuditFixture::new("color-default-reg");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let output = run_from_with_env(
        &fixture.0,
        &["audit", "."],
        &[],
        &["CLICOLOR_FORCE", "NO_COLOR"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("\x1b["),
        "default execution in test process without terminal must not produce ANSI codes: {stdout}"
    );
}

// ---- #338: configurable text output width ----

#[test]
fn audit_width_long_message_wraps_at_specified_width() {
    let fixture = AuditFixture::new("width-wrap");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let output = run_from(&fixture.0, &["audit", ".", "--width", "50"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Finding line should wrap into continuation lines indented with 4 spaces
    assert!(
        stdout.contains("\n    "),
        "continuation line must be indented with 4 spaces: {stdout}"
    );
    for line in stdout.lines() {
        if line.starts_with("crates/vault/src/lib.rs:") || line.starts_with("    ") {
            // Check that line length (visible characters) does not exceed 50
            assert!(line.chars().count() <= 50, "line exceeds width 50: {line}");
        }
    }
}

#[test]
fn audit_width_invalid_values_rejected_with_actionable_error() {
    let fixture = AuditFixture::new("width-invalid");

    // Zero
    let out_zero = run_from(&fixture.0, &["audit", ".", "--width", "0"]);
    assert!(!out_zero.status.success());
    let err_zero = String::from_utf8_lossy(&out_zero.stderr);
    assert!(err_zero.contains("invalid width `0`"), "stderr: {err_zero}");

    // Negative
    let out_neg = run_from(&fixture.0, &["audit", ".", "--width", "-5"]);
    assert!(!out_neg.status.success());
    let err_neg = String::from_utf8_lossy(&out_neg.stderr);
    assert!(err_neg.contains("invalid width `-5`"), "stderr: {err_neg}");

    // Non-numeric
    let out_alpha = run_from(&fixture.0, &["audit", ".", "--width", "abc"]);
    assert!(!out_alpha.status.success());
    let err_alpha = String::from_utf8_lossy(&out_alpha.stderr);
    assert!(
        err_alpha.contains("invalid width `abc`"),
        "stderr: {err_alpha}"
    );

    // Absurdly large
    let out_huge = run_from(&fixture.0, &["audit", ".", "--width", "50000"]);
    assert!(!out_huge.status.success());
    let err_huge = String::from_utf8_lossy(&out_huge.stderr);
    assert!(
        err_huge.contains("invalid width `50000`"),
        "stderr: {err_huge}"
    );
}

#[test]
fn audit_width_configuration_in_toml_honored() {
    let fixture = AuditFixture::new("width-toml");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write(".soroban-testkit.toml", "width = 45\n");
    let output = run_from(&fixture.0, &["audit", "."]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\n    "),
        "must wrap based on config file width: {stdout}"
    );

    // CLI overrides configuration file
    let cli_output = run_from(&fixture.0, &["audit", ".", "--width", "120"]);
    let cli_stdout = String::from_utf8_lossy(&cli_output.stdout);
    let finding_line = cli_stdout
        .lines()
        .find(|l| l.starts_with("crates/vault/src/lib.rs:"))
        .expect("finding line must exist");
    assert!(!finding_line.is_empty());
}

#[test]
fn audit_width_default_unwrapped_regression() {
    let fixture = AuditFixture::new("width-unwrapped");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let output = run_from(&fixture.0, &["audit", "."]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let finding_line = stdout
        .lines()
        .find(|l| l.starts_with("crates/vault/src/lib.rs:"))
        .expect("finding line must exist");
    // Default has no continuation lines for the finding message
    assert!(
        finding_line.contains("fn withdraw takes Address parameter(s)"),
        "default finding line must contain full message without wrapping: {finding_line}"
    );
}

// ---- #339: rule confidence and known limitations ----

#[test]
fn audit_rules_walk_registry_confidence_and_limitations() {
    let output = run(&["audit", "rules", "--format", "json"]);
    assert!(
        output.status.success(),
        "audit rules --format json must succeed"
    );

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let rules = report["rules"].as_array().expect("rules must be an array");
    assert!(!rules.is_empty(), "rule registry must not be empty");

    let valid_confidence = ["high", "medium", "low", "not assessed"];

    for rule in rules {
        let id = rule["id"].as_str().expect("rule must have string id");
        let confidence = rule["confidence"]
            .as_str()
            .expect("rule must have string confidence");
        assert!(
            valid_confidence.contains(&confidence),
            "rule {id} has invalid confidence '{confidence}'"
        );

        let limitations = rule["limitations"]
            .as_array()
            .expect("limitations must be an array");
        assert!(
            !limitations.is_empty(),
            "rule {id} must have at least one limitation or explicit 'none known'"
        );
        for lim in limitations {
            let lim_str = lim.as_str().expect("limitation must be string");
            assert!(
                !lim_str.trim().is_empty(),
                "rule {id} has empty limitation string"
            );
        }
    }
}

#[test]
fn audit_rules_listing_and_explain_output_includes_confidence_and_limitations() {
    // Check text listing
    let list_out = run(&["audit", "rules"]);
    assert!(list_out.status.success());
    let list_stdout = String::from_utf8_lossy(&list_out.stdout);
    assert!(
        list_stdout.contains("CONFIDENCE"),
        "listing must have CONFIDENCE column: {list_stdout}"
    );
    assert!(
        list_stdout.contains("* limitation:"),
        "listing must list limitations: {list_stdout}"
    );

    // Check rule explain output
    let explain_out = run(&["audit", "explain", "missing-require-auth"]);
    assert!(explain_out.status.success());
    let explain_stdout = String::from_utf8_lossy(&explain_out.stdout);
    assert!(
        explain_stdout.contains("Confidence: medium"),
        "explain output must show confidence: {explain_stdout}"
    );
    assert!(
        explain_stdout.contains("Known limitations:"),
        "explain output must list limitations: {explain_stdout}"
    );
    assert!(
        explain_stdout.contains("Cannot inspect code generated by macros"),
        "explain output must include verified limitations: {explain_stdout}"
    );
}

#[test]
fn audit_rule_demonstrates_documented_limitation_unchecked_i128() {
    // Limitation: unchecked-i128-arithmetic only tracks function parameter bindings, not local let bindings
    let source = br#"
#[contractimpl]
impl Calculator {
    pub fn compute(env: Env) {
        let a: i128 = 100;
        let b = a + 1;
    }
}
"#;
    let output = run_with_stdin(&["audit", "-", "--format", "json"], source);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let i128_findings: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule"] == "unchecked-i128-arithmetic")
        .collect();
    assert!(
        i128_findings.is_empty(),
        "documented limitation: local let binding arithmetic is not flagged"
    );
}

#[test]
fn audit_structured_output_includes_additive_remediation() {
    let fixture = AuditFixture::new("remediation-structured");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let output = fixture.scan(&["--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = &report["findings"][0];
    assert_eq!(finding["rule"], "missing-require-auth");
    let remediation = finding["remediation"]
        .as_str()
        .expect("finding remediation");
    assert!(
        remediation.contains("require_auth"),
        "remediation missing expected content: {remediation}"
    );
}

// ---- #325: summary grouped by severity and rule ----

#[test]
fn audit_summary_human_readable_grouped_by_severity_and_rule() {
    let fixture = AuditFixture::new("summary-human-readable");
    fixture.write(
        "crates/vault/src/lib.rs",
        r#"
        #[contractimpl]
        impl Vault {
            pub fn withdraw(env: Env, from: Address, amount: i128) {
                let x = amount + 1;
                let _ = &from;
            }
        }
        "#,
    );
    let output = fixture.scan(&["--format", "text"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Summary:"), "{stdout}");
    assert!(stdout.contains("warning:"), "{stdout}");
    assert!(stdout.contains("missing-require-auth"), "{stdout}");
    assert!(stdout.contains("unchecked-i128-arithmetic"), "{stdout}");
    assert!(
        stdout.contains("Total: 3 finding(s) across 1 file(s) scanned"),
        "{stdout}"
    );

    // Summary must be the last section
    let summary_pos = stdout.find("Summary:").unwrap();
    let note_pos = stdout.rfind("note:").unwrap();
    assert!(summary_pos > note_pos, "Summary should appear after notes");
}

#[test]
fn audit_summary_clean_run_has_no_findings_summary() {
    let fixture = AuditFixture::new("summary-clean");
    fixture.write("crates/vault/src/lib.rs", "// clean contract\n");
    let output = fixture.scan(&["--format", "text"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("audit: no findings"), "{stdout}");
    assert!(!stdout.contains("Summary:"), "{stdout}");
}

#[test]
fn audit_summary_json_structured_output_is_additive() {
    let fixture = AuditFixture::new("summary-json");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let output = fixture.scan(&["--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let summary = &report["summary"];
    assert_eq!(summary["finding_count"], 1);
    assert_eq!(summary["files_scanned"], 1);
    let by_sev = summary["by_severity"]
        .as_array()
        .expect("by_severity array");
    assert_eq!(by_sev.len(), 1);
    assert_eq!(by_sev[0]["severity"], "warning");
    assert_eq!(by_sev[0]["total"], 1);
    assert_eq!(by_sev[0]["rules"][0]["rule"], "missing-require-auth");
    assert_eq!(by_sev[0]["rules"][0]["count"], 1);
}

#[test]
fn audit_summary_deterministic_across_runs() {
    let fixture = AuditFixture::new("summary-determinism");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let out1 = fixture.scan(&["--format", "text"]);
    let out2 = fixture.scan(&["--format", "text"]);
    assert_eq!(out1.stdout, out2.stdout);
}

// ---- #328: include and exclude glob patterns ----

#[test]
fn audit_filter_include_only() {
    let fixture = AuditFixture::new("filter-include-only");
    fixture.write("src/included.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write("src/other.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--include", "src/included.rs", "--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 1);
    assert_eq!(report["summary"]["files_scanned"], 1);
    assert_eq!(report["findings"][0]["file"], "src/included.rs");
}

#[test]
fn audit_filter_exclude_only() {
    let fixture = AuditFixture::new("filter-exclude-only");
    fixture.write("src/a.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write("src/b.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--exclude", "src/b.rs", "--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 1);
    assert_eq!(report["summary"]["files_scanned"], 1);
    assert_eq!(report["findings"][0]["file"], "src/a.rs");
}

#[test]
fn audit_filter_both_with_exclude_winning() {
    let fixture = AuditFixture::new("filter-exclude-wins");
    fixture.write("src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write("src/nested/mod.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&[
        "--include",
        "src/**/*.rs",
        "--exclude",
        "src/nested/**",
        "--format",
        "json",
    ]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 1);
    assert_eq!(report["summary"]["files_scanned"], 1);
    assert_eq!(report["findings"][0]["file"], "src/lib.rs");
}

#[test]
fn audit_filter_nested_double_star() {
    let fixture = AuditFixture::new("filter-nested-double-star");
    fixture.write(
        "crates/vault/src/deep/nested/lib.rs",
        UNAUTHORIZED_ENTRY_POINT,
    );
    fixture.write("crates/vault/tests/ignored.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--include", "crates/**/src/**/*.rs", "--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 1);
    assert_eq!(
        report["findings"][0]["file"],
        "crates/vault/src/deep/nested/lib.rs"
    );
}

#[test]
fn audit_filter_character_classes() {
    let fixture = AuditFixture::new("filter-char-classes");
    fixture.write("src/a_vault.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write("src/b_vault.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write("src/z_vault.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--include", "src/[a-b]_*.rs", "--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 2);
    assert_eq!(report["summary"]["files_scanned"], 2);
}

#[test]
fn audit_filter_directory_patterns() {
    let fixture = AuditFixture::new("filter-dir-pattern");
    fixture.write("src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write("tests/integration.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--exclude", "tests/", "--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 1);
    assert_eq!(report["findings"][0]["file"], "src/lib.rs");
}

#[test]
fn audit_filter_no_pattern_unchanged_behavior() {
    let fixture = AuditFixture::new("filter-no-pattern");
    fixture.write("src/a.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write("src/b.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 2);
    assert_eq!(report["summary"]["files_scanned"], 2);
}

#[test]
fn audit_filter_repeated_flags() {
    let fixture = AuditFixture::new("filter-repeated-flags");
    fixture.write("src/a.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write("src/b.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write("src/c.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&[
        "--include",
        "src/a.rs",
        "--include",
        "src/b.rs",
        "--format",
        "json",
    ]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 2);
    assert_eq!(report["summary"]["files_scanned"], 2);
}

#[test]
fn audit_filter_invalid_pattern_error_text_and_exit_code() {
    let fixture = AuditFixture::new("filter-invalid-pat");
    fixture.write("src/lib.rs", UNAUTHORIZED_ENTRY_POINT);

    // Unclosed bracket
    let output = fixture.scan(&["--include", "[a-z"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid glob pattern"), "{stderr}");
    assert!(stderr.contains("unclosed character class"), "{stderr}");

    // Empty pattern
    let output_empty = fixture.scan(&["--include", ""]);
    assert!(!output_empty.status.success());
    let stderr_empty = String::from_utf8_lossy(&output_empty.stderr);
    assert!(stderr_empty.contains("cannot be empty"), "{stderr_empty}");
}

#[test]
fn audit_filter_matching_nothing_reports_clearly() {
    let fixture = AuditFixture::new("filter-match-nothing");
    fixture.write("src/lib.rs", UNAUTHORIZED_ENTRY_POINT);

    let text_output = fixture.scan(&["--include", "nonexistent/*.rs", "--format", "text"]);
    assert!(text_output.status.success(), "{text_output:?}");
    let stdout = String::from_utf8_lossy(&text_output.stdout);
    assert!(
        stdout.contains("audit: no files matched the configured include/exclude filters"),
        "{stdout}"
    );

    let json_output = fixture.scan(&["--include", "nonexistent/*.rs", "--format", "json"]);
    assert!(json_output.status.success(), "{json_output:?}");
    let report: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 0);
    assert_eq!(report["summary"]["files_scanned"], 0);
    assert_eq!(
        report["summary"]["message"],
        "no files matched the configured include/exclude filters"
    );
}

#[test]
fn audit_rule_demonstrates_documented_limitation_missing_positive_amount() {
    // Limitation: missing-positive-amount-validation only inspects parameters named *amount*
    let source = br#"
#[contractimpl]
impl Vault {
    pub fn deposit(env: Env, tokens: i128) {
        // tokens is signed i128 without positive check, but parameter is not named *amount*
    }
}
"#;
    let output = run_with_stdin(&["audit", "-", "--format", "json"], source);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let amount_findings: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["rule"] == "missing-positive-amount-validation")
        .collect();
    assert!(
        amount_findings.is_empty(),
        "documented limitation: parameters without 'amount' in identifier are not flagged"
    );
}

#[test]
fn audit_filter_platform_style_separators() {
    let fixture = AuditFixture::new("filter-platform-separators");
    fixture.write("src/nested/lib.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--include", "src\\nested\\*.rs", "--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 1);
    assert_eq!(report["findings"][0]["file"], "src/nested/lib.rs");
}

#[test]
fn audit_filter_excluded_files_are_never_opened() {
    let fixture = AuditFixture::new("filter-never-opened");
    fixture.write("src/valid.rs", UNAUTHORIZED_ENTRY_POINT);
    // Put completely invalid syntax in the excluded file
    fixture.write("src/broken.rs", "fn broken( { let x = ;");

    let output = fixture.scan(&["--exclude", "src/broken.rs", "--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    assert!(
        output.stderr.is_empty(),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 1);
    assert_eq!(report["summary"]["skipped_file_count"], 0);
    assert!(report["summary"]["parser_limitations"]
        .as_array()
        .unwrap()
        .is_empty());
}
// ---- #323: validate configuration keys and report unknown rules ----

#[test]
fn audit_config_validation_accepts_valid_configuration() {
    let fixture = AuditFixture::new("config-valid");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write(
        ".soroban-testkit.toml",
        "[rules.missing-require-auth]\nenabled = true\nseverity = 'warning'\n",
    );
    let output = fixture.scan(&[]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn audit_config_validation_rejects_unknown_top_level_key() {
    let fixture = AuditFixture::new("config-unknown-top");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let path = fixture.write(
        ".soroban-testkit.toml",
        "unknown_option = true\n[rules.missing-require-auth]\nenabled = true\n",
    );
    let output = fixture.scan(&[]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to validate audit config"),
        "{stderr}"
    );
    assert!(stderr.contains(path.to_str().unwrap()), "{stderr}");
    assert!(stderr.contains("unknown_option"), "{stderr}");
    assert!(stderr.contains("unknown configuration key"), "{stderr}");
}

#[test]
fn audit_config_validation_rejects_unknown_nested_key() {
    let fixture = AuditFixture::new("config-unknown-nested");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let path = fixture.write(
        ".soroban-testkit.toml",
        "[rules.missing-require-auth]\nenabled = true\ninvalid_prop = 42\n",
    );
    let output = fixture.scan(&[]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to validate audit config"),
        "{stderr}"
    );
    assert!(stderr.contains(path.to_str().unwrap()), "{stderr}");
    assert!(
        stderr.contains("rules.missing-require-auth.invalid_prop"),
        "{stderr}"
    );
    assert!(stderr.contains("unknown configuration key"), "{stderr}");
}

#[test]
fn audit_config_validation_rejects_unknown_rule_with_valid_choices() {
    let fixture = AuditFixture::new("config-unknown-rule");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let path = fixture.write(
        ".soroban-testkit.toml",
        "[rules.nonexistent-audit-rule]\nenabled = false\n",
    );
    let output = fixture.scan(&[]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to validate audit config"),
        "{stderr}"
    );
    assert!(stderr.contains(path.to_str().unwrap()), "{stderr}");
    assert!(
        stderr.contains("unknown rule `nonexistent-audit-rule`"),
        "{stderr}"
    );
    assert!(stderr.contains("missing-require-auth"), "{stderr}");
    assert!(stderr.contains("unchecked-i128-arithmetic"), "{stderr}");
}

#[test]
fn audit_config_validation_reports_multiple_problems_deterministically() {
    let fixture = AuditFixture::new("config-multiple-errors");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write(
        ".soroban-testkit.toml",
        "bad_key_1 = 'a'\n[rules.typo-rule]\nenabled = true\n[rules.missing-require-auth]\nbad_nested = 1\n",
    );
    let run1 = fixture.scan(&[]);
    let run2 = fixture.scan(&[]);
    assert!(!run1.status.success());
    assert!(!run2.status.success());
    let stderr1 = String::from_utf8_lossy(&run1.stderr);
    let stderr2 = String::from_utf8_lossy(&run2.stderr);
    assert_eq!(stderr1, stderr2);
    assert!(stderr1.contains("bad_key_1"), "{stderr1}");
    assert!(stderr1.contains("typo-rule"), "{stderr1}");
    assert!(stderr1.contains("bad_nested"), "{stderr1}");
}

#[test]
fn audit_config_validation_ignores_other_tool_sections() {
    let fixture = AuditFixture::new("config-other-sections");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write(
        ".soroban-testkit.toml",
        "[coverage]\nfail_under = 80\n[limits]\ntimeout = 30\n[other_section]\nfoo = 'bar'\n[rules.missing-require-auth]\nenabled = true\n",
    );
    let output = fixture.scan(&[]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn audit_config_validation_handles_empty_or_missing_configuration() {
    let fixture = AuditFixture::new("config-empty-missing");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    // Missing config
    let output1 = fixture.scan(&[]);
    assert!(output1.status.success());

    // Empty config
    fixture.write(".soroban-testkit.toml", "");
    let output2 = fixture.scan(&[]);
    assert!(output2.status.success());

    // Whitespace only config
    fixture.write(".soroban-testkit.toml", "   \n\n  \t\n");
    let output3 = fixture.scan(&[]);
    assert!(output3.status.success());
}

#[test]
fn audit_config_validation_regression_previously_valid_config_still_loads() {
    let fixture = AuditFixture::new("config-regression");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write(
        ".soroban-testkit.toml",
        "[rules.missing-require-auth]\nenabled = false\n[rules.unchecked-i128-arithmetic]\nseverity = 'warning'\n",
    );
    let output = fixture.scan(&["--strict"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---- #322: allow per-rule severity overrides ----

#[test]
fn audit_severity_override_sets_effective_severity() {
    let fixture = AuditFixture::new("severity-override");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write(
        ".soroban-testkit.toml",
        "[rules.missing-require-auth]\nseverity = 'error'\n",
    );
    let output = fixture.scan(&["--format", "json"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["findings"][0]["severity"], "error");
}

#[test]
fn audit_severity_override_case_insensitive() {
    let fixture = AuditFixture::new("severity-case");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write(
        ".soroban-testkit.toml",
        "[rules.missing-require-auth]\nseverity = 'ERROR'\n",
    );
    let output = fixture.scan(&["--format", "json"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["findings"][0]["severity"], "error");
}

#[test]
fn audit_severity_override_rejects_invalid_severity_value() {
    let fixture = AuditFixture::new("severity-invalid");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let path = fixture.write(
        ".soroban-testkit.toml",
        "[rules.missing-require-auth]\nseverity = 'fatal'\n",
    );
    let output = fixture.scan(&[]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to validate audit config"),
        "{stderr}"
    );
    assert!(stderr.contains(path.to_str().unwrap()), "{stderr}");
    assert!(stderr.contains("invalid severity `fatal`"), "{stderr}");
    assert!(
        stderr.contains("allowed values are: error, warning, note"),
        "{stderr}"
    );
}

#[test]
fn audit_severity_override_multiple_rules_at_once() {
    let fixture = AuditFixture::new("severity-multiple");
    fixture.write(
        "crates/vault/src/lib.rs",
        r#"
        #[contractimpl]
        impl Contract {
            pub fn withdraw(env: Env, from: Address) {
                let x: i128 = 10;
                let _ = x + 1;
            }
        }
    "#,
    );
    fixture.write(
        ".soroban-testkit.toml",
        "[rules.missing-require-auth]\nseverity = 'error'\n[rules.unchecked-i128-arithmetic]\nseverity = 'note'\n",
    );
    let output = fixture.scan(&["--format", "json"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    for finding in findings {
        if finding["rule"] == "missing-require-auth" {
            assert_eq!(finding["severity"], "error");
        } else if finding["rule"] == "unchecked-i128-arithmetic" {
            assert_eq!(finding["severity"], "note");
        }
    }
}

#[test]
fn audit_no_severity_overrides_leaves_default_severities() {
    let fixture = AuditFixture::new("severity-defaults");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let output = fixture.scan(&["--format", "json"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["findings"][0]["severity"], "warning");
}

// ---- #321: support excluding generated source directories ----

#[test]
fn audit_excludes_directory_via_cli_flag() {
    let fixture = AuditFixture::new("exclude-cli");
    std::fs::create_dir_all(fixture.0.join("src/gen")).unwrap();
    fixture.write("src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write("src/gen/generated.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--exclude", "src/gen"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["file"], "src/lib.rs");
}

#[test]
fn audit_excludes_directory_via_config() {
    let fixture = AuditFixture::new("exclude-config");
    std::fs::create_dir_all(fixture.0.join("generated")).unwrap();
    fixture.write("src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write("generated/code.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write(".soroban-testkit.toml", "exclude = [\"generated\"]\n");

    let output = fixture.scan(&[]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["file"], "src/lib.rs");
}

#[test]
fn audit_excludes_directory_matches_whole_path_components() {
    let fixture = AuditFixture::new("exclude-whole-component");
    std::fs::create_dir_all(fixture.0.join("gen")).unwrap();
    std::fs::create_dir_all(fixture.0.join("generated_utils")).unwrap();
    std::fs::create_dir_all(fixture.0.join("src/regen")).unwrap();
    fixture.write("gen/a.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write("generated_utils/b.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write("src/regen/c.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--exclude", "gen"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    let files: Vec<&str> = findings
        .iter()
        .map(|f| f["file"].as_str().unwrap())
        .collect();
    assert!(!files.contains(&"gen/a.rs"), "{files:?}");
    assert!(files.contains(&"generated_utils/b.rs"), "{files:?}");
    assert!(files.contains(&"src/regen/c.rs"), "{files:?}");
}

#[test]
fn audit_excludes_normalizes_trailing_slashes_and_leading_dotslash() {
    let fixture = AuditFixture::new("exclude-normalize");
    std::fs::create_dir_all(fixture.0.join("gen/nested")).unwrap();
    fixture.write("src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write("gen/nested/gen.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--exclude", "./gen/nested/"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["file"], "src/lib.rs");
}

#[test]
fn audit_excludes_nonexistent_directory_is_safe_and_does_not_fail() {
    let fixture = AuditFixture::new("exclude-nonexistent");
    fixture.write("src/lib.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--exclude", "does_not_exist"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 1);
}

#[test]
fn audit_excludes_rejects_paths_that_escape_project_root() {
    let fixture = AuditFixture::new("exclude-escape");
    fixture.write("src/lib.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--exclude", "../escaped"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("escapes the project root"), "{stderr}");
}

#[test]
fn audit_scans_explicit_file_inside_excluded_directory() {
    let fixture = AuditFixture::new("exclude-explicit-file");
    std::fs::create_dir_all(fixture.0.join("gen")).unwrap();
    let file = fixture.write("gen/lib.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = run_from(
        &fixture.0,
        &[
            "audit",
            file.to_str().unwrap(),
            "--exclude",
            "gen",
            "--format",
            "json",
        ],
    );
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 1);
}

#[test]
fn audit_combines_config_and_cli_exclusions() {
    let fixture = AuditFixture::new("exclude-combined");
    std::fs::create_dir_all(fixture.0.join("gen1")).unwrap();
    std::fs::create_dir_all(fixture.0.join("gen2")).unwrap();
    fixture.write("src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write("gen1/a.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write("gen2/b.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write(".soroban-testkit.toml", "exclude = [\"gen1\"]\n");

    let output = fixture.scan(&["--exclude", "gen2"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["file"], "src/lib.rs");
}

#[test]
fn audit_no_exclusions_regression() {
    let fixture = AuditFixture::new("exclude-none");
    fixture.write("src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let output = fixture.scan(&[]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 1);
}

// ---- #320: report source ranges for multi-line findings ----

#[test]
fn audit_single_line_finding_looks_exactly_as_before() {
    let fixture = AuditFixture::new("ranges-single-line");
    fixture.write("src/lib.rs", "fn test_broad() { mock_all_auths(); }\n");

    // Text format: prefix is file:line: without range suffix
    let text_output = fixture.scan(&["--format", "text"]);
    assert!(text_output.status.success());
    let text = String::from_utf8_lossy(&text_output.stdout);
    assert!(text.contains("src/lib.rs:1: ["), "text: {text}");
    assert!(!text.contains("src/lib.rs:1:-"), "text: {text}");

    // JSON format: end_line is omitted for single-line findings
    let json_output = fixture.scan(&["--format", "json"]);
    assert!(json_output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    let finding = &report["findings"][0];
    assert_eq!(finding["line"], 1);
    assert!(
        finding.get("end_line").is_none(),
        "end_line should not be serialized for single-line: {finding}"
    );

    // SARIF format: region contains startLine and no endLine
    let sarif_output = fixture.scan(&["--format", "sarif"]);
    assert!(sarif_output.status.success());
    let sarif: serde_json::Value = serde_json::from_slice(&sarif_output.stdout).unwrap();
    let region = &sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
    assert_eq!(region["startLine"], 1);
    assert!(
        region.get("endLine").is_none(),
        "endLine should not be present in SARIF: {region}"
    );
}

#[test]
fn audit_multi_line_finding_has_correct_start_and_end() {
    // Arithmetic worked out by hand:
    // Line 1: #[contractimpl]
    // Line 2: impl Contract {
    // Line 3:     pub fn withdraw(
    // Line 4:         env: Env,
    // Line 5:         from: Address,
    // Line 6:     ) {
    // Line 7:         save(&from);
    // Line 8:     }
    // Line 9: }
    // The fn `withdraw` starts at line 3 (token `pub`) and ends at line 8 (token `}`).
    // Spanned lines: [3, 8], span length = 8 - 3 + 1 = 6 lines.
    let source = "\
#[contractimpl]
impl Contract {
    pub fn withdraw(
        env: Env,
        from: Address,
    ) {
        save(&from);
    }
}
";
    let fixture = AuditFixture::new("ranges-multiline");
    fixture.write("src/lib.rs", source);

    // JSON format
    let json_output = fixture.scan(&["--format", "json"]);
    assert!(json_output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&json_output.stdout).unwrap();
    let finding = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule"] == "missing-require-auth")
        .expect("missing-require-auth finding must be present");
    assert_eq!(finding["line"], 3, "start line: {finding}");
    assert_eq!(finding["end_line"], 8, "end line: {finding}");

    // SARIF format
    let sarif_output = fixture.scan(&["--format", "sarif"]);
    assert!(sarif_output.status.success());
    let sarif: serde_json::Value = serde_json::from_slice(&sarif_output.stdout).unwrap();
    let result = sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["ruleId"] == "missing-require-auth")
        .expect("missing-require-auth result must be present in SARIF");
    let region = &result["locations"][0]["physicalLocation"]["region"];
    assert_eq!(region["startLine"], 3);
    assert_eq!(region["endLine"], 8);

    // Text format: keeps file:line: prefix and appends range
    let text_output = fixture.scan(&["--format", "text"]);
    assert!(text_output.status.success());
    let text = String::from_utf8_lossy(&text_output.stdout);
    assert!(
        text.contains("src/lib.rs:3:-8:"),
        "text must keep prefix and append range: {text}"
    );
}

#[test]
fn audit_multi_line_finding_crlf_input() {
    // Arithmetic worked out by hand:
    // Line 1: #[contractimpl]\r\n
    // Line 2: impl Contract {\r\n
    // Line 3:     pub fn withdraw(\r\n
    // Line 4:         env: Env,\r\n
    // Line 5:         from: Address,\r\n
    // Line 6:     ) {\r\n
    // Line 7:         save(&from);\r\n
    // Line 8:     }\r\n
    // Line 9: }\r\n
    // Line range: start = 3, end = 8.
    let crlf_source = "#[contractimpl]\r\nimpl Contract {\r\n    pub fn withdraw(\r\n        env: Env,\r\n        from: Address,\r\n    ) {\r\n        save(&from);\r\n    }\r\n}\r\n";
    let fixture = AuditFixture::new("ranges-crlf");
    fixture.write("src/lib.rs", crlf_source);

    let output = fixture.scan(&["--format", "json"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = &report["findings"][0];
    assert_eq!(finding["line"], 3);
    assert_eq!(finding["end_line"], 8);
}

#[test]
fn audit_multi_line_finding_with_multibyte_characters_before_finding() {
    // Arithmetic worked out by hand:
    // Line 1: // 🦀 Stellar Smart Contracts 🚀\n
    // Line 2: // 日本語コメント 雪\n
    // Line 3: #[contractimpl]\n
    // Line 4: impl Contract {\n
    // Line 5:     pub fn withdraw(\n
    // Line 6:         env: Env,\n
    // Line 7:         from: Address,\n
    // Line 8:     ) {\n
    // Line 9:         save(&from);\n
    // Line 10:    }\n
    // Line 11: }\n
    // With 2 multibyte comment lines before the impl, `withdraw` starts at line 5 and ends at line 10.
    let source = "// 🦀 Stellar Smart Contracts 🚀\n// 日本語コメント 雪\n#[contractimpl]\nimpl Contract {\n    pub fn withdraw(\n        env: Env,\n        from: Address,\n    ) {\n        save(&from);\n    }\n}\n";
    let fixture = AuditFixture::new("ranges-multibyte");
    fixture.write("src/lib.rs", source);

    let output = fixture.scan(&["--format", "json"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = &report["findings"][0];
    assert_eq!(finding["line"], 5);
    assert_eq!(finding["end_line"], 10);
}

#[test]
fn audit_multi_line_finding_ending_at_end_of_file() {
    // Arithmetic worked out by hand:
    // Line 1: pub fn withdraw(
    // Line 2:     env: Env,
    // Line 3:     from: Address,
    // Line 4: ) { save(&from); }
    // No trailing newline after line 4.
    // Start line: 1. End line: 4.
    let source = "pub fn withdraw(\n    env: Env,\n    from: Address,\n) { save(&from); }";
    let fixture = AuditFixture::new("ranges-eof");
    fixture.write("src/lib.rs", source);

    let output = fixture.scan(&["--format", "json"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = &report["findings"][0];
    assert_eq!(finding["line"], 1);
    assert_eq!(finding["end_line"], 4);
}

#[test]
fn audit_structured_output_only_gained_fields() {
    let fixture = AuditFixture::new("ranges-fields");
    fixture.write("src/lib.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--format", "json"]);
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let finding = &report["findings"][0];
    assert!(finding.get("file").is_some());
    assert!(finding.get("line").is_some());
    assert!(finding.get("rule").is_some());
    assert!(finding.get("severity").is_some());
    assert!(finding.get("message").is_some());
    assert!(finding.get("source_snippet").is_some());
    assert!(finding.get("end_line").is_some());
}

#[test]
fn audit_text_output_keeps_prefix() {
    let fixture = AuditFixture::new("ranges-text-prefix");
    fixture.write("src/lib.rs", UNAUTHORIZED_ENTRY_POINT);

    let output = fixture.scan(&["--format", "text"]);
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("src/lib.rs:3:"),
        "must keep src/lib.rs:3: prefix: {text}"
    );
}

// ---------------------------------------------------------------------------
// Issues #317-#319: project config defaults, workflow annotations, stable ids
// ---------------------------------------------------------------------------

#[test]
fn audit_config_defaults_are_documented_in_rule_listing() {
    let output = run(&["audit", "rules", "--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let rules = report["rules"].as_array().expect("rules array");
    assert_eq!(rules.len(), 7);
    for rule in rules {
        assert_eq!(rule["defaultEnabled"], true, "{rule}");
        assert!(rule["defaultSeverity"].as_str().is_some(), "{rule}");
        assert!(!rule["identifier"].as_str().unwrap_or_default().is_empty());
    }

    let explained = run(&["audit", "explain", "missing-require-auth"]);
    assert!(explained.status.success(), "{explained:?}");
    let text = String::from_utf8_lossy(&explained.stdout);
    assert!(
        text.contains("Default: enabled=true, severity=warning"),
        "{text}"
    );
}

#[test]
fn audit_explicit_config_path_overrides_discovery() {
    let fixture = AuditFixture::new("explicit-config");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write(
        ".soroban-testkit.toml",
        "[rules.missing-require-auth]\nenabled = false\n",
    );
    fixture.write(
        "crates/vault/enable.toml",
        "[rules.missing-require-auth]\nenabled = true\n",
    );

    let discovered = fixture.scan(&["--format", "json"]);
    assert!(discovered.status.success(), "{discovered:?}");
    let report: serde_json::Value = serde_json::from_slice(&discovered.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 0);

    let explicit = fixture.scan(&["--config", "crates/vault/enable.toml", "--format", "json"]);
    assert!(explicit.status.success(), "{explicit:?}");
    let report: serde_json::Value = serde_json::from_slice(&explicit.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 1);
}

#[test]
fn audit_missing_explicit_config_errors_actionably() {
    let fixture = AuditFixture::new("missing-explicit-config");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let output = fixture.scan(&["--config", "does-not-exist.toml"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("audit config") && stderr.contains("does not exist"),
        "{stderr}"
    );
    assert!(!stderr.contains("panicked at"), "{stderr}");
}

#[test]
fn audit_width_key_in_config_is_accepted() {
    let fixture = AuditFixture::new("config-width-key");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    fixture.write(".soroban-testkit.toml", "width = 40\n");
    let output = fixture.scan(&["--format", "text"]);
    assert!(
        output.status.success(),
        "config `width` should be accepted: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn audit_annotations_are_emitted_to_stderr_only() {
    let fixture = AuditFixture::new("annotations");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let output = fixture.scan(&["--annotations", "--format", "json"]);
    assert!(output.status.success(), "{output:?}");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("::warning file=crates/vault/src/lib.rs,line="),
        "{stderr}"
    );
    assert!(stderr.contains("title=missing-require-auth,"), "{stderr}");
    assert!(
        stderr.contains("heuristic finding (manual review)"),
        "{stderr}"
    );

    // stdout remains a clean JSON report.
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["finding_count"], 1);
}

#[test]
fn audit_annotations_absent_without_flag() {
    let fixture = AuditFixture::new("annotations-off");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);
    let output = fixture.scan(&["--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("::warning file="));
}

#[test]
fn audit_annotations_clean_scan_emits_nothing() {
    let fixture = AuditFixture::new("annotations-clean");
    fixture.write("crates/vault/src/lib.rs", "pub fn safe() {}\n");
    let output = fixture.scan(&["--annotations", "--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("::warning file="));
}

#[test]
fn audit_stable_rule_id_is_present_in_every_output_format() {
    let fixture = AuditFixture::new("stable-rule-id");
    fixture.write("crates/vault/src/lib.rs", UNAUTHORIZED_ENTRY_POINT);

    let text = fixture.scan(&["--format", "text"]);
    assert!(text.status.success(), "{text:?}");
    assert!(String::from_utf8_lossy(&text.stdout).contains("missing-require-auth"));

    let summary = fixture.scan(&["--summary-only", "--format", "text"]);
    assert!(summary.status.success(), "{summary:?}");
    assert!(String::from_utf8_lossy(&summary.stdout).contains("missing-require-auth"));

    let json = fixture.scan(&["--format", "json"]);
    assert!(json.status.success(), "{json:?}");
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let finding = &report["findings"][0];
    assert_eq!(finding["rule"], "missing-require-auth");
    assert_eq!(finding["rule_id"], "missing-require-auth");

    let sarif = fixture.scan(&["--format", "sarif"]);
    assert!(sarif.status.success(), "{sarif:?}");
    let report: serde_json::Value = serde_json::from_slice(&sarif.stdout).unwrap();
    let result = &report["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "missing-require-auth");
    assert_eq!(result["properties"]["stableRuleId"], "missing-require-auth");
}

#[test]
fn audit_stable_rule_ids_are_unique_and_nonempty() {
    let output = run(&["audit", "rules", "--format", "json"]);
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let rules = report["rules"].as_array().expect("rules array");
    let ids: std::collections::BTreeSet<&str> = rules
        .iter()
        .map(|rule| rule["identifier"].as_str().expect("identifier"))
        .collect();
    assert_eq!(ids.len(), rules.len(), "rule identifiers must be unique");
    assert!(!ids.contains(""), "rule identifiers must be non-empty");
}
