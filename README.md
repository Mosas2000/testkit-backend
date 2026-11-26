# soroban-testkit

**The testing crate you would have written yourself, on the third contract.**

Testing infrastructure for Soroban contracts: property-test generators for
money math, an event-assertion API, ledger time and TTL-expiry control,
token test doubles, and a coverage-aware CLI.

`soroban-sdk` ships `testutils`, which is adequate for basic unit tests. It
is not adequate for testing contracts that hold money. Every serious
Soroban contract repo independently rebuilds some subset of:

- Advancing ledger time correctly, including the interaction between
  `timestamp` and `sequence`
- Asserting on emitted events without hand-decoding `Val` topics
- Generating adversarial `i128` values that actually find overflow bugs
- Deploying and funding a Stellar Asset Contract token double for transfer
  tests
- Proving that every privileged entry point rejects unauthorized callers
- Simulating TTL expiry

`soroban-testkit` is that shared layer, as a dev-dependency crate plus a
small CLI.

## Example

A small escrow contract, tested end to end: mint a token, release it to
the seller, and check the event, the balances, and that no value was
created or destroyed along the way.

```
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};
use soroban_testkit::prelude::*;

#[contract]
struct Escrow;

#[contractimpl]
impl Escrow {
    pub fn release(env: Env, token: Address, from: Address, to: Address, amount: i128) {
        from.require_auth();
        soroban_sdk::token::TokenClient::new(&env, &token)
            .transfer(&from, soroban_sdk::MuxedAddress::from(to), &amount);
        #[allow(deprecated)]
        env.events().publish((symbol_short!("release"),), amount);
    }
}

# fn main() {
let env = TestEnv::new();
let token = env.token();
let buyer = env.address();
let seller = env.address();
token.mint(&buyer, 100);

let escrow_id = env.env().register(Escrow, ());
let client = EscrowClient::new(env.env(), &escrow_id);

env.env().mock_all_auths();
let (_, events) = env.events_during(|| {
    client.release(&token.address(), &buyer, &seller, &1_000_000_000);
});
events
    .from(&escrow_id)
    .assert_emitted(symbol_short!("release"));

// Each of these balance queries is itself a top-level call, so check
// them after reading events — see EventLog's note on scope.
token.assert_balance(&buyer, 0);
token.assert_balance(&seller, 1_000_000_000);

Conservation {
    deposited: 1_000_000_000,
    withdrawn: 1_000_000_000,
    refunded: 0,
    remaining: 0,
}
.assert_holds();
# }
```

## CLI

A companion binary, `soroban-testkit-cli` (installs as `soroban-testkit`),
for things that don't belong in a dev-dependency:

```sh
# Coverage for the WASM target (wraps cargo-llvm-cov, which needs no
# Soroban-specific flags since contract tests run natively).
soroban-testkit coverage --format html --open

# Machine-readable coverage report
soroban-testkit coverage --format json --output coverage.json

# Empirically find how many recipients a batch operation can handle
# before it exceeds mainnet resource limits. Build successfully first so
# a failed rebuild cannot leave limits measuring an older WASM artifact.
cargo build -p my_contract --target wasm32v1-none --release &&
soroban-testkit limits --contract target/wasm32v1-none/release/my_contract.wasm \
  --fn batch_payout --ramp recipients

# Static checks: missing require_auth, unchecked i128 arithmetic,
# storage reads with no TTL bump, ignored token-transfer results, and
# signed amount parameters with no positive-value validation.
soroban-testkit audit ./src --strict

# Print only the audit summary without individual finding details.
soroban-testkit audit ./src --summary-only

# Disable ANSI color escape codes (also honors NO_COLOR env var).
soroban-testkit audit ./src --no-color

# Wrap text findings to a specified character width (e.g. 80 columns).
soroban-testkit audit ./src --width 80

# Use an explicit project config instead of automatic discovery.
soroban-testkit audit ./src --config ./config/audit.toml

# Emit GitHub Actions workflow annotations on stderr (stdout stays machine-readable).
soroban-testkit audit ./src --format json --annotations

# Stable machine-readable reports for automation and GitHub code scanning.
soroban-testkit audit ./src --format json
soroban-testkit audit ./src --format sarif > audit.sarif
```

`limits` ramps numeric and `Bytes` parameters directly, or ramps a `Vec<T>`
by element count. `--ramp` must exactly match an input name in the selected
function's contract ABI. An unknown name is rejected before probes run or
reports are written, with the available inputs listed for recovery.
Use repeated `--arg NAME=VALUE` options for non-ramped scalar values;
`Bytes` overrides use `0x`-prefixed hex. The command refines the first
failing ramp value with binary search.
Every ramp attempt runs in its own subprocess: a real `.wasm` contract
that exceeds resource limits can abort the process outright rather than
return an error, and isolating each attempt is the only safe way to probe
past that boundary. Failed probes are classified with a stable category
(`exit-failure`, `timed-out`, `abort`, or `spawn-failure`), and the same
summary renders both the terminal output and the `--export` JSON, so the
two formats cannot disagree about the discovered boundary. Ledger
read/write counts and transaction size aren't reported (they come from a
network-side simulated footprint this crate doesn't produce); instructions
and memory, measured locally, are.

Each probe is killed after `--probe-timeout` seconds (default 30) and
recorded as `timed-out`, with the ramp value and timeout in its report. Add
`--timeout <SECONDS>` to bound the whole run: probes wait at most for the
time left, and a run that hits the deadline fails with the best value
verified so far instead of reporting an unconfirmed boundary. `--progress`
prints one line per probe to stderr (phase, value, outcome, best so far,
elapsed time) without changing stdout or the `--export` JSON. Next to the
maximum success, the summary reports the last failing probe, with its
category and first stderr line, as `last_failed_probe` in JSON.

```sh
soroban-testkit limits --contract target/wasm32v1-none/release/my_contract.wasm \
  --fn batch_payout --ramp recipients --probe-timeout 10 --timeout 300 --progress
```

Probe execution uses the already-built `soroban-testkit` executable directly,
not `cargo run` or a throwaway Cargo project. Each probe child is killed and
reaped on timeout; an early ordinary error/return also invokes a cleanup
guard. This guard cannot run if the operating system forcibly kills the
parent process. Contract paths are passed as single OS arguments; copyable
reproduction instructions shell-quote paths containing spaces or quotes.

`audit` accepts three scan roots: a crate directory (walked recursively for
`.rs` files), a single `.rs` file, or `-` to read Rust source from stdin.
While walking a directory it skips `target/`, `vendor/`, `node_modules/`,
and hidden directories such as `.git/` and `.github/`, along with any
directories passed via repeatable `--exclude <DIR>` flags or the `exclude = [...]`
configuration key (exact relative directory paths; glob matching is not
supported), keeping build output, generated source, and dependency trees out
of recursive scans. A missing path is an actionable
error rather than an empty "no findings" run. An explicitly selected excluded
directory or single file is still scanned. Empty, whitespace-only, and
comment-only Rust files are valid inputs with no findings. Raw identifiers
such as `r#amount` are checked the same way as their ordinary spellings.

Run `audit` from a Cargo workspace root (`soroban-testkit audit .`) to scan
every member crate in one pass. The same walk applies, so the exclusions above
still hold. Running from a member crate resolves the same workspace root, so
paths stay workspace-relative.

`--strict` additionally exits non-zero when any finding is reported. Inputs
that fail to read or parse always exit non-zero, with or without `--strict`.

Findings use paths relative to the Cargo workspace root (or the repository
root or crate root when there is no workspace). Every path the command
compares or prints is normalized first — symlinks and `.`/`..` components
resolved — so one file always reports under a single spelling however its
scan root was spelled on the command line. Findings are then reported in
one deterministic order — file, then line, then rule, then message — so a
report diff always reflects a real change rather than scan order. For
multi-line findings, source ranges are reported additively: text output keeps
the `file:line:` prefix and appends `:-<end_line>:` (e.g. `src/lib.rs:3:-8:`),
JSON reports add an `end_line` field, and SARIF output sets `endLine` on the
location region. Single-line findings report start positions as before. Line
numbers are 1-based and end-inclusive. The
nearest `.soroban-testkit.toml` or `soroban-testkit.toml` between the
scanned source directory and that root supplies rule configuration; the
dotted name takes precedence in the same directory. Single-file scans start
config discovery at the file's parent, and stdin scans start at the current
directory.

Project-level rule configuration is enabled by default: all rules start
enabled at the severity in the central registry, and a config only overrides
what it names. `audit rules --format json` reports each rule's `id`,
`defaultEnabled`, `defaultSeverity` and documented limitations, and
`audit explain <rule>` prints its default. `--config PATH` bypasses discovery
and loads exactly that file; a missing path is an actionable error.

Every output format carries the stable rule identifier (`rule` in text and
JSON, `rule_id` in JSON, `ruleId` and `properties.stableRuleId` in SARIF, and
the annotation `title`), so baselines and dashboards can key on it across
releases. Rule ids are stable; the prose description is not.

`--baseline baseline.json` resolves the baseline file from the current
directory, while its `file` entries are workspace-relative, so one baseline
works from member crates too. Absolute entries are also accepted.

Unreadable files, directory traversal failures, and Rust parse errors are
reported separately on stderr with the affected path (and line/column for
syntax errors). These are *parse warnings*, not findings: a warning means
the input was skipped rather than scanned. JSON reports list them under
`summary.parser_limitations`, separate from `findings`, and the number of
skipped files is in `summary.skipped_file_count`. Skipped inputs never count
toward `finding_count` and never trigger `--strict`. When any file is
skipped, stderr also prints a `audit: summary:` line with the scanned and
skipped counts.
The scan continues through other files and writes their findings in the
requested format, then exits non-zero to signal an incomplete audit even
without `--strict`. Fix these warnings before treating an empty report as a
clean scan. JSON reports escape control characters in file names and
diagnostic text.

**Audit limitation:** the linter inspects written Rust source only. It does
not expand procedural macros (including Soroban contract macros) or
`macro_rules!`, so generated entry points and generated bodies may go
unexamined. A clean report does not certify generated code. The limitation
is included in text, JSON (`summary.limitations`) and SARIF
(`runs[].properties.limitations`) results. Inspect expanded source
separately when generated code matters.

### Rule Confidence & Known Limitations

`soroban-testkit audit` is a heuristic linter, not a formal verification or security auditing tool. Rules have varying precision depending on their analysis technique.

#### Confidence Scale
- **High**: Direct syntactic match for a specific API call or unambiguous pattern. Minimal false positives within evaluated AST.
- **Medium**: AST-based pattern matching over types and expressions within a single function. Limited by lack of cross-function, cross-crate, or macro expansion analysis.
- **Low**: String or token pattern heuristic (substring search, identifier naming convention). Prone to false positives and negatives due to lack of type and execution flow analysis.
- **Not Assessed**: The rule's precision and edge cases have not been formally evaluated.

#### Rule Registry
| Rule | Severity | Confidence | Primary Known Limitations |
| --- | --- | --- | --- |
| `missing-require-auth` | warning | medium | Cannot inspect macro expansions; auth validation in private helper functions without recognized auth stems is missed; no cross-file call graph analysis. |
| `unchecked-i128-arithmetic` | warning | medium | Only checks `i128` bindings declared as function parameters; does not track local `let` bindings or struct fields; cannot inspect macros. |
| `missing-ttl-bump` | warning | low | Heuristic token match on body source; does not track key equivalence between read and extend_ttl; misses TTL bumps in helper functions; ignores instance storage. |
| `broad-mock-all-auths` | warning | high | Cannot detect calls generated through external test macros or helper functions outside test modules. |
| `ignored-token-transfer-result` | warning | medium | Syntactic heuristic matching transfer methods without type resolution; binding to an unused variable (`let _ = ...`) bypasses detection. |
| `missing-positive-amount-validation` | warning | low | Only inspects parameters named `*amount*`; does not evaluate branching or execution flow; helper validation missed. |
| `unchecked-timestamp-arithmetic` | warning | low | Substring match on `timestamp`; flags any arithmetic in a function mentioning timestamp even on unrelated counters; no semantic type checking. |

To inspect metadata, confidence, and limitations for any rule from the CLI, run:
```sh
soroban-testkit audit explain <rule>
soroban-testkit audit rules
soroban-testkit audit rules --format json
```

## Status

This crate is under active development. See `BUILD_SPEC.md` for the build
plan and module boundaries, and [`ARCHITECTURE.md`](ARCHITECTURE.md) for a
contributor-facing map of the workspace and how its modules fit together.

CI enforces the guarantees that keep this documentation honest: every Rust
example above is compiled and run as a doctest against the public API,
rustdoc warnings fail the build, the test suite runs with network access
removed, and the crates.io `repository` metadata is checked against the
canonical repository URL.

## Documentation

- [`CHANGELOG.md`](CHANGELOG.md) — user-facing release notes for each
  version of both workspace crates.
- [`API_STABILITY.md`](API_STABILITY.md) — the semver/API stability policy
  for the `0.x` releases: what a version bump means and what you may rely
  on.
- [`COMPATIBILITY.md`](COMPATIBILITY.md) — which `soroban-sdk` and Stellar
  protocol versions each release targets.
- [`MIGRATION.md`](MIGRATION.md) — upgrade notes for each minor release,
  with before/after code for every breaking change.
- [`RELEASING.md`](RELEASING.md) — the release checklist for
  `soroban-testkit` and `soroban-testkit-cli`.
- [`BUILD_SPEC.md`](BUILD_SPEC.md) — the build plan and module boundaries.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — a contributor-facing map of the
  workspace.
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) — what the common
  `soroban-testkit` failure codes mean and how to fix them.

## Prior art

[`soroban-fork`](https://crates.io/crates/soroban-fork) does lazy
mainnet/testnet forking for tests. That is a different problem;
`soroban-testkit` does not attempt it.

## License

Apache-2.0
add validation coverage for the recurring contract
add validation coverage for the batch payout auth model

add a line-count and coverage comparison to validation

add benchmark tracking for TestEnv construction

## Nested sub-invoke authorization

A top-level authorization assertion does not automatically authorize the contract calls it triggers. When an entry point invokes another contract, register the nested invocation in the mocked authorization tree as well:

1. Add a `MockAuthInvoke` for the top-level call.
2. Add each nested contract, function name, argument tuple, and its own `sub_invokes` list.
3. Assert the complete tree for both the permitted and denied actor cells.
4. Reset mocked authorizations between matrix cells so one successful invocation cannot satisfy a later nested call.

For escrow streams and recurring contracts, keep the payer, recipient, operator, scheduler, and beneficiary addresses as named actors in the matrix. Then use `AuthMatrix::denied_addresses` to verify that every role excluded from a privileged entry point is still exercised. This catches a common false positive where the outer call is authorized while a nested transfer or schedule update is not.
