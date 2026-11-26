use soroban_sdk::testutils::{AuthorizedFunction, AuthorizedInvocation};
use soroban_sdk::Address;

use crate::core::{TestEnv, TestkitError};

type InvokeFn<'a> = Box<dyn Fn(&Address) -> Result<(), soroban_sdk::Error> + 'a>;

struct EntryPointSpec<'a> {
    name: String,
    allowed: Vec<Address>,
    // Optional per-cell error expectations. This lets callers assert the
    // contract returned the right authorization error, not merely any error.
    expected_errors: Vec<(Address, String)>,
    invoke: InvokeFn<'a>,
}

/// A declarative table of who may call what, so that a contract's full
/// caller/entry-point grid is checked by default instead of the four cases
/// someone thought to write by hand.
///
/// Register each privileged entry point with [`AuthMatrix::entry_point`],
/// then call [`AuthMatrix::assert_enforced`] to check that every allowed
/// address succeeds and every other **known actor** is rejected, for every
/// entry point.
///
/// # What counts as a "known actor"
///
/// A *known actor* is any address named in at least one entry point's
/// `allowed` list — the de-duplicated union across every registered entry
/// point, returned by [`AuthMatrix::known_actors`]. The matrix cross-checks
/// each known actor against *every* entry point, not only the one that named
/// it: that is how an actor permitted elsewhere gets caught on a privileged
/// entry point that should have rejected it.
///
/// An address that is never listed on any entry point is **not** a known
/// actor and is never placed in the grid, so a caller that should be rejected
/// must still be named on at least one entry point to be covered.
pub struct AuthMatrix<'a> {
    // Ties the matrix's lifetime to its TestEnv; entry point closures
    // capture their own references into it independently.
    #[allow(dead_code)]
    env: &'a TestEnv,
    entry_points: Vec<EntryPointSpec<'a>>,
    roles: Vec<(Address, String)>,
}

fn csv_escape(value: &str) -> String {
    let quote = char::from(34);
    let escaped = value.replace(quote, &format!("{quote}{quote}"));
    format!("{quote}{escaped}{quote}")
}

impl<'a> AuthMatrix<'a> {
    /// Start an empty matrix against `env`.
    pub fn new(env: &'a TestEnv) -> Self {
        Self {
            env,
            entry_points: Vec::new(),
            roles: Vec::new(),
        }
    }

    /// Attach a human-readable role name to an actor.
    pub fn role(mut self, actor: &Address, name: &str) -> Self {
        self.roles.retain(|(address, _)| address != actor);
        self.roles.push((actor.clone(), name.to_string()));
        self
    }

    /// Attach several role names at once.
    pub fn roles(mut self, actors: &[(Address, &str)]) -> Self {
        for (actor, name) in actors {
            self = self.role(actor, name);
        }
        self
    }

    fn role_name(&self, actor: &Address) -> &str {
        self.roles
            .iter()
            .find(|(address, _)| address == actor)
            .map(|(_, name)| name.as_str())
            .unwrap_or("")
    }

    /// Return the known actors denied by an entry point.
    pub fn denied_addresses(&self, name: &str) -> Vec<Address> {
        let allowed = self
            .entry_points
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| &entry.allowed);
        match allowed {
            Some(allowed) => self
                .known_actors()
                .into_iter()
                .filter(|actor| !allowed.contains(actor))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Export the expected authorization grid as deterministic CSV.
    pub fn to_csv(&self) -> String {
        let mut csv = String::from("entry_point,actor,role,allowed,expected_error\n");
        for entry in &self.entry_points {
            for actor in self.known_actors() {
                let expected_error = entry
                    .expected_errors
                    .iter()
                    .find(|(address, _)| address == &actor)
                    .map(|(_, error)| error.as_str())
                    .unwrap_or("");
                let actor_text = format!("{actor:?}");
                let fields = [
                    entry.name.as_str(),
                    actor_text.as_str(),
                    self.role_name(&actor),
                    if entry.allowed.contains(&actor) {
                        "true"
                    } else {
                        "false"
                    },
                    expected_error,
                ];
                csv.push_str(
                    &fields
                        .iter()
                        .map(|field| csv_escape(field))
                        .collect::<Vec<_>>()
                        .join(","),
                );
                csv.push('\n');
            }
        }
        csv
    }

    /// Alias for to_csv.
    pub fn csv_report(&self) -> String {
        self.to_csv()
    }
    /// Register a privileged entry point: its name (for failure messages),
    /// the addresses permitted to call it, and a closure that attempts the
    /// call as a given caller, returning `Ok(())` if it succeeded and
    /// `Err` if the contract rejected it.
    ///
    /// `invoke` is typically built from a generated client's `try_*`
    /// method with the candidate address mocked as the caller — see
    /// [`AuthMatrix::assert_enforced`]'s example.
    ///
    /// # Duplicates
    ///
    /// Repeating an address in `allowed` is harmless: the matrix de-duplicates
    /// addresses before building its grid, so a duplicated caller is still
    /// checked exactly once per entry point rather than being counted (or
    /// reported) twice.
    ///
    /// Entry-point *names* are not required to be unique. Registering the same
    /// name twice produces two independently-checked sections in the report —
    /// useful when one contract function is expected to behave differently
    /// under two different setups — but the failure message will name both
    /// with the same string, so give them distinct names unless the
    /// duplication is deliberate.
    pub fn entry_point(
        mut self,
        name: &str,
        allowed: &[Address],
        invoke: impl Fn(&Address) -> Result<(), soroban_sdk::Error> + 'a,
    ) -> Self {
        self.entry_points.push(EntryPointSpec {
            name: name.to_string(),
            allowed: allowed.to_vec(),
            expected_errors: Vec::new(),
            invoke: Box::new(invoke),
        });
        self
    }

    /// Validate that a contract actor set is fully represented by the matrix.
    ///
    /// This is useful for contracts with several participant categories, such
    /// as escrow streams (payer, recipient, operator) and recurring contracts
    /// (owner, beneficiary, scheduler). Every supplied actor must be listed in
    /// at least one entry point so it participates in the cross-product.
    pub fn validate_against(&self, actors: &[Address]) -> Result<(), TestkitError> {
        let known = self.known_actors();
        let missing: Vec<String> = actors
            .iter()
            .filter(|actor| !known.contains(actor))
            .map(|actor| format!("{actor:?}"))
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(TestkitError::AssertionFailed(format!(
                "auth matrix is missing {} actor(s): {}",
                missing.len(),
                missing.join(", "),
            )))
        }
    }

    /// Register an entry point with expected error text for selected caller cells.
    ///
    /// The expected text is matched against the `Debug` form of the returned
    /// Soroban error (for example `Error(Contract, #1)`), or against the panic
    /// message if the invocation panicked. This is useful when an escrow stream and a
    /// recurring contract intentionally use different authorization errors.
    pub fn entry_point_with_expected_errors(
        mut self,
        name: &str,
        allowed: &[Address],
        expected_errors: &[(Address, &str)],
        invoke: impl Fn(&Address) -> Result<(), soroban_sdk::Error> + 'a,
    ) -> Self {
        self.entry_points.push(EntryPointSpec {
            name: name.to_string(),
            allowed: allowed.to_vec(),
            expected_errors: expected_errors
                .iter()
                .map(|(address, error)| (address.clone(), (*error).to_string()))
                .collect(),
            invoke: Box::new(invoke),
        });
        self
    }

    /// The matrix's **known actors**: every address named in any entry
    /// point's `allowed` list, de-duplicated and kept in first-seen order.
    ///
    /// These are exactly the addresses [`AuthMatrix::assert_enforced`] places
    /// in its grid; an address that never appears as `allowed` on any entry
    /// point is not a known actor and is not checked.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::auth::AuthMatrix;
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let alice = env.address();
    /// let bob = env.address();
    ///
    /// let matrix = AuthMatrix::new(&env)
    ///     .entry_point("a", &[alice.clone()], |_| Ok(()))
    ///     .entry_point("b", &[alice.clone(), bob.clone()], |_| Ok(()));
    ///
    /// // `alice` is named on both entry points but appears once.
    /// assert_eq!(matrix.known_actors(), vec![alice, bob]);
    /// ```
    pub fn known_actors(&self) -> Vec<Address> {
        let mut known: Vec<Address> = Vec::new();
        for ep in &self.entry_points {
            for addr in &ep.allowed {
                if !known.contains(addr) {
                    known.push(addr.clone());
                }
            }
        }
        known
    }

    /// Reset all authorization state a matrix cell could leave behind: any
    /// authorization entries or mocks set on the environment (including
    /// `mock_all_auths`), and the authorizations recorded by the most recent
    /// invocation (what [`soroban_sdk::Env::auths`] reports).
    ///
    /// [`AuthMatrix::assert_enforced`] and [`AuthMatrix::report`] call this
    /// before and after every cell, so no cell observes or inherits another
    /// cell's authorization state.
    ///
    /// Recorded authorizations can only be cleared when they name a contract
    /// function (the SDK replaces them when a contract frame finishes, and the
    /// matrix opens an empty frame on that already-registered contract rather
    /// than registering anything new). Authorizations recorded solely for
    /// contract creation are left in place.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    /// use soroban_testkit::auth::AuthMatrix;
    ///
    /// let env = TestEnv::new();
    /// let matrix = AuthMatrix::new(&env);
    /// matrix.reset_auth();
    /// assert!(env.env().auths().is_empty());
    /// ```
    pub fn reset_auth(&self) {
        isolate_auth_state(self.env.env());
    }

    /// Run every cell of the matrix and return the results **without
    /// panicking** — the report-only counterpart to
    /// [`AuthMatrix::assert_enforced`].
    ///
    /// Use this when a test needs to inspect individual cells, log the grid,
    /// or decide for itself what counts as a failure. The cells are evaluated
    /// exactly as `assert_enforced` evaluates them (same isolation, same
    /// expected-error matching, same panic handling); the only difference is
    /// that violations are returned in the [`MatrixReport`] instead of being
    /// raised. Call [`MatrixReport::into_result`] to turn the report into the
    /// same [`TestkitError::AssertionFailed`] `assert_enforced` would panic
    /// with.
    ///
    /// # Ordering
    ///
    /// Cells are evaluated and reported in a fixed order: entry points in
    /// registration order, and within each entry point the known actors in
    /// first-seen order (see [`AuthMatrix::known_actors`]). Nothing is sorted
    /// or hashed, so the same matrix always yields byte-identical report text.
    ///
    /// # Edge cases
    ///
    /// A matrix with no entry points, or whose entry points name no allowed
    /// address, has no cells; its report is trivially enforced.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::auth::{AuthMatrix, CellOutcome};
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let owner = env.address();
    /// let attacker = env.address();
    ///
    /// // `guarded` wrongly accepts everyone.
    /// let report = AuthMatrix::new(&env)
    ///     .entry_point("open", &[owner.clone(), attacker.clone()], |_| Ok(()))
    ///     .entry_point("guarded", &[owner.clone()], |_| Ok(()))
    ///     .report();
    ///
    /// assert!(!report.is_enforced());
    /// let violations = report.violations();
    /// assert_eq!(violations.len(), 1);
    /// assert_eq!(violations[0].entry_point, "guarded");
    /// assert_eq!(violations[0].caller, attacker);
    /// assert!(!violations[0].allowed);
    /// assert_eq!(violations[0].observed, CellOutcome::Succeeded);
    /// assert!(report.into_result().is_err());
    /// ```
    pub fn report(&self) -> MatrixReport {
        let known = self.known_actors();
        let mut cells = Vec::with_capacity(self.entry_points.len() * known.len());

        for ep in &self.entry_points {
            for addr in &known {
                let allowed = ep.allowed.contains(addr);
                // Isolate the cell: no mocked, set, or recorded authorization
                // from an earlier cell (or from test setup) may leak into it.
                self.reset_auth();
                // A panic must not prevent later callers from being checked.
                let observed = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    (ep.invoke)(addr)
                })) {
                    Ok(Ok(())) => CellOutcome::Succeeded,
                    Ok(Err(error)) => CellOutcome::Failed(format!("{error:?}")),
                    Err(payload) => CellOutcome::Panicked(panic_summary(payload.as_ref())),
                };
                // Leave a clean slate for the next cell and for the caller.
                self.reset_auth();

                let expected_error = ep
                    .expected_errors
                    .iter()
                    .find(|(actor, _)| actor == addr)
                    .map(|(_, text)| text.clone());
                let matches = if allowed {
                    observed.is_success() && expected_error.is_none()
                } else {
                    !observed.is_success()
                        && expected_error.as_deref().is_none_or(|expected| {
                            observed
                                .error_text()
                                .is_some_and(|text| text.contains(expected))
                        })
                };

                cells.push(CellResult {
                    entry_point: ep.name.clone(),
                    caller: addr.clone(),
                    role: self.role_name(addr).to_string(),
                    allowed,
                    expected_error,
                    observed,
                    matches,
                });
            }
        }

        MatrixReport {
            known_actors: known,
            entry_points: self.entry_points.iter().map(|ep| ep.name.clone()).collect(),
            cells,
        }
    }

    /// For every registered entry point, assert every allowed address
    /// succeeds and every other **known actor** (see [`AuthMatrix`] and
    /// [`AuthMatrix::known_actors`]) fails.
    ///
    /// Known addresses are de-duplicated, so an address listed more than once
    /// — on one entry point or across several — is still checked (and counted)
    /// exactly once per entry point.
    ///
    /// Every cell runs with isolated authorization state (see
    /// [`AuthMatrix::reset_auth`]), and cells run in the deterministic order
    /// documented on [`AuthMatrix::report`]. To inspect results without
    /// panicking, use [`AuthMatrix::report`] instead.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] naming every
    /// violating (entry point, caller) cell — each with whether the caller is
    /// allowed, the expected outcome, and the observed outcome (success, the
    /// returned error, or the panic message) — followed by the full grid
    /// (every cell's expected vs. actual outcome) so a passing cell isn't
    /// mistaken for a gap in coverage.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::auth::AuthMatrix;
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// let owner = env.address();
    ///
    /// // A single-entry-point matrix where the only allowed caller is
    /// // itself: trivially enforced.
    /// AuthMatrix::new(&env)
    ///     .entry_point("noop", &[owner.clone()], move |caller| {
    ///         if *caller == owner {
    ///             Ok(())
    ///         } else {
    ///             Err(soroban_sdk::Error::from_contract_error(1))
    ///         }
    ///     })
    ///     .assert_enforced();
    /// ```
    pub fn assert_enforced(self) {
        if let Err(error) = self.report().into_result() {
            panic!("{error}");
        }
    }
}

/// Clear env-level authorization mocks/entries and the authorizations
/// recorded by the last invocation. See [`AuthMatrix::reset_auth`].
fn isolate_auth_state(env: &soroban_sdk::Env) {
    env.set_auths(&[]);
    // `Env::auths()` reports what the most recent invocation recorded, and the
    // SDK only replaces that snapshot when another contract frame finishes.
    // Open an empty frame on a contract the recorded invocation already
    // touched so the snapshot is replaced without registering anything new.
    let recorded = env.auths();
    if let Some(contract) = recorded
        .iter()
        .find_map(|(_, invocation)| recorded_contract(invocation))
    {
        // A failure here (e.g. the contract's instance was archived) only
        // means the snapshot could not be replaced; it must not abort the run.
        let _ = env.try_as_contract::<(), soroban_sdk::Error>(&contract, || ());
    }
}

fn recorded_contract(invocation: &AuthorizedInvocation) -> Option<Address> {
    match &invocation.function {
        AuthorizedFunction::Contract((contract, _, _)) => Some(contract.clone()),
        _ => invocation
            .sub_invocations
            .iter()
            .find_map(recorded_contract),
    }
}

/// The first line of a panic payload, so a cell's report stays one line even
/// when the panic carries a multi-line host event log.
fn panic_summary(payload: &(dyn std::any::Any + Send)) -> String {
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("non-string panic payload");
    message.lines().next().unwrap_or("").trim().to_string()
}

/// What a matrix cell observed when its entry point was invoked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CellOutcome {
    /// The invocation returned `Ok(())`.
    Succeeded,
    /// The invocation returned `Err`; holds the error's `Debug` text, such as
    /// `Error(Contract, #1)`.
    Failed(String),
    /// The invocation panicked; holds the first line of the panic message.
    Panicked(String),
}

impl CellOutcome {
    /// Whether the invocation succeeded.
    pub fn is_success(&self) -> bool {
        matches!(self, CellOutcome::Succeeded)
    }

    /// The error or panic text, or `None` for a successful invocation. This
    /// is the text an expected error (see
    /// [`AuthMatrix::entry_point_with_expected_errors`]) is matched against.
    pub fn error_text(&self) -> Option<&str> {
        match self {
            CellOutcome::Succeeded => None,
            CellOutcome::Failed(text) | CellOutcome::Panicked(text) => Some(text),
        }
    }
}

impl std::fmt::Display for CellOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CellOutcome::Succeeded => write!(f, "success"),
            CellOutcome::Failed(error) => write!(f, "error {error}"),
            CellOutcome::Panicked(message) => write!(f, "panic {message:?}"),
        }
    }
}

/// The result of one (entry point, caller) cell of an [`AuthMatrix`] run.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CellResult {
    /// The entry point's registered name.
    pub entry_point: String,
    /// The known actor the entry point was invoked as.
    pub caller: Address,
    /// The caller's role name (see [`AuthMatrix::role`]), or empty if none.
    pub role: String,
    /// Whether `caller` is in the entry point's `allowed` list, i.e. whether
    /// the call was expected to succeed.
    pub allowed: bool,
    /// The error text this cell's rejection was expected to contain, if one
    /// was registered with [`AuthMatrix::entry_point_with_expected_errors`].
    pub expected_error: Option<String>,
    /// What the invocation actually did.
    pub observed: CellOutcome,
    /// Whether the observed outcome satisfies the expectation.
    pub matches: bool,
}

impl CellResult {
    /// Whether this cell violates the matrix's expectation.
    pub fn is_violation(&self) -> bool {
        !self.matches
    }

    fn expected_label(&self) -> String {
        match (self.allowed, &self.expected_error) {
            (true, _) => "success".to_string(),
            (false, None) => "rejection".to_string(),
            (false, Some(error)) => format!("rejection with error containing {error:?}"),
        }
    }

    /// One line naming the cell, whether the caller is allowed, and the
    /// expected and observed outcomes.
    fn violation_line(&self) -> String {
        let mut line = format!(
            "entry point {:?}: caller {:?} (role={}): allowed={} expected={} observed={}",
            self.entry_point,
            self.caller,
            self.role,
            self.allowed,
            self.expected_label(),
            self.observed,
        );
        if self.allowed && self.expected_error.is_some() {
            line.push_str(
                " (an expected error is registered for this allowed caller, \
                 so this cell cannot pass)",
            );
        }
        line
    }
}

/// The results of running an [`AuthMatrix`], returned by
/// [`AuthMatrix::report`].
///
/// Cells are stored in evaluation order: entry points in registration order,
/// and within each entry point the known actors in first-seen order. Its
/// `Display` output is the same text [`AuthMatrix::assert_enforced`] panics
/// with when the matrix is violated, or a summary plus the full grid when it
/// is enforced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatrixReport {
    known_actors: Vec<Address>,
    entry_points: Vec<String>,
    cells: Vec<CellResult>,
}

impl MatrixReport {
    /// Render the authorization matrix as a deterministic Markdown table.
    ///
    /// The output is suitable for README files and CI artifacts. One row is
    /// emitted per entry-point/caller cell, preserving registration order.
    pub fn to_markdown(&self) -> String {
        let mut markdown = String::from("| Entry point | Actor | Role | Allowed | Expected error | Observed | Matches |\n|---|---|---|---:|---|---|---:|\n");
        for cell in &self.cells {
            let expected = cell.expected_label().replace('|', "\\\\|");
            let observed = cell.observed.to_string().replace('|', "\\\\|");
            markdown.push_str(&format!(
                "| {} | {:?} | {} | {} | {} | {} | {} |\n",
                cell.entry_point.replace('|', "\\\\|"),
                cell.caller,
                cell.role.replace('|', "\\\\|"),
                cell.allowed,
                expected,
                observed,
                cell.matches
            ));
        }
        markdown
    }

    /// Alias for the Markdown report.
    pub fn markdown_report(&self) -> String {
        self.to_markdown()
    }

    /// Every cell, in evaluation order.
    pub fn cells(&self) -> &[CellResult] {
        &self.cells
    }

    /// The known actors each entry point was checked against, in first-seen
    /// order.
    pub fn known_actors(&self) -> &[Address] {
        &self.known_actors
    }

    /// The cells whose observed outcome did not match the expectation, in
    /// evaluation order.
    pub fn violations(&self) -> Vec<&CellResult> {
        self.cells
            .iter()
            .filter(|cell| cell.is_violation())
            .collect()
    }

    /// Whether every cell matched its expectation.
    pub fn is_enforced(&self) -> bool {
        self.cells.iter().all(|cell| cell.matches)
    }

    /// `Ok(())` if the matrix is enforced, otherwise the
    /// [`TestkitError::AssertionFailed`] that [`AuthMatrix::assert_enforced`]
    /// panics with.
    pub fn into_result(self) -> Result<(), TestkitError> {
        if self.is_enforced() {
            Ok(())
        } else {
            Err(TestkitError::AssertionFailed(self.to_string()))
        }
    }

    fn grid(&self) -> String {
        let mut grid = format!(
            "known actors = union of all entry points' allowed lists ({} address(es)); \
             each is checked against every entry point\n",
            self.known_actors.len()
        );
        let width = self.known_actors.len();
        for (index, name) in self.entry_points.iter().enumerate() {
            // Each section's cells are contiguous; derive `denied` from this
            // section itself so same-named entry points report their own list.
            let section = &self.cells[index * width..(index + 1) * width];
            let denied: Vec<&Address> = section
                .iter()
                .filter(|cell| !cell.allowed)
                .map(|cell| &cell.caller)
                .collect();
            grid.push_str(&format!("  [{name}] denied={denied:?}\n"));
            for cell in section {
                grid.push_str(&format!(
                    "    {:?} (role={}): expected={} actual={}{}\n",
                    cell.caller,
                    cell.role,
                    if cell.allowed { "pass" } else { "reject" },
                    if cell.observed.is_success() {
                        "pass"
                    } else {
                        "reject"
                    },
                    if cell.matches { "" } else { "  <-- MISMATCH" },
                ));
            }
        }
        grid
    }
}

impl std::fmt::Display for MatrixReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let violations = self.violations();
        if violations.is_empty() {
            write!(
                f,
                "auth matrix enforced (all {} cells matched):\nfull grid:\n{}",
                self.cells.len(),
                self.grid()
            )
        } else {
            let lines: Vec<String> = violations
                .iter()
                .map(|cell| cell.violation_line())
                .collect();
            write!(
                f,
                "auth matrix violated ({} of {} cells):\n{}\nfull grid:\n{}",
                violations.len(),
                self.cells.len(),
                lines.join("\n"),
                self.grid()
            )
        }
    }
}

impl TestEnv {
    /// Reset any active authorizations or mocked auths in this environment.
    ///
    /// # Example
    ///
    /// ```
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// env.reset_auth();
    /// ```
    pub fn reset_auth(&self) {
        self.env().set_auths(&[]);
    }

    /// Assert that `f` fails when it runs without the authorization it
    /// requires — the single-call counterpart to [`AuthMatrix`], for a
    /// caller that just needs "this must reject an unauthorized attempt"
    /// without a full grid.
    ///
    /// # Panics
    ///
    /// Panics with a [`TestkitError::AssertionFailed`] if `f` completes
    /// (returns) instead of failing.
    ///
    /// # Example
    ///
    /// ```should_panic
    /// use soroban_testkit::core::TestEnv;
    ///
    /// let env = TestEnv::new();
    /// // A closure that succeeds unconditionally can never satisfy this.
    /// env.assert_requires_auth(|| {});
    /// ```
    pub fn assert_requires_auth(&self, f: impl FnOnce()) {
        self.reset_auth();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        self.reset_auth();
        if result.is_ok() {
            panic!(
                "{}",
                TestkitError::AssertionFailed(
                    "expected the call to fail without authorization, but it succeeded".into()
                )
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{MockAuth, MockAuthInvoke};
    use soroban_sdk::IntoVal;
    use vault::{VaultClient, VaultError};

    fn flatten<T>(
        result: Result<
            Result<T, soroban_sdk::ConversionError>,
            Result<VaultError, soroban_sdk::InvokeError>,
        >,
    ) -> Result<(), soroban_sdk::Error> {
        match result {
            Ok(Ok(_)) => Ok(()),
            _ => Err(soroban_sdk::Error::from_contract_error(0)),
        }
    }

    fn panic_message(err: Box<dyn std::any::Any + Send>) -> String {
        err.downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    }

    #[test]
    fn known_actors_is_the_deduped_union_in_first_seen_order() {
        let env = TestEnv::new();
        let alice = env.address();
        let bob = env.address();
        let carol = env.address();

        let matrix = AuthMatrix::new(&env)
            .entry_point("a", &[alice.clone(), bob.clone()], |_| Ok(()))
            .entry_point("b", &[bob.clone(), carol.clone()], |_| Ok(()));

        // `bob` is named on both entry points but appears once; order follows
        // first appearance.
        assert_eq!(matrix.known_actors(), vec![alice, bob, carol]);
    }

    #[test]
    fn known_actors_ignores_addresses_never_listed() {
        let env = TestEnv::new();
        let listed = env.address();
        let never_listed = env.address();

        let matrix =
            AuthMatrix::new(&env).entry_point("only", std::slice::from_ref(&listed), |_| Ok(()));

        let known = matrix.known_actors();
        assert_eq!(known, vec![listed]);
        assert!(
            !known.contains(&never_listed),
            "an address never listed as allowed is not a known actor"
        );
    }

    #[test]
    fn assert_enforced_report_states_the_known_actor_definition() {
        let env = TestEnv::new();
        let owner = env.address();
        let attacker = env.address();

        // `open` allows both callers (making both "known"), while `guarded`
        // is buggy: it allows everyone. `attacker` is known from `open` and so
        // is cross-checked against `guarded`, where it wrongly succeeds.
        let matrix = AuthMatrix::new(&env)
            .entry_point("open", &[owner.clone(), attacker.clone()], |_| Ok(()))
            .entry_point("guarded", std::slice::from_ref(&owner), |_| Ok(()));

        let err =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| matrix.assert_enforced()))
                .expect_err("guarded allows everyone, so the attacker cell must be caught");
        let message = panic_message(err);

        assert!(
            message.contains("known actors = union of all entry points' allowed lists"),
            "the report must state the definition of a known actor: {message}"
        );
        assert!(
            message.contains(&format!("{attacker:?}")),
            "the report must name the offending known actor: {message}"
        );
    }

    #[test]
    fn assert_enforced_catches_a_real_missing_auth_bug() {
        let env = TestEnv::new();
        let owner = env.address();
        let attacker = env.address();
        let vault_id = env.env().register(vault::Vault, ());
        VaultClient::new(env.env(), &vault_id).initialize(&owner);
        VaultClient::new(env.env(), &vault_id).deposit(&100);

        // `deposit` is legitimately open to anyone, which is what puts
        // `attacker` into the matrix's "known addresses" set. `withdraw`
        // (the buggy entry point) never calls owner.require_auth(), so
        // when we check that only `owner` may withdraw, `attacker` — a
        // known address the matrix now cross-checks against every entry
        // point — incorrectly succeeds too. That's exactly the bug.
        let matrix = AuthMatrix::new(&env)
            .entry_point(
                "deposit",
                &[owner.clone(), attacker.clone()],
                |caller: &Address| {
                    let result = VaultClient::new(env.env(), &vault_id)
                        .mock_auths(&[MockAuth {
                            address: caller,
                            invoke: &MockAuthInvoke {
                                contract: &vault_id,
                                fn_name: "deposit",
                                args: (1_i128,).into_val(env.env()),
                                sub_invokes: &[],
                            },
                        }])
                        .try_deposit(&1);
                    flatten(result)
                },
            )
            .entry_point(
                "withdraw",
                std::slice::from_ref(&owner),
                |caller: &Address| {
                    let result = VaultClient::new(env.env(), &vault_id)
                        .mock_auths(&[MockAuth {
                            address: caller,
                            invoke: &MockAuthInvoke {
                                contract: &vault_id,
                                fn_name: "withdraw",
                                args: (10_i128,).into_val(env.env()),
                                sub_invokes: &[],
                            },
                        }])
                        .try_withdraw(&10);
                    flatten(result)
                },
            );

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            matrix.assert_enforced();
        }));

        let err = result.expect_err("expected assert_enforced to catch the missing auth check");
        let message = err
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default();
        assert!(
            message.contains("withdraw"),
            "failure message should name the entry point: {message}"
        );
        assert!(
            message.contains(&format!("{attacker:?}")),
            "failure message should name the offending caller: {message}"
        );
    }

    #[test]
    fn assert_enforced_passes_once_the_bug_is_fixed() {
        let env = TestEnv::new();
        let owner = env.address();
        let other = env.address();
        let vault_id = env.env().register(vault::Vault, ());
        VaultClient::new(env.env(), &vault_id).initialize(&owner);
        VaultClient::new(env.env(), &vault_id).deposit(&100);

        // Same shape as the buggy-case test (two entry points, so `other`
        // is a known address cross-checked against withdraw_checked), but
        // against the fixed entry point: `other` is correctly rejected.
        AuthMatrix::new(&env)
            .entry_point(
                "deposit",
                &[owner.clone(), other.clone()],
                |caller: &Address| {
                    let result = VaultClient::new(env.env(), &vault_id)
                        .mock_auths(&[MockAuth {
                            address: caller,
                            invoke: &MockAuthInvoke {
                                contract: &vault_id,
                                fn_name: "deposit",
                                args: (1_i128,).into_val(env.env()),
                                sub_invokes: &[],
                            },
                        }])
                        .try_deposit(&1);
                    flatten(result)
                },
            )
            .entry_point(
                "withdraw_checked",
                std::slice::from_ref(&owner),
                |caller: &Address| {
                    let result = VaultClient::new(env.env(), &vault_id)
                        .mock_auths(&[MockAuth {
                            address: caller,
                            invoke: &MockAuthInvoke {
                                contract: &vault_id,
                                fn_name: "withdraw_checked",
                                args: (10_i128,).into_val(env.env()),
                                sub_invokes: &[],
                            },
                        }])
                        .try_withdraw_checked(&10);
                    flatten(result)
                },
            )
            .assert_enforced();
    }

    #[test]
    fn a_duplicated_allowed_address_is_checked_once_not_twice() {
        let env = TestEnv::new();
        let alice = env.address();

        // The same actor listed twice in one `allowed` list must still count
        // as a single known address: the report should cover one cell, not two.
        let matrix =
            AuthMatrix::new(&env).entry_point("dup", &[alice.clone(), alice.clone()], |_| {
                Err(soroban_sdk::Error::from_contract_error(1))
            });

        let err =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| matrix.assert_enforced()))
                .expect_err("alice is expected to pass but is rejected");
        let message = panic_message(err);

        assert!(
            message.contains("of 1 cells"),
            "a duplicated actor must be counted once: {message}"
        );
    }

    #[test]
    fn duplicate_entry_point_names_produce_independent_sections() {
        let env = TestEnv::new();
        let alice = env.address();

        // Deliberately reusing a name: both sections are checked separately,
        // one violating and one passing, and both appear in the report.
        let matrix = AuthMatrix::new(&env)
            .entry_point("deposit", std::slice::from_ref(&alice), |_| {
                Err(soroban_sdk::Error::from_contract_error(1))
            })
            .entry_point("deposit", std::slice::from_ref(&alice), |_| Ok(()));

        let err =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| matrix.assert_enforced()))
                .expect_err("the first `deposit` rejects alice and must be flagged");
        let message = panic_message(err);

        assert_eq!(
            message.matches("[deposit]").count(),
            2,
            "two entry points sharing a name must both be reported: {message}"
        );
        assert!(
            message.contains("of 2 cells"),
            "each same-named entry point still gets its own cells: {message}"
        );
    }

    #[test]
    fn assert_requires_auth_passes_when_call_panics() {
        let env = TestEnv::new();
        env.assert_requires_auth(|| panic!("simulated auth failure"));
    }

    #[test]
    #[should_panic(expected = "expected the call to fail without authorization")]
    fn assert_requires_auth_panics_when_call_succeeds() {
        let env = TestEnv::new();
        env.assert_requires_auth(|| {});
    }
    #[test]
    fn reports_include_roles_denied_addresses_and_csv() {
        let env = TestEnv::new();
        let admin = env.address();
        let user = env.address();
        let matrix = AuthMatrix::new(&env)
            .role(&admin, "admin")
            .role(&user, "user")
            .entry_point("configure", std::slice::from_ref(&admin), |_| Ok(()))
            // `user` must be named on some entry point to be a known actor.
            .entry_point("read", &[admin.clone(), user.clone()], |_| Ok(()));
        assert_eq!(matrix.denied_addresses("configure"), vec![user.clone()]);
        let csv = matrix.to_csv();
        assert!(csv.starts_with("entry_point,actor,role,allowed,expected_error"));
        assert!(csv.contains("admin"));
        assert!(csv.contains("false"));
    }

    #[test]
    fn a_panicking_cell_does_not_skip_remaining_cells() {
        let env = TestEnv::new();
        let first = env.address();
        let second = env.address();
        let calls = std::cell::Cell::new(0u32);
        let matrix = AuthMatrix::new(&env).entry_point(
            "panic_then_continue",
            &[first.clone(), second.clone()],
            |caller| {
                calls.set(calls.get() + 1);
                if *caller == first {
                    panic!("simulated contract panic");
                }
                Ok(())
            },
        );

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            matrix.assert_enforced();
        }));
        assert!(result.is_err());
        assert_eq!(calls.get(), 2, "all matrix cells must be attempted");
    }

    #[test]
    fn expected_error_text_is_checked_per_caller_cell() {
        let env = TestEnv::new();
        let allowed = env.address();
        let denied = env.address();
        let allowed_caller = allowed.clone();
        AuthMatrix::new(&env)
            .entry_point_with_expected_errors(
                "role_guard",
                std::slice::from_ref(&allowed),
                &[(denied.clone(), "Contract")],
                move |caller| {
                    if *caller == allowed_caller {
                        Ok(())
                    } else {
                        Err(soroban_sdk::Error::from_contract_error(1))
                    }
                },
            )
            .assert_enforced();
    }

    #[test]
    fn recorded_auths_from_one_cell_do_not_leak_into_the_next() {
        let env = TestEnv::new();
        let owner = env.address();
        let other = env.address();
        let vault_id = env.env().register(vault::Vault, ());
        VaultClient::new(env.env(), &vault_id).initialize(&owner);
        VaultClient::new(env.env(), &vault_id).deposit(&100);

        // The owner's cell records an authorization; the next cell (`other`)
        // never reaches the contract. Without isolation, `env.auths()` in the
        // second cell still reports the owner's authorization from the first.
        let leaked = std::cell::RefCell::new(Vec::new());
        AuthMatrix::new(&env)
            .entry_point(
                "withdraw_checked",
                &[owner.clone(), other.clone()],
                |caller| {
                    if !env.env().auths().is_empty() {
                        leaked.borrow_mut().push(caller.clone());
                    }
                    if *caller == owner {
                        flatten(
                            VaultClient::new(env.env(), &vault_id)
                                .mock_all_auths()
                                .try_withdraw_checked(&1),
                        )
                    } else {
                        Ok(())
                    }
                },
            )
            .assert_enforced();

        assert!(
            leaked.borrow().is_empty(),
            "cells observed authorizations recorded by an earlier cell: {:?}",
            leaked.borrow()
        );
        assert!(
            env.env().auths().is_empty(),
            "recorded authorizations must not outlive the matrix run"
        );
    }

    #[test]
    fn env_level_mock_all_auths_in_one_cell_does_not_authorize_the_next() {
        let env = TestEnv::new();
        let owner = env.address();
        let attacker = env.address();
        let vault_id = env.env().register(vault::Vault, ());
        VaultClient::new(env.env(), &vault_id).initialize(&owner);
        VaultClient::new(env.env(), &vault_id).deposit(&100);

        // `attacker` is known via `deposit`. On `withdraw_checked` only the
        // owner's cell mocks auths (env-wide); the attacker's cell does not, so
        // it must be rejected rather than inherit the owner's mock.
        AuthMatrix::new(&env)
            .entry_point("deposit", &[owner.clone(), attacker.clone()], |_| {
                flatten(VaultClient::new(env.env(), &vault_id).try_deposit(&1))
            })
            .entry_point("withdraw_checked", std::slice::from_ref(&owner), |caller| {
                if *caller == owner {
                    env.env().mock_all_auths();
                }
                flatten(VaultClient::new(env.env(), &vault_id).try_withdraw_checked(&1))
            })
            .assert_enforced();
    }

    fn reject(_: &Address) -> Result<(), soroban_sdk::Error> {
        Err(soroban_sdk::Error::from_contract_error(1))
    }

    /// The violation lines of a report: everything before the full grid.
    fn violation_lines(message: &str) -> Vec<String> {
        message
            .split("\nfull grid:\n")
            .next()
            .unwrap_or_default()
            .lines()
            .skip(1)
            .map(str::to_string)
            .collect()
    }

    // ---- #162: report-only mode ----

    #[test]
    fn report_returns_results_for_an_enforced_matrix_without_panicking() {
        let env = TestEnv::new();
        let owner = env.address();
        let other = env.address();
        let owner_for_guard = owner.clone();

        let report = AuthMatrix::new(&env)
            .entry_point("open", &[owner.clone(), other.clone()], |_| Ok(()))
            .entry_point("guarded", std::slice::from_ref(&owner), move |caller| {
                if *caller == owner_for_guard {
                    Ok(())
                } else {
                    reject(caller)
                }
            })
            .report();

        assert!(report.is_enforced());
        assert!(report.violations().is_empty());
        assert_eq!(report.known_actors(), &[owner.clone(), other.clone()]);
        assert_eq!(report.cells().len(), 4);
        let guarded_other = &report.cells()[3];
        assert_eq!(guarded_other.entry_point, "guarded");
        assert_eq!(guarded_other.caller, other);
        assert!(!guarded_other.allowed);
        assert_eq!(
            guarded_other.observed,
            CellOutcome::Failed("Error(Contract, #1)".to_string())
        );
        assert!(guarded_other.matches);
        let text = report.to_string();
        assert!(
            text.starts_with("auth matrix enforced (all 4 cells matched)"),
            "{text}"
        );
        assert!(report.into_result().is_ok());
    }

    #[test]
    fn report_returns_violations_that_match_assert_enforced() {
        let env = TestEnv::new();
        let owner = env.address();
        let attacker = env.address();
        let build = || {
            AuthMatrix::new(&env)
                .entry_point("open", &[owner.clone(), attacker.clone()], |_| Ok(()))
                .entry_point("guarded", std::slice::from_ref(&owner), |_| Ok(()))
        };

        let report = build().report();
        assert!(!report.is_enforced());
        let violations = report.violations();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].entry_point, "guarded");
        assert_eq!(violations[0].caller, attacker);
        assert_eq!(violations[0].observed, CellOutcome::Succeeded);

        let err = report
            .clone()
            .into_result()
            .expect_err("matrix is violated");
        assert!(matches!(err, TestkitError::AssertionFailed(_)));

        let panicked =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| build().assert_enforced()))
                .expect_err("assert_enforced must panic on the same matrix");
        assert_eq!(panic_message(panicked), err.to_string());
    }

    #[test]
    fn report_of_an_empty_matrix_has_no_cells() {
        let env = TestEnv::new();
        let report = AuthMatrix::new(&env).report();
        assert!(report.cells().is_empty());
        assert!(report.known_actors().is_empty());
        assert!(report.is_enforced());

        // Entry points that name no allowed address produce no known actors.
        let report = AuthMatrix::new(&env)
            .entry_point("nobody", &[], |_| Ok(()))
            .report();
        assert!(report.cells().is_empty());
        assert!(report.to_string().contains("[nobody] denied=[]"));
    }

    #[test]
    fn report_records_panicking_cells_and_keeps_going() {
        let env = TestEnv::new();
        let first = env.address();
        let second = env.address();
        let panicking = first.clone();

        let matrix = AuthMatrix::new(&env).entry_point(
            "boom",
            &[first.clone(), second.clone()],
            move |caller| {
                if *caller == panicking {
                    panic!("simulated contract panic\nwith a second line");
                }
                Ok(())
            },
        );

        let report = matrix.report();
        assert_eq!(
            report.cells()[0].observed,
            CellOutcome::Panicked("simulated contract panic".to_string())
        );
        assert_eq!(report.cells()[1].observed, CellOutcome::Succeeded);
        assert_eq!(report.violations().len(), 1);
        // Reporting is repeatable on the same matrix.
        assert_eq!(matrix.report(), report);
    }

    // ---- #157: allowed and observed outcomes in every failed cell ----

    #[test]
    fn every_failed_cell_states_allowed_expected_and_observed_outcomes() {
        let env = TestEnv::new();
        let owner = env.address();
        let attacker = env.address();
        let owner_for_panic = owner.clone();
        let owner_for_typed = owner.clone();

        let report = AuthMatrix::new(&env)
            .role(&owner, "owner")
            .role(&attacker, "attacker")
            // owner: allowed but rejected. attacker: denied but succeeds.
            .entry_point("inverted", std::slice::from_ref(&owner), move |caller| {
                if *caller == owner_for_panic {
                    reject(caller)
                } else {
                    Ok(())
                }
            })
            // attacker: rejected, but with the wrong error.
            .entry_point_with_expected_errors(
                "typed",
                std::slice::from_ref(&owner),
                &[(attacker.clone(), "Error(Auth")],
                move |caller| {
                    if *caller == owner_for_typed {
                        Ok(())
                    } else {
                        reject(caller)
                    }
                },
            )
            // both: panic.
            .entry_point("panics", &[owner.clone(), attacker.clone()], |_| {
                panic!("boom")
            })
            .report();

        let message = report.to_string();
        let lines = violation_lines(&message);
        assert_eq!(lines.len(), 5, "{message}");
        for line in &lines {
            assert!(line.contains("allowed="), "missing allowed: {line}");
            assert!(line.contains("expected="), "missing expected: {line}");
            assert!(line.contains("observed="), "missing observed: {line}");
        }
        let owner_dbg = format!("{owner:?}");
        let attacker_dbg = format!("{attacker:?}");
        assert_eq!(
            lines[0],
            format!(
                "entry point \"inverted\": caller {owner_dbg} (role=owner): allowed=true \
                 expected=success observed=error Error(Contract, #1)"
            )
        );
        assert_eq!(
            lines[1],
            format!(
                "entry point \"inverted\": caller {attacker_dbg} (role=attacker): allowed=false \
                 expected=rejection observed=success"
            )
        );
        assert_eq!(
            lines[2],
            format!(
                "entry point \"typed\": caller {attacker_dbg} (role=attacker): allowed=false \
                 expected=rejection with error containing \"Error(Auth\" \
                 observed=error Error(Contract, #1)"
            )
        );
        assert!(lines[3].contains("observed=panic \"boom\""), "{}", lines[3]);
        assert!(lines[4].contains("observed=panic \"boom\""), "{}", lines[4]);
    }

    #[test]
    fn an_expected_error_on_an_allowed_caller_explains_why_the_cell_fails() {
        let env = TestEnv::new();
        let owner = env.address();
        let report = AuthMatrix::new(&env)
            .entry_point_with_expected_errors(
                "misconfigured",
                std::slice::from_ref(&owner),
                &[(owner.clone(), "Contract")],
                |_| Ok(()),
            )
            .report();
        let lines = violation_lines(&report.to_string());
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("allowed=true expected=success observed=success"),
            "{}",
            lines[0]
        );
        assert!(
            lines[0].contains("an expected error is registered for this allowed caller"),
            "{}",
            lines[0]
        );
    }

    // ---- #156: deterministic output ordering ----

    #[test]
    fn cells_and_violations_follow_registration_order() {
        let env = TestEnv::new();
        let zed = env.address();
        let amy = env.address();

        // Deliberately non-alphabetical names and actor order: output must
        // follow registration / first-seen order, not any sorting.
        let report = AuthMatrix::new(&env)
            .entry_point("zeta", &[zed.clone(), amy.clone()], reject)
            .entry_point("alpha", std::slice::from_ref(&amy), reject)
            .report();

        let order: Vec<(&str, &Address)> = report
            .cells()
            .iter()
            .map(|cell| (cell.entry_point.as_str(), &cell.caller))
            .collect();
        assert_eq!(
            order,
            vec![
                ("zeta", &zed),
                ("zeta", &amy),
                ("alpha", &zed),
                ("alpha", &amy)
            ]
        );

        let message = report.to_string();
        let lines = violation_lines(&message);
        assert_eq!(lines.len(), 3, "{message}");
        assert!(lines[0].starts_with(&format!("entry point \"zeta\": caller {zed:?}")));
        assert!(lines[1].starts_with(&format!("entry point \"zeta\": caller {amy:?}")));
        assert!(lines[2].starts_with(&format!("entry point \"alpha\": caller {amy:?}")));
        let zeta = message.find("[zeta]").expect("zeta section");
        let alpha = message.find("[alpha]").expect("alpha section");
        assert!(zeta < alpha, "sections must follow registration order");
    }

    #[test]
    fn identical_matrices_produce_identical_reports() {
        let run = || {
            let env = TestEnv::with_seed(7);
            let a = env.address();
            let b = env.address();
            let c = env.address();
            let report = AuthMatrix::new(&env)
                .role(&b, "user")
                .role(&a, "admin")
                .entry_point("read", &[c.clone(), b.clone(), a.clone()], |_| Ok(()))
                // buggy: everyone may write
                .entry_point("write", std::slice::from_ref(&a), |_| Ok(()))
                .report();
            report.to_string()
        };
        let first = run();
        assert!(
            first.contains("auth matrix violated (2 of 6 cells)"),
            "{first}"
        );
        for _ in 0..3 {
            assert_eq!(run(), first);
        }
    }

    #[test]
    fn same_named_entry_points_report_their_own_denied_lists() {
        let env = TestEnv::new();
        let alice = env.address();
        let bob = env.address();

        let report = AuthMatrix::new(&env)
            .entry_point("deposit", std::slice::from_ref(&alice), |_| Ok(()))
            .entry_point("deposit", &[alice.clone(), bob.clone()], |_| Ok(()))
            .report();
        let message = report.to_string();

        assert!(
            message.contains(&format!("  [deposit] denied=[{bob:?}]\n")),
            "{message}"
        );
        assert!(
            message.contains("  [deposit] denied=[]\n"),
            "the second section allows everyone and must say so: {message}"
        );
    }
}
