//! Sandbox runner trait (WI-0205).

use async_trait::async_trait;

use super::error::SandboxError;
use super::input::SandboxInput;
use super::output::SandboxOutput;
use super::profile::SandboxSecurityProfile;

/// Execution boundary for running an untrusted parser inside a hardened sandbox.
#[async_trait]
pub trait SandboxRunner: Send + Sync {
    /// Executes the parser sandbox under the given security profile with the scoped input.
    ///
    /// # Invariants
    /// - Operates strictly on the provided `SandboxInput` (single object handoff)
    /// - Enforces all limits in `SandboxSecurityProfile`
    /// - Fails closed on any error, returning typed `SandboxError`
    /// - Never writes directly to application databases
    async fn run(
        &self,
        profile: &SandboxSecurityProfile,
        input: &SandboxInput,
    ) -> Result<SandboxOutput, SandboxError>;
}
