//! Deterministic test double sandbox runner (WI-0205).

use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use w014_domain::LocatorVersion;

use super::error::SandboxError;
use super::input::SandboxInput;
use super::output::{SANDBOX_PROTOCOL_VERSION, SandboxOutput, SandboxStatus};
use super::profile::SandboxSecurityProfile;
use super::traits::SandboxRunner;

/// Deterministic behaviors for the mock sandbox runner.
#[derive(Debug, Clone, PartialEq)]
pub enum MockSandboxBehavior {
    /// Automatically construct valid matching SandboxOutput.
    AutomaticSuccess,
    /// Return the exact provided SandboxOutput.
    Success(SandboxOutput),
    /// Simulate a wall-clock timeout.
    Timeout(u64),
    /// Simulate an Out-Of-Memory termination.
    OutOfMemory,
    /// Simulate a resource ceiling limit violation (e.g. PID or TMPFS).
    ResourceViolation(String),
    /// Simulate a process crash.
    Crash {
        exit_code: Option<i32>,
        stderr: String,
    },
    /// Simulate an attempted security violation (e.g. network egress).
    SandboxViolation(String),
    /// Simulate malformed output from sandbox.
    MalformedOutput(String),
    /// Simulate tampered / mismatched output.
    TamperedOutput(SandboxOutput),
}

/// Thread-safe deterministic mock sandbox runner for testing.
pub struct MockSandboxRunner {
    behaviors: Mutex<VecDeque<MockSandboxBehavior>>,
    executions: Mutex<Vec<(SandboxSecurityProfile, SandboxInput)>>,
}

impl Default for MockSandboxRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl MockSandboxRunner {
    /// Creates a new mock sandbox runner initialized with AutomaticSuccess.
    #[must_use]
    pub fn new() -> Self {
        let mut behaviors = VecDeque::new();
        behaviors.push_back(MockSandboxBehavior::AutomaticSuccess);
        Self {
            behaviors: Mutex::new(behaviors),
            executions: Mutex::new(Vec::new()),
        }
    }

    /// Replaces the default behavior with the specified behavior (builder pattern).
    #[must_use]
    pub fn with_behavior(self, behavior: MockSandboxBehavior) -> Self {
        let mut lock = self.behaviors.lock().expect("mutex poisoned");
        lock.clear();
        lock.push_back(behavior);
        drop(lock);
        self
    }

    /// Replaces the behavior queue with a single behavior.
    pub fn set_behavior(&self, behavior: MockSandboxBehavior) {
        let mut lock = self.behaviors.lock().expect("mutex poisoned");
        lock.clear();
        lock.push_back(behavior);
    }

    /// Pushes a behavior to the end of the queue.
    pub fn push_behavior(&self, behavior: MockSandboxBehavior) {
        self.behaviors
            .lock()
            .expect("mutex poisoned")
            .push_back(behavior);
    }

    /// Returns the number of times `run` was called.
    #[must_use]
    pub fn execution_count(&self) -> usize {
        self.executions.lock().expect("mutex poisoned").len()
    }

    /// Returns a copy of the last input handed to the sandbox.
    #[must_use]
    pub fn last_input(&self) -> Option<SandboxInput> {
        self.executions
            .lock()
            .expect("mutex poisoned")
            .last()
            .map(|(_, input)| input.clone())
    }

    /// Returns a copy of the last profile handed to the sandbox.
    #[must_use]
    pub fn last_profile(&self) -> Option<SandboxSecurityProfile> {
        self.executions
            .lock()
            .expect("mutex poisoned")
            .last()
            .map(|(profile, _)| profile.clone())
    }
}

#[async_trait]
impl SandboxRunner for MockSandboxRunner {
    async fn run(
        &self,
        profile: &SandboxSecurityProfile,
        input: &SandboxInput,
    ) -> Result<SandboxOutput, SandboxError> {
        // Enforce profile validation even in mock
        profile
            .validate()
            .map_err(|detail| SandboxError::SandboxViolation {
                violation_type: "INVALID_PROFILE".to_string(),
                detail,
            })?;

        // Verify input integrity
        input.verify_integrity().map_err(|detail| {
            SandboxError::OutputValidation(super::output::OutputValidationError::InvalidField {
                field: "input_integrity",
                reason: detail,
            })
        })?;

        // Record execution
        self.executions
            .lock()
            .expect("mutex poisoned")
            .push((profile.clone(), input.clone()));

        // Determine behavior
        let behavior = {
            let mut lock = self.behaviors.lock().expect("mutex poisoned");
            if lock.len() > 1 {
                lock.pop_front()
                    .unwrap_or(MockSandboxBehavior::AutomaticSuccess)
            } else {
                lock.front()
                    .cloned()
                    .unwrap_or(MockSandboxBehavior::AutomaticSuccess)
            }
        };

        match behavior {
            MockSandboxBehavior::AutomaticSuccess => {
                let locator = LocatorVersion::new("w014-loc-v1").expect("valid locator");
                let output = SandboxOutput {
                    protocol_version: SANDBOX_PROTOCOL_VERSION.to_string(),
                    document_version_id: input.document_version_id,
                    object_artifact_id: input.object_artifact_id,
                    input_sha256: input.content_sha256,
                    status: SandboxStatus::Success,
                    parser_name: "mock-sandbox-parser".to_string(),
                    parser_version: "1.0.0".to_string(),
                    locator_version: locator,
                    page_count: 1,
                    block_count: 1,
                    span_count: 1,
                    text_sha256: Some(input.content_sha256),
                    execution_duration_ms: 42,
                    failure_code: None,
                    failure_detail: None,
                    parsed_artifact: None,
                };
                output
                    .validate_against_input(input)
                    .map_err(SandboxError::OutputValidation)?;
                Ok(output)
            }
            MockSandboxBehavior::Success(output) => {
                output
                    .validate_against_input(input)
                    .map_err(SandboxError::OutputValidation)?;
                Ok(output)
            }
            MockSandboxBehavior::Timeout(secs) => Err(SandboxError::Timeout {
                elapsed_secs: secs,
                limit_secs: profile.ceilings.max_wall_clock_seconds,
            }),
            MockSandboxBehavior::OutOfMemory => Err(SandboxError::OutOfMemory {
                detail: format!(
                    "Memory allocation exceeded ceiling of {} bytes",
                    profile.ceilings.max_memory_bytes
                ),
            }),
            MockSandboxBehavior::ResourceViolation(detail) => {
                Err(SandboxError::ResourceViolation {
                    resource: "PIDS".to_string(),
                    limit: profile.ceilings.max_pids.to_string(),
                    detail,
                })
            }
            MockSandboxBehavior::Crash { exit_code, stderr } => Err(SandboxError::ProcessCrash {
                exit_code,
                signal: None,
                stderr,
            }),
            MockSandboxBehavior::SandboxViolation(detail) => Err(SandboxError::SandboxViolation {
                violation_type: "NETWORK_EGRESS_BLOCKED".to_string(),
                detail,
            }),
            MockSandboxBehavior::MalformedOutput(detail) => {
                Err(SandboxError::MalformedOutput { detail })
            }
            MockSandboxBehavior::TamperedOutput(output) => {
                // Return tampered output directly without pre-validation
                // Caller / executor will validate and fail closed
                Ok(output)
            }
        }
    }
}
