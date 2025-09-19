pub mod cosign;
pub mod github;
pub mod slsa;

use crate::Result;
use crate::bundle::ParsedBundle;
use async_trait::async_trait;
use std::path::Path;

/// Verification policy that can be applied during verification
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Required SLSA level (1, 2, or 3)
    pub slsa_level: Option<u8>,
    /// Required certificate identity
    pub certificate_identity: Option<String>,
    /// Required OIDC issuer
    pub certificate_oidc_issuer: Option<String>,
    /// Required workflow/builder identity
    pub signer_workflow: Option<String>,
    /// Allow self-hosted runners
    pub allow_self_hosted: bool,
    /// Custom policy expressions (future: CUE or Rego)
    pub custom_policies: Vec<String>,
}

/// Result of verification
#[derive(Debug)]
pub struct VerificationResult {
    /// Whether verification succeeded
    pub success: bool,
    /// SLSA level achieved (if applicable)
    pub slsa_level: Option<u8>,
    /// Certificate identity found
    pub certificate_identity: Option<String>,
    /// Builder/workflow identity
    pub builder_identity: Option<String>,
    /// Any warnings or notes
    pub messages: Vec<String>,
}

/// Trait for different verification strategies
#[async_trait]
pub trait Verifier: Send + Sync {
    /// Verify an attestation bundle against an artifact
    async fn verify(
        &self,
        bundle: &ParsedBundle,
        artifact_path: &Path,
        policy: &Policy,
    ) -> Result<VerificationResult>;

    /// Get the verifier type name for logging
    fn verifier_type(&self) -> &'static str;
}
