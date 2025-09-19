use crate::bundle::ParsedBundle;
use crate::verifiers::{Policy, VerificationResult, Verifier};
use crate::Result;
use async_trait::async_trait;
use log::debug;
use std::path::Path;

/// GitHub Actions attestation verifier
/// Specializes in verifying GitHub-generated attestations with workflow identity
pub struct GitHubVerifier {
    /// Expected repository (e.g., "owner/repo")
    pub repository: Option<String>,
    /// Expected workflow path (e.g., ".github/workflows/release.yml")
    pub workflow: Option<String>,
}

impl GitHubVerifier {
    pub fn new() -> Self {
        Self {
            repository: None,
            workflow: None,
        }
    }

    pub fn with_repository(mut self, repo: impl Into<String>) -> Self {
        self.repository = Some(repo.into());
        self
    }

    pub fn with_workflow(mut self, workflow: impl Into<String>) -> Self {
        self.workflow = Some(workflow.into());
        self
    }
}

impl Default for GitHubVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Verifier for GitHubVerifier {
    async fn verify(
        &self,
        bundle: &ParsedBundle,
        artifact_path: &Path,
        policy: &Policy,
    ) -> Result<VerificationResult> {
        debug!("Starting GitHub attestation verification for {:?}", artifact_path);

        // Use the workflow from policy if not set on verifier
        let expected_workflow = policy.signer_workflow.as_deref()
            .or(self.workflow.as_deref());

        // Reuse existing GitHub verification logic
        let attestations = vec![crate::api::Attestation {
            bundle: Some(serde_json::from_slice(&bundle.payload)?),
            bundle_url: None,
        }];

        crate::verify::verify_attestations(
            &attestations,
            artifact_path,
            expected_workflow,
        ).await?;

        // Extract certificate info for the result
        let cert_info = if let Some(cert) = &bundle.certificate {
            Some(crate::verify::verify_certificate(cert)?)
        } else {
            None
        };

        Ok(VerificationResult {
            success: true,
            slsa_level: Some(3), // GitHub Actions attestations are SLSA L3
            certificate_identity: cert_info.as_ref()
                .and_then(|ci| ci.repository.clone()),
            builder_identity: cert_info.as_ref()
                .and_then(|ci| ci.workflow_ref.clone()),
            messages: vec![
                "GitHub attestation verification successful".to_string(),
                format!("Workflow: {}", expected_workflow.unwrap_or("any")),
            ],
        })
    }

    fn verifier_type(&self) -> &'static str {
        "GitHub"
    }
}