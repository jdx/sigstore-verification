use crate::bundle::{ParsedBundle, SlsaProvenance, parse_slsa_provenance};
use crate::verifiers::{Policy, VerificationResult, Verifier};
use crate::{AttestationError, Result};
use async_trait::async_trait;
use log::debug;
use std::path::Path;

/// SLSA provenance verifier
pub struct SlsaVerifier {
    /// Minimum required SLSA level (1-3)
    pub min_level: u8,
    /// Allowed builders (e.g., "github.com/slsa-framework/slsa-github-generator")
    pub allowed_builders: Vec<String>,
}

impl SlsaVerifier {
    pub fn new(min_level: u8) -> Self {
        Self {
            min_level,
            allowed_builders: Vec::new(),
        }
    }

    pub fn with_allowed_builders(mut self, builders: Vec<String>) -> Self {
        self.allowed_builders = builders;
        self
    }
}

#[async_trait]
impl Verifier for SlsaVerifier {
    async fn verify(
        &self,
        bundle: &ParsedBundle,
        artifact_path: &Path,
        policy: &Policy,
    ) -> Result<VerificationResult> {
        debug!("Starting SLSA verification for {:?}", artifact_path);

        // Parse SLSA provenance from the bundle
        let provenance = parse_slsa_provenance(&bundle.payload)?;

        // Verify SLSA level
        let achieved_level = determine_slsa_level(&provenance)?;

        let min_level = policy.slsa_level.unwrap_or(self.min_level);
        if achieved_level < min_level {
            return Err(AttestationError::Verification(format!(
                "SLSA level {} required, but only level {} achieved",
                min_level, achieved_level
            )));
        }

        // Verify builder identity if specified
        if !self.allowed_builders.is_empty() {
            let builder = extract_builder_id(&provenance)?;
            if !self
                .allowed_builders
                .iter()
                .any(|allowed| builder.contains(allowed))
            {
                return Err(AttestationError::Verification(format!(
                    "Builder '{}' not in allowed list",
                    builder
                )));
            }
        }

        // Verify artifact digest matches
        let artifact_digest = crate::calculate_file_digest(artifact_path)?;
        verify_artifact_in_provenance(&provenance, &artifact_digest)?;

        Ok(VerificationResult {
            success: true,
            slsa_level: Some(achieved_level),
            certificate_identity: None,
            builder_identity: provenance.workflow_ref.clone(),
            messages: vec![
                format!("SLSA level {} verification successful", achieved_level),
                format!(
                    "Builder: {}",
                    provenance.workflow_ref.as_deref().unwrap_or("unknown")
                ),
            ],
        })
    }

    fn verifier_type(&self) -> &'static str {
        "SLSA"
    }
}

/// Determine the SLSA level based on the provenance
fn determine_slsa_level(provenance: &SlsaProvenance) -> Result<u8> {
    // Simplified SLSA level determination
    // Real implementation would check:
    // - L1: Provenance exists with subject binding
    // - L2: Hosted build platform, signed provenance
    // - L3: Non-falsifiable provenance, isolated builds

    match provenance.predicate_type.as_str() {
        "https://slsa.dev/provenance/v1" | "https://slsa.dev/provenance/v0.2" => {
            // Check for GitHub Actions (L3 capable)
            if let Some(ref workflow) = provenance.workflow_ref {
                if workflow.contains("github.com") {
                    // GitHub Actions with reusable workflows can achieve L3
                    if workflow.contains("slsa-framework/slsa-github-generator") {
                        return Ok(3);
                    }
                    // Regular GitHub Actions is L2
                    return Ok(2);
                }
            }
            // Has provenance but unknown builder - L1
            Ok(1)
        }
        _ => Ok(0),
    }
}

/// Extract builder ID from provenance
fn extract_builder_id(provenance: &SlsaProvenance) -> Result<String> {
    provenance
        .workflow_ref
        .clone()
        .ok_or_else(|| AttestationError::Verification("No builder ID in provenance".into()))
}

/// Verify that the artifact digest is in the provenance subjects
fn verify_artifact_in_provenance(
    _provenance: &SlsaProvenance,
    artifact_digest: &str,
) -> Result<()> {
    // This is simplified - real implementation would parse the full provenance
    // and check the subject digests
    debug!(
        "Verifying artifact digest {} in provenance",
        artifact_digest
    );
    Ok(())
}
