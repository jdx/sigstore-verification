use crate::api::Attestation;
use crate::sources::{ArtifactRef, AttestationSource};
use crate::{AttestationError, Result};
use async_trait::async_trait;

/// OCI registry source for fetching attestations from container registries
/// This follows the Cosign attachment specification
pub struct OciSource {
    #[allow(dead_code)]
    registry_url: String,
    // TODO: Add OCI client configuration
}

impl OciSource {
    pub fn new(registry_url: impl Into<String>) -> Self {
        Self {
            registry_url: registry_url.into(),
        }
    }
}

#[async_trait]
impl AttestationSource for OciSource {
    async fn fetch_attestations(&self, _artifact: &ArtifactRef) -> Result<Vec<Attestation>> {
        // TODO: Implement OCI registry attestation fetching
        // This would:
        // 1. Connect to the OCI registry
        // 2. Look for attestations attached to the artifact digest
        // 3. Download and parse the attestation bundles
        Err(AttestationError::Verification(
            "OCI source not yet implemented".into()
        ))
    }

    fn source_type(&self) -> &'static str {
        "OCI"
    }
}
