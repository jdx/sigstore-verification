pub mod file;
pub mod github;
pub mod oci;

use crate::Result;
use async_trait::async_trait;
use std::path::Path;

/// Reference to an artifact that needs verification
#[derive(Debug, Clone)]
pub struct ArtifactRef {
    /// SHA256 digest of the artifact
    pub digest: String,
    /// Optional path to the artifact file
    pub path: Option<String>,
    /// Optional additional metadata
    pub metadata: Option<serde_json::Value>,
}

impl ArtifactRef {
    pub fn from_path(path: &Path) -> Result<Self> {
        let digest = crate::calculate_file_digest(path)?;
        Ok(Self {
            digest: format!("sha256:{}", digest),
            path: Some(path.to_string_lossy().to_string()),
            metadata: None,
        })
    }

    pub fn from_digest(digest: &str) -> Self {
        Self {
            digest: digest.to_string(),
            path: None,
            metadata: None,
        }
    }
}

/// Trait for different sources of attestations
#[async_trait]
pub trait AttestationSource: Send + Sync {
    /// Fetch attestations for a given artifact
    async fn fetch_attestations(
        &self,
        artifact: &ArtifactRef,
    ) -> Result<Vec<crate::api::Attestation>>;

    /// Get the source type name for logging
    fn source_type(&self) -> &'static str;
}
