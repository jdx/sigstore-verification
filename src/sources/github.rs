use crate::api::{Attestation, AttestationClient, FetchParams};
use crate::sources::{ArtifactRef, AttestationSource};
use crate::Result;
use async_trait::async_trait;

/// GitHub attestation source for fetching attestations from GitHub's API
pub struct GitHubSource {
    client: AttestationClient,
    owner: String,
    repo: String,
}

impl GitHubSource {
    pub fn new(owner: impl Into<String>, repo: impl Into<String>, token: Option<&str>) -> Result<Self> {
        Ok(Self {
            client: AttestationClient::new(token)?,
            owner: owner.into(),
            repo: repo.into(),
        })
    }
}

#[async_trait]
impl AttestationSource for GitHubSource {
    async fn fetch_attestations(&self, artifact: &ArtifactRef) -> Result<Vec<Attestation>> {
        let params = FetchParams {
            owner: self.owner.clone(),
            repo: Some(format!("{}/{}", self.owner, self.repo)),
            digest: artifact.digest.clone(),
            limit: 30,
            predicate_type: Some("https://slsa.dev/provenance/v1".to_string()),
        };

        self.client.fetch_attestations(params).await
    }

    fn source_type(&self) -> &'static str {
        "GitHub"
    }
}