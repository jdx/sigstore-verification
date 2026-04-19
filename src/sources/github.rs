use crate::Result;
use crate::api::{Attestation, AttestationClient, FetchParams};
use crate::sources::{ArtifactRef, AttestationSource};
use async_trait::async_trait;

/// GitHub source for fetching artifact attestations from GitHub's API
pub struct GitHubSource {
    client: AttestationClient,
    owner: String,
    repo: String,
}

impl GitHubSource {
    /// Create a new `GitHubSource` targeting `https://api.github.com`.
    pub fn new(
        owner: impl Into<String>,
        repo: impl Into<String>,
        token: Option<&str>,
    ) -> Result<Self> {
        let mut builder = Self::builder().owner(owner).repo(repo);
        if let Some(token) = token {
            builder = builder.token(token);
        }
        builder.build()
    }

    /// Create a new `GitHubSource` targeting a custom API base URL (e.g. a
    /// GitHub Enterprise Server instance such as
    /// `https://github.enterprise.com/api/v3`).
    pub fn with_base_url(
        owner: impl Into<String>,
        repo: impl Into<String>,
        token: Option<&str>,
        base_url: &str,
    ) -> Result<Self> {
        let mut builder = Self::builder().owner(owner).repo(repo).base_url(base_url);
        if let Some(token) = token {
            builder = builder.token(token);
        }
        builder.build()
    }

    /// Create a new `GitHubSource` from an already-built [`AttestationClient`],
    /// allowing the caller to configure the HTTP client (base URL, token, etc.)
    /// independently.
    pub fn with_client(
        owner: impl Into<String>,
        repo: impl Into<String>,
        client: AttestationClient,
    ) -> Self {
        Self {
            client,
            owner: owner.into(),
            repo: repo.into(),
        }
    }

    /// Start building a `GitHubSource` with a fluent builder.
    pub fn builder() -> GitHubSourceBuilder {
        GitHubSourceBuilder::default()
    }
}

/// Builder for [`GitHubSource`].
#[derive(Debug, Default)]
pub struct GitHubSourceBuilder {
    owner: Option<String>,
    repo: Option<String>,
    token: Option<String>,
    base_url: Option<String>,
}

impl GitHubSourceBuilder {
    pub fn owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = Some(owner.into());
        self
    }

    pub fn repo(mut self, repo: impl Into<String>) -> Self {
        self.repo = Some(repo.into());
        self
    }

    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    pub fn build(self) -> Result<GitHubSource> {
        let owner = self.owner.ok_or_else(|| {
            crate::AttestationError::Api("GitHubSource: owner is required".into())
        })?;
        let repo = self
            .repo
            .ok_or_else(|| crate::AttestationError::Api("GitHubSource: repo is required".into()))?;

        let mut client_builder = AttestationClient::builder();
        if let Some(token) = self.token {
            client_builder = client_builder.github_token(&token);
        }
        if let Some(base_url) = self.base_url {
            client_builder = client_builder.base_url(&base_url);
        }
        let client = client_builder.build()?;

        Ok(GitHubSource {
            client,
            owner,
            repo,
        })
    }
}

#[async_trait]
impl AttestationSource for GitHubSource {
    /// Fetch attestations for an artifact from the configured GitHub API.
    ///
    /// Note: this filters the GitHub API response to SLSA provenance v1
    /// (`https://slsa.dev/provenance/v1`) because `GitHubSource` is intended
    /// for SLSA verification via the generic `verify_artifact` + `SlsaVerifier`
    /// flow. Callers who need the unfiltered attestation set (e.g. non-SLSA
    /// bundles such as SPDX SBOMs) should use
    /// [`crate::verify_github_attestation`] /
    /// [`crate::verify_github_attestation_with_base_url`], which send no
    /// predicate filter, or drive [`AttestationClient`] directly.
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
