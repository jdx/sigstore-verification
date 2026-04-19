use std::path::Path;
use thiserror::Error;

pub mod api;
pub mod bundle;
pub mod sources;
pub mod verifiers;
pub mod verify;

// Re-export commonly used types
pub use api::{
    Attestation, AttestationClient, AttestationClientBuilder, FetchParams, MessageDigest,
    MessageSignature,
};
pub use bundle::{ParsedBundle, SlsaProvenance};
pub use sources::{ArtifactRef, AttestationSource};
pub use verifiers::{Policy, VerificationResult, Verifier};
pub use verify::verify_attestations;

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("API error: {0}")]
    Api(String),

    #[error("Verification failed: {0}")]
    Verification(String),

    #[error("No attestations found")]
    NoAttestations,

    #[error("Invalid digest format: {0}")]
    InvalidDigest(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Sigstore error: {0}")]
    Sigstore(String),
}

pub type Result<T> = std::result::Result<T, AttestationError>;

// ===== Generic Verification Functions =====

/// Verify an artifact using any source and verifier
pub async fn verify_artifact(
    artifact_path: &Path,
    source: &dyn AttestationSource,
    verifier: &dyn Verifier,
    policy: Option<&Policy>,
) -> Result<VerificationResult> {
    let artifact_ref = ArtifactRef::from_path(artifact_path)?;
    let attestations = source.fetch_attestations(&artifact_ref).await?;

    if attestations.is_empty() {
        return Err(AttestationError::NoAttestations);
    }

    // Parse the first attestation into a bundle
    let bundle = bundle::parse_bundle(&attestations[0])?;

    // Use provided policy or default
    let default_policy = Policy::default();
    let policy = policy.unwrap_or(&default_policy);

    // Verify using the specified verifier
    verifier.verify(&bundle, artifact_path, policy).await
}

/// Verify a Cosign signature or bundle from a file (keyless)
pub async fn verify_cosign_signature(
    artifact_path: &Path,
    sig_or_bundle_path: &Path,
) -> Result<bool> {
    let source = sources::file::FileSource::new(sig_or_bundle_path);
    let verifier = verifiers::cosign::CosignVerifier::new_keyless();

    let result = verify_artifact(artifact_path, &source, &verifier, None).await?;

    Ok(result.success)
}

/// Verify a Cosign signature using a public key
pub async fn verify_cosign_signature_with_key(
    artifact_path: &Path,
    sig_or_bundle_path: &Path,
    public_key_path: &Path,
) -> Result<bool> {
    let source = sources::file::FileSource::new(sig_or_bundle_path);
    let verifier = verifiers::cosign::CosignVerifier::new_with_key_file(public_key_path).await?;

    let result = verify_artifact(artifact_path, &source, &verifier, None).await?;

    Ok(result.success)
}

/// Verify SLSA provenance from a file
pub async fn verify_slsa_provenance(
    artifact_path: &Path,
    provenance_path: &Path,
    min_level: u8,
) -> Result<bool> {
    let source = sources::file::FileSource::new(provenance_path);
    let verifier = verifiers::slsa::SlsaVerifier::new(min_level);

    let policy = Policy {
        slsa_level: Some(min_level),
        ..Default::default()
    };

    let result = verify_artifact(artifact_path, &source, &verifier, Some(&policy)).await?;

    Ok(result.success)
}

// ===== Legacy GitHub-specific function (for backwards compatibility) =====

/// Verify a GitHub artifact attestation
///
/// # Arguments
/// * `artifact_path` - Path to the artifact file to verify
/// * `owner` - GitHub organization or user that owns the repository
/// * `repo` - Repository name (without owner)
/// * `token` - Optional GitHub token for API authentication
/// * `signer_workflow` - Optional workflow path to verify against
pub async fn verify_github_attestation(
    artifact_path: &Path,
    owner: &str,
    repo: &str,
    token: Option<&str>,
    signer_workflow: Option<&str>,
) -> Result<bool> {
    verify_github_attestation_inner(artifact_path, owner, repo, token, signer_workflow, None).await
}

/// Verify a GitHub artifact attestation against a custom GitHub API base URL
/// (e.g. a GitHub Enterprise Server instance such as
/// `https://github.enterprise.com/api/v3`).
///
/// # Arguments
/// * `artifact_path` - Path to the artifact file to verify
/// * `owner` - GitHub organization or user that owns the repository
/// * `repo` - Repository name (without owner)
/// * `token` - Optional GitHub token for API authentication
/// * `signer_workflow` - Optional workflow path to verify against
/// * `base_url` - Base URL of the GitHub API (e.g.
///   `https://github.enterprise.com/api/v3`). The auth token is only sent to
///   this host — bundle URLs pointing elsewhere are fetched unauthenticated.
pub async fn verify_github_attestation_with_base_url(
    artifact_path: &Path,
    owner: &str,
    repo: &str,
    token: Option<&str>,
    signer_workflow: Option<&str>,
    base_url: &str,
) -> Result<bool> {
    verify_github_attestation_inner(
        artifact_path,
        owner,
        repo,
        token,
        signer_workflow,
        Some(base_url),
    )
    .await
}

async fn verify_github_attestation_inner(
    artifact_path: &Path,
    owner: &str,
    repo: &str,
    token: Option<&str>,
    signer_workflow: Option<&str>,
    base_url: Option<&str>,
) -> Result<bool> {
    // Calculate artifact digest
    let digest = calculate_file_digest(artifact_path)?;

    // Create API client
    let mut client_builder = AttestationClient::builder();
    if let Some(token) = token {
        client_builder = client_builder.github_token(token);
    }
    if let Some(base_url) = base_url {
        client_builder = client_builder.base_url(base_url);
    }
    let client = client_builder.build()?;

    // Fetch attestations from GitHub. Don't filter by predicate type — some
    // projects publish non-SLSA attestations (e.g. SPDX SBOM), and filtering
    // would hide them even though they are still valid sigstore bundles we
    // can verify via certificate + DSSE signature.
    let params = FetchParams {
        owner: owner.to_string(),
        repo: Some(format!("{}/{}", owner, repo)),
        digest: format!("sha256:{}", digest),
        limit: 30,
        predicate_type: None,
    };

    let attestations = client.fetch_attestations(params).await?;

    if attestations.is_empty() {
        return Err(AttestationError::NoAttestations);
    }

    // Verify attestations
    verify::verify_attestations(&attestations, artifact_path, signer_workflow).await?;

    Ok(true)
}

pub fn calculate_file_digest(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hex::encode(hasher.finalize()))
}
