use std::path::Path;
use thiserror::Error;

pub mod api;
pub mod bundle;
pub mod verify;
pub mod sources;
pub mod verifiers;

// Re-export commonly used types
pub use api::{AttestationClient, FetchParams, Attestation};
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

    let result = verify_artifact(
        artifact_path,
        &source,
        &verifier,
        None,
    ).await?;

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

    let result = verify_artifact(
        artifact_path,
        &source,
        &verifier,
        None,
    ).await?;

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

    let result = verify_artifact(
        artifact_path,
        &source,
        &verifier,
        Some(&policy),
    ).await?;

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
    // Calculate artifact digest
    let digest = calculate_file_digest(artifact_path)?;

    // Create API client
    let client = AttestationClient::new(token)?;

    // Fetch attestations from GitHub
    let params = FetchParams {
        owner: owner.to_string(),
        repo: Some(format!("{}/{}", owner, repo)),
        digest: format!("sha256:{}", digest),
        limit: 30,
        predicate_type: Some("https://slsa.dev/provenance/v1".to_string()),
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
    use sha2::{Sha256, Digest};
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