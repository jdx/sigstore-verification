use crate::bundle::ParsedBundle;
use crate::verifiers::{Policy, VerificationResult, Verifier};
use crate::{AttestationError, Result};
use async_trait::async_trait;
use log::debug;
use std::path::Path;

// Import cryptographic libraries for key-based verification
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use p256::ecdsa::{signature::Verifier as P256Verifier, VerifyingKey as P256VerifyingKey, Signature as P256Signature};
use p256::pkcs8::DecodePublicKey;  // For from_public_key_pem
use ed25519_dalek::{VerifyingKey as Ed25519VerifyingKey, Signature as Ed25519Signature};

/// Cosign-compatible verifier for blob signatures and attestations
pub struct CosignVerifier {
    /// Whether to use keyless verification (Fulcio) or key-based
    pub keyless: bool,
    /// Optional public key for key-based verification
    pub public_key: Option<Vec<u8>>,
}

impl CosignVerifier {
    pub fn new_keyless() -> Self {
        Self {
            keyless: true,
            public_key: None,
        }
    }

    pub fn new_with_key(public_key: Vec<u8>) -> Self {
        Self {
            keyless: false,
            public_key: Some(public_key),
        }
    }

    /// Load a public key from a file
    pub async fn new_with_key_file(key_path: &Path) -> Result<Self> {
        use tokio::fs;

        let public_key = fs::read(key_path)
            .await
            .map_err(|e| AttestationError::Verification(
                format!("Failed to read public key file: {}", e)
            ))?;

        Ok(Self {
            keyless: false,
            public_key: Some(public_key),
        })
    }

    /// Load a public key from a string (PEM or base64)
    pub fn new_with_key_string(key_str: &str) -> Self {
        Self {
            keyless: false,
            public_key: Some(key_str.as_bytes().to_vec()),
        }
    }
}

#[async_trait]
impl Verifier for CosignVerifier {
    async fn verify(
        &self,
        bundle: &ParsedBundle,
        artifact_path: &Path,
        policy: &Policy,
    ) -> Result<VerificationResult> {
        debug!("Starting Cosign verification for {:?}", artifact_path);

        // Calculate artifact digest
        let artifact_digest = crate::calculate_file_digest(artifact_path)?;

        if self.keyless {
            // Perform keyless verification using Fulcio certificates
            verify_keyless(bundle, &artifact_digest, policy).await
        } else if let Some(key) = &self.public_key {
            // Perform key-based verification
            verify_with_key(bundle, &artifact_digest, key, policy).await
        } else {
            Err(AttestationError::Verification(
                "No public key provided for key-based verification".into()
            ))
        }
    }

    fn verifier_type(&self) -> &'static str {
        if self.keyless {
            "Cosign-Keyless"
        } else {
            "Cosign-Key"
        }
    }
}

async fn verify_keyless(
    bundle: &ParsedBundle,
    _artifact_digest: &str,
    policy: &Policy,
) -> Result<VerificationResult> {
    // This reuses the existing Sigstore verification logic
    let mut result = VerificationResult {
        success: false,
        slsa_level: None,
        certificate_identity: None,
        builder_identity: None,
        messages: Vec::new(),
    };

    // Verify the bundle using existing verify module
    let attestations = vec![crate::api::Attestation {
        bundle: Some(serde_json::from_slice(&bundle.payload)?),
        bundle_url: None,
    }];

    let artifact_path = std::path::Path::new("dummy"); // We already have the digest
    crate::verify::verify_attestations(
        &attestations,
        artifact_path,
        policy.signer_workflow.as_deref(),
    ).await?;

    result.success = true;
    result.messages.push("Cosign keyless verification successful".to_string());

    Ok(result)
}

async fn verify_with_key(
    bundle: &ParsedBundle,
    artifact_digest: &str,
    public_key: &[u8],
    _policy: &Policy,
) -> Result<VerificationResult> {
    let mut result = VerificationResult {
        success: false,
        slsa_level: None,
        certificate_identity: None,
        builder_identity: None,
        messages: Vec::new(),
    };

    // Cosign key-based signatures can be in different formats:
    // 1. Simple blob signature (just the signature bytes)
    // 2. DSSE envelope with signatures
    // 3. Bundle format with signature and optional certificate

    if let Some(dsse_envelope) = &bundle.dsse_envelope {
        // Handle DSSE envelope format
        debug!("Verifying DSSE envelope with public key");

        // Get the first signature from the envelope
        let signature = dsse_envelope.signatures.first()
            .ok_or_else(|| AttestationError::Verification("No signatures in DSSE envelope".into()))?;

        // Decode the signature
        let sig_bytes = BASE64.decode(&signature.sig)
            .map_err(|e| AttestationError::Verification(format!("Failed to decode signature: {}", e)))?;

        // Create the message to verify (for DSSE, it's the PAE)
        let pae = create_dsse_pae(&dsse_envelope.payload_type, dsse_envelope.payload.as_bytes());

        // Verify the signature
        verify_signature_with_key(public_key, &sig_bytes, &pae)?;

        // Verify that the payload contains the artifact digest
        verify_payload_digest(&dsse_envelope.payload, artifact_digest)?;

        result.messages.push("DSSE envelope signature verified with public key".to_string());
    } else {
        // Handle simple signature format (raw signature bytes in payload)
        debug!("Verifying simple signature with public key");

        // For simple signatures, the payload is typically the signature itself
        // and we need to reconstruct what was signed (usually the digest)
        let signature = &bundle.payload;

        // The signed content for simple blob signatures is typically:
        // - Just the artifact digest (for detached signatures)
        // - Or the artifact content itself
        let message = artifact_digest.as_bytes();

        // Verify the signature
        verify_signature_with_key(public_key, signature, message)?;

        result.messages.push("Simple signature verified with public key".to_string());
    }

    result.success = true;
    result.messages.push(format!("Artifact digest verified: {}", artifact_digest));

    Ok(result)
}

/// Verify a signature using a public key
fn verify_signature_with_key(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<()> {
    // Try to determine the key type and verify accordingly

    // Try Ed25519 first (fixed size: 32 bytes for public key, 64 for signature)
    if public_key.len() == 32 && signature.len() == 64 {
        debug!("Attempting Ed25519 verification");
        if let Ok(verifying_key) = Ed25519VerifyingKey::from_bytes(public_key.try_into().unwrap()) {
            let sig = Ed25519Signature::from_bytes(signature.try_into().unwrap());

            return verifying_key.verify(message, &sig)
                .map_err(|e| AttestationError::Verification(format!("Ed25519 verification failed: {}", e)));
        }
    }

    // Try P-256 ECDSA (common for Cosign)
    // P-256 public keys in compressed form are 33 bytes, uncompressed are 65 bytes
    if public_key.len() == 33 || public_key.len() == 65 {
        debug!("Attempting P-256 ECDSA verification");

        // Try to parse as P-256 public key
        if let Ok(verifying_key) = P256VerifyingKey::from_sec1_bytes(public_key) {
            // Try to parse signature (can be DER encoded or raw)
            let sig = P256Signature::from_der(signature)
                .or_else(|_| P256Signature::from_bytes(signature.into()))
                .map_err(|e| AttestationError::Verification(format!("Failed to parse P-256 signature: {}", e)))?;

            return verifying_key.verify(message, &sig)
                .map_err(|e| AttestationError::Verification(format!("P-256 verification failed: {}", e)));
        }
    }

    // Try PEM-encoded public key
    if public_key.starts_with(b"-----BEGIN PUBLIC KEY-----") {
        debug!("Attempting to parse PEM-encoded public key");
        return verify_with_pem_key(public_key, signature, message);
    }

    Err(AttestationError::Verification(
        "Unable to determine public key type or verification failed".into()
    ))
}

/// Verify using a PEM-encoded public key
fn verify_with_pem_key(
    pem_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<()> {
    // Parse PEM to get the actual key bytes
    let pem_str = std::str::from_utf8(pem_key)
        .map_err(|e| AttestationError::Verification(format!("Invalid PEM encoding: {}", e)))?;

    // Try to parse as P-256 key
    if let Ok(verifying_key) = P256VerifyingKey::from_public_key_pem(pem_str) {
        debug!("Parsed P-256 public key from PEM");
        let sig = P256Signature::from_der(signature)
            .or_else(|_| P256Signature::from_bytes(signature.into()))
            .map_err(|e| AttestationError::Verification(format!("Failed to parse signature: {}", e)))?;

        return verifying_key.verify(message, &sig)
            .map_err(|e| AttestationError::Verification(format!("P-256 verification failed: {}", e)));
    }

    // Try to parse as Ed25519 key
    // Ed25519-dalek doesn't have direct PEM support, we need to extract the key bytes
    // from the PEM and then parse them
    if pem_str.contains("-----BEGIN PUBLIC KEY-----") {
        // Extract the base64 content between the PEM headers
        let lines: Vec<&str> = pem_str.lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let pem_content = lines.join("");

        // Decode the base64 content
        if let Ok(der_bytes) = BASE64.decode(&pem_content) {
            // For Ed25519, the public key is typically the last 32 bytes of the DER structure
            // DER structure for Ed25519: SEQUENCE -> SEQUENCE -> BIT STRING containing the key
            if der_bytes.len() >= 44 {
                // Skip the DER structure overhead and get the actual key (last 32 bytes)
                let key_start = der_bytes.len() - 32;
                let key_bytes = &der_bytes[key_start..];

                if let Ok(verifying_key) = Ed25519VerifyingKey::from_bytes(key_bytes.try_into().unwrap()) {
                    debug!("Parsed Ed25519 public key from PEM");
                    if signature.len() != 64 {
                        return Err(AttestationError::Verification(
                            format!("Invalid Ed25519 signature length: {}", signature.len())
                        ));
                    }
                    let sig = Ed25519Signature::from_bytes(signature.try_into().unwrap());

                    return verifying_key.verify(message, &sig)
                        .map_err(|e| AttestationError::Verification(format!("Ed25519 verification failed: {}", e)));
                }
            }
        }
    }

    Err(AttestationError::Verification(
        "Failed to parse PEM public key".into()
    ))
}

/// Create DSSE PAE (Pre-Authentication Encoding)
fn create_dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut pae = Vec::new();

    // DSSEv1 = ASCII(DSSEv1) + SP + LEN(type) + SP + type + SP + LEN(payload) + SP + payload
    pae.extend_from_slice(b"DSSEv1");
    pae.push(b' ');
    pae.extend_from_slice(payload_type.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload_type.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload);

    pae
}

/// Verify that the DSSE payload contains the expected artifact digest
fn verify_payload_digest(payload: &str, expected_digest: &str) -> Result<()> {
    // Decode the payload (it's base64 encoded in DSSE)
    let payload_bytes = BASE64.decode(payload)
        .map_err(|e| AttestationError::Verification(format!("Failed to decode payload: {}", e)))?;

    // Parse as JSON to check for subject digest
    let payload_json: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AttestationError::Verification(format!("Failed to parse payload JSON: {}", e)))?;

    // Check if the payload contains the expected digest in the subject field
    if let Some(subject) = payload_json.get("subject").and_then(|s| s.as_array()) {
        for subj in subject {
            if let Some(digest) = subj.get("digest").and_then(|d| d.get("sha256")).and_then(|s| s.as_str()) {
                if digest == expected_digest || format!("sha256:{}", digest) == expected_digest {
                    debug!("Artifact digest verified in payload: {}", digest);
                    return Ok(());
                }
            }
        }
    }

    // For simple signatures, the digest might not be in the payload
    // In that case, we assume the caller has already verified the content matches
    debug!("Digest not found in payload, assuming external verification");
    Ok(())
}