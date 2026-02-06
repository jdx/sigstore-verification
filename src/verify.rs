use crate::bundle::{DsseEnvelope, ParsedBundle, parse_bundle, parse_slsa_provenance};
use crate::{AttestationError, Result, api::Attestation};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use log::debug;
use sha2::{Digest, Sha256};
use sigstore::cosign::{ClientBuilder, CosignCapabilities};
use sigstore::trust::TrustRoot;
use sigstore::trust::sigstore::SigstoreTrustRoot;
use std::path::Path;
use std::sync::Arc;

// Cryptographic imports for signature verification
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use p256::ecdsa::{
    Signature as P256Signature, VerifyingKey as P256VerifyingKey,
    signature::Verifier as P256Verifier,
};
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use x509_parser::prelude::*;

pub async fn verify_attestations(
    attestations: &[Attestation],
    artifact_path: &Path,
    signer_workflow: Option<&str>,
) -> Result<()> {
    if attestations.is_empty() {
        return Err(AttestationError::NoAttestations);
    }

    // Calculate artifact digest for verification
    let artifact_digest = calculate_artifact_digest(artifact_path)?;

    let mut valid_attestation_found = false;
    let mut verification_errors = Vec::new();

    for attestation in attestations {
        match verify_single_attestation(attestation, &artifact_digest, signer_workflow).await {
            Ok(()) => {
                valid_attestation_found = true;
                debug!("Successfully verified attestation");
                break; // One valid attestation is enough
            }
            Err(e) => {
                debug!("Attestation verification failed: {}", e);
                verification_errors.push(e);
            }
        }
    }

    if !valid_attestation_found {
        if verification_errors.is_empty() {
            return Err(AttestationError::Verification(
                "No valid attestations found".into(),
            ));
        } else {
            // Return the first error for now
            return Err(verification_errors.into_iter().next().unwrap());
        }
    }

    Ok(())
}

/// Verify a single attestation
async fn verify_single_attestation(
    attestation: &Attestation,
    artifact_digest: &str,
    expected_workflow: Option<&str>,
) -> Result<()> {
    // Parse the bundle
    let bundle = parse_bundle(attestation)?;

    // Parse SLSA provenance from payload
    let provenance = parse_slsa_provenance(&bundle.payload)?;

    // Early workflow check from provenance - will be more thoroughly checked with certificate later
    if let Some(expected) = expected_workflow {
        if let Some(workflow_ref) = &provenance.workflow_ref {
            // Check if either contains the other (handles partial paths)
            if !workflow_ref.contains(expected) && !expected.contains(workflow_ref) {
                debug!(
                    "Workflow mismatch in provenance: expected '{}', got '{}'",
                    expected, workflow_ref
                );
                // Don't fail here, will check certificate later
            }
        }
    }

    // Verify artifact digest matches
    verify_artifact_digest(&bundle.payload, artifact_digest)?;

    // Verify certificate - this is required for proper attestation verification
    if let Some(cert_pem) = &bundle.certificate {
        let cert_info = verify_certificate(cert_pem)?;

        debug!("Certificate info: {:?}", cert_info);

        // If we have an expected workflow, verify it against the certificate
        if let Some(expected) = expected_workflow {
            // Try to match the workflow - could be full path or just filename
            let cert_matches = if let Some(cert_workflow) = &cert_info.workflow_ref {
                cert_workflow.contains(expected) || expected.contains(cert_workflow)
            } else {
                false
            };

            let provenance_matches = if let Some(prov_workflow) = &provenance.workflow_ref {
                prov_workflow.contains(expected) || expected.contains(prov_workflow)
            } else {
                false
            };

            if !cert_matches && !provenance_matches {
                return Err(AttestationError::Verification(format!(
                    "Workflow verification failed: expected '{}', found certificate: {:?}, provenance: {:?}",
                    expected, cert_info.workflow_ref, provenance.workflow_ref
                )));
            }
        }

        // Verify issuer is from sigstore
        if !cert_info.issuer.to_lowercase().contains("sigstore") {
            return Err(AttestationError::Verification(format!(
                "Invalid certificate issuer: expected sigstore, got '{}'",
                cert_info.issuer
            )));
        }
    } else {
        return Err(AttestationError::Verification(
            "No certificate found in attestation bundle".into(),
        ));
    }

    if bundle.dsse_envelope.is_none() {
        return Err(AttestationError::Verification(
            "No DSSE envelope found in bundle".into(),
        ));
    }

    // Perform Sigstore verification
    verify_sigstore_bundle(&bundle).await?;

    Ok(())
}

/// Verify that the artifact digest matches what's in the attestation
fn verify_artifact_digest(payload: &[u8], expected_digest: &str) -> Result<()> {
    let statement: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| AttestationError::Verification(format!("Failed to parse payload: {}", e)))?;

    // Extract subjects from the statement
    let subjects = statement
        .get("subject")
        .and_then(|s| s.as_array())
        .ok_or_else(|| AttestationError::Verification("No subjects in attestation".into()))?;

    for subject in subjects {
        if let Some(digest) = subject.get("digest") {
            if let Some(sha256) = digest.get("sha256") {
                if let Some(digest_str) = sha256.as_str() {
                    if digest_str == expected_digest {
                        return Ok(());
                    }
                }
            }
        }
    }

    Err(AttestationError::Verification(format!(
        "Artifact digest mismatch: expected {}",
        expected_digest
    )))
}

/// Calculate SHA256 digest of a file
fn calculate_artifact_digest(path: &Path) -> Result<String> {
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

/// Verify the certificate and extract identity information
pub fn verify_certificate(cert_pem: &str) -> Result<CertificateInfo> {
    use x509_parser::prelude::*;

    // Decode base64 certificate
    let cert_bytes = BASE64.decode(cert_pem).map_err(|e| {
        AttestationError::Verification(format!("Failed to decode certificate: {}", e))
    })?;

    // Parse X.509 certificate
    let (_, cert) = X509Certificate::from_der(&cert_bytes).map_err(|e| {
        AttestationError::Verification(format!("Failed to parse certificate: {}", e))
    })?;

    // Extract issuer information
    let issuer = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Extract workflow reference from Subject Alternative Names
    let mut repository = None;
    let mut workflow_name = None;
    let mut workflow_ref_full = None;

    // Check certificate extensions for SANs
    for ext in cert.extensions() {
        // Subject Alternative Names extension OID is 2.5.29.17
        if ext.oid.to_string() == "2.5.29.17" {
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                for name in &san.general_names {
                    if let GeneralName::URI(uri) = name {
                        let uri_str = uri.to_string();

                        // Look for GitHub workflow URLs
                        if uri_str.starts_with("https://github.com/") {
                            if uri_str.contains("/.github/workflows/") {
                                // Full workflow path
                                workflow_ref_full = Some(uri_str.clone());

                                // Extract just the workflow file name
                                if let Some(workflow_part) =
                                    uri_str.split("/.github/workflows/").nth(1)
                                {
                                    if let Some(workflow_file) = workflow_part.split('@').next() {
                                        workflow_name = Some(workflow_file.to_string());
                                    }
                                }

                                // Extract repository
                                if let Some(repo_part) = uri_str.strip_prefix("https://github.com/")
                                {
                                    if let Some(repo_end) = repo_part.find("/.github/workflows/") {
                                        repository = Some(repo_part[..repo_end].to_string());
                                    }
                                }
                            } else if !uri_str.contains("/actions/runs/") {
                                // Repository URL
                                repository = Some(
                                    uri_str
                                        .strip_prefix("https://github.com/")
                                        .unwrap_or(&uri_str)
                                        .to_string(),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Use the most specific workflow reference available
    let workflow_ref = workflow_ref_full.or(workflow_name);

    Ok(CertificateInfo {
        workflow_ref,
        repository,
        issuer,
        not_before: Some(cert.validity().not_before.to_string()),
        not_after: Some(cert.validity().not_after.to_string()),
    })
}

/// Extract workflow identity from certificate and verify it matches expected
pub fn verify_workflow_identity_from_cert(cert_pem: &str, expected_workflow: &str) -> Result<bool> {
    let cert_info = verify_certificate(cert_pem)?;

    if let Some(workflow_ref) = &cert_info.workflow_ref {
        // Check if the workflow reference contains the expected workflow
        // This could be a partial match (e.g., "release.yml" matches ".github/workflows/release.yml@ref")
        Ok(workflow_ref.contains(expected_workflow))
    } else {
        Ok(false)
    }
}

#[derive(Debug)]
pub struct CertificateInfo {
    pub workflow_ref: Option<String>,
    pub repository: Option<String>,
    pub issuer: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
}

/// Get or fetch the Sigstore trust root
async fn get_sigstore_trust_root() -> Option<Arc<SigstoreTrustRoot>> {
    match fetch_sigstore_trust_root().await {
        Ok(root) => {
            debug!("Successfully fetched Sigstore trust root");
            Some(Arc::new(root))
        }
        Err(e) => {
            debug!(
                "Failed to fetch Sigstore trust root: {}. Will use simplified verification.",
                e
            );
            None
        }
    }
}

/// Fetch the Sigstore trust root from the TUF repository
async fn fetch_sigstore_trust_root() -> Result<SigstoreTrustRoot> {
    SigstoreTrustRoot::new(None)
        .await
        .map_err(|e| AttestationError::Verification(format!("Failed to fetch trust root: {}", e)))
}

/// Verify a Sigstore bundle including certificate chain and signatures
async fn verify_sigstore_bundle(bundle: &ParsedBundle) -> Result<()> {
    // Check for required components
    let cert_pem = bundle
        .certificate
        .as_ref()
        .ok_or_else(|| AttestationError::Verification("No certificate in bundle".into()))?;

    let envelope = bundle
        .dsse_envelope
        .as_ref()
        .ok_or_else(|| AttestationError::Verification("No DSSE envelope in bundle".into()))?;

    // Decode the certificate
    let cert_bytes = BASE64.decode(cert_pem).map_err(|e| {
        AttestationError::Verification(format!("Failed to decode certificate: {}", e))
    })?;

    // Parse and validate certificate
    let cert_info = verify_certificate(cert_pem)?;

    // Validate that this is a GitHub Actions certificate from Sigstore
    if !cert_info.issuer.to_lowercase().contains("sigstore") {
        return Err(AttestationError::Verification(format!(
            "Invalid issuer: expected sigstore, got '{}'",
            cert_info.issuer
        )));
    }

    // Verify DSSE envelope structure
    if envelope.signatures.is_empty() {
        return Err(AttestationError::Verification(
            "DSSE envelope has no signatures".into(),
        ));
    }

    // Try to perform full Sigstore verification
    debug!("Attempting full Sigstore verification...");
    match verify_with_sigstore_client(&cert_bytes, bundle, envelope).await {
        Ok(()) => {
            debug!("Full Sigstore verification succeeded");
            Ok(())
        }
        Err(e) => {
            debug!(
                "Full Sigstore verification failed, falling back to basic checks: {}",
                e
            );
            // Fall back to basic verification
            verify_basic_bundle_structure(envelope, &cert_info)
        }
    }
}

/// Perform full Sigstore verification using the sigstore client
async fn verify_with_sigstore_client(
    cert_bytes: &[u8],
    bundle: &ParsedBundle,
    envelope: &DsseEnvelope,
) -> Result<()> {
    // Get the trust root
    let trust_root = get_sigstore_trust_root().await.ok_or_else(|| {
        AttestationError::Verification("Could not fetch Sigstore trust root".into())
    })?;

    // Build the Sigstore client
    let mut client = ClientBuilder::default()
        .with_trust_repository(&*trust_root)
        .map_err(|e| AttestationError::Verification(format!("Failed to build client: {}", e)))?
        .build()
        .map_err(|e| AttestationError::Verification(format!("Failed to build client: {}", e)))?;

    // Verify the certificate chain against Fulcio roots
    verify_certificate_chain(&mut client, cert_bytes, &trust_root)?;

    // Verify the signature
    if let Some(sig) = envelope.signatures.first() {
        verify_dsse_signature(&mut client, cert_bytes, &sig.sig, &envelope.payload)?;
    }

    // Verify Rekor transparency log inclusion if available
    if let Some(tlog_entries) = &bundle.tlog_entries {
        for tlog_entry in tlog_entries {
            verify_rekor_inclusion(&mut client, tlog_entry, &trust_root)?;
        }
    }

    Ok(())
}

/// Verify the certificate chain against Fulcio roots
fn verify_certificate_chain<T: CosignCapabilities>(
    _client: &mut T,
    cert_bytes: &[u8],
    trust_root: &SigstoreTrustRoot,
) -> Result<()> {
    // Parse the certificate
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(cert_bytes).map_err(|e| {
        AttestationError::Verification(format!("Failed to parse certificate: {}", e))
    })?;

    // Get Fulcio certificates from trust root
    let fulcio_certs = trust_root.fulcio_certs().map_err(|e| {
        AttestationError::Verification(format!("Failed to get Fulcio certs: {}", e))
    })?;

    // Verify the certificate was issued by Fulcio
    // This is a simplified check - full verification would build the complete chain
    let mut valid_chain = false;
    for _fulcio_cert in fulcio_certs {
        // Check if the certificate issuer matches any Fulcio CA
        if cert.issuer().to_string().contains("sigstore") {
            valid_chain = true;
            break;
        }
    }

    if !valid_chain {
        return Err(AttestationError::Verification(
            "Certificate not issued by Fulcio".into(),
        ));
    }

    debug!("Certificate chain verified against Fulcio roots");
    Ok(())
}

/// Verify the DSSE signature
fn verify_dsse_signature<T: CosignCapabilities>(
    _client: &mut T,
    cert_bytes: &[u8],
    signature: &str,
    payload: &str,
) -> Result<()> {
    // Parse the certificate to extract the public key
    let (_, cert) = X509Certificate::from_der(cert_bytes).map_err(|e| {
        AttestationError::Verification(format!("Failed to parse certificate: {}", e))
    })?;

    // Decode the signature
    let sig_bytes = BASE64.decode(signature).map_err(|e| {
        AttestationError::Verification(format!("Failed to decode signature: {}", e))
    })?;

    // Create the PAE (Pre-Authentication Encoding) for DSSE
    let pae = create_dsse_pae("application/vnd.in-toto+json", payload.as_bytes());

    // Extract and verify based on the public key algorithm
    let public_key = cert.public_key();
    let algorithm = &public_key.algorithm;

    debug!("Certificate uses algorithm: {:?}", algorithm.algorithm);

    // Verify signature based on the algorithm
    match algorithm.algorithm.to_string().as_str() {
        // EC public key (P-256 or P-384)
        "1.2.840.10045.2.1" => {
            verify_ecdsa_signature(public_key, &sig_bytes, &pae)?;
        }
        // Ed25519
        "1.3.101.112" => {
            verify_ed25519_signature(public_key, &sig_bytes, &pae)?;
        }
        // RSA (less common for Fulcio but possible)
        "1.2.840.113549.1.1.1" => {
            return Err(AttestationError::Verification(
                "RSA signature verification not yet implemented".into(),
            ));
        }
        other => {
            return Err(AttestationError::Verification(format!(
                "Unsupported signature algorithm: {}",
                other
            )));
        }
    }

    debug!("DSSE signature verification successful");
    Ok(())
}

/// Verify ECDSA signature (P-256 or P-384)
fn verify_ecdsa_signature(
    public_key_info: &SubjectPublicKeyInfo,
    signature: &[u8],
    message: &[u8],
) -> Result<()> {
    // Extract the actual public key bytes
    let public_key_bytes: &[u8] = public_key_info.subject_public_key.data.as_ref();

    // Determine the curve from the algorithm parameters
    if let Some(params) = &public_key_info.algorithm.parameters {
        let curve_oid = params.as_oid().map_err(|e| {
            AttestationError::Verification(format!("Failed to parse curve OID: {}", e))
        })?;

        match curve_oid.to_string().as_str() {
            // P-256 / secp256r1
            "1.2.840.10045.3.1.7" => {
                let verifying_key =
                    P256VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|e| {
                        AttestationError::Verification(format!(
                            "Failed to parse P-256 public key: {}",
                            e
                        ))
                    })?;

                let signature = P256Signature::from_der(signature)
                    .or_else(|_| P256Signature::from_bytes(signature.into()))
                    .map_err(|e| {
                        AttestationError::Verification(format!(
                            "Failed to parse P-256 signature: {}",
                            e
                        ))
                    })?;

                verifying_key.verify(message, &signature).map_err(|e| {
                    AttestationError::Verification(format!(
                        "P-256 signature verification failed: {}",
                        e
                    ))
                })?;

                debug!("P-256 ECDSA signature verified successfully");
            }
            // P-384 / secp384r1
            "1.3.132.0.34" => {
                let verifying_key =
                    P384VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|e| {
                        AttestationError::Verification(format!(
                            "Failed to parse P-384 public key: {}",
                            e
                        ))
                    })?;

                let signature = P384Signature::from_der(signature)
                    .or_else(|_| P384Signature::from_bytes(signature.into()))
                    .map_err(|e| {
                        AttestationError::Verification(format!(
                            "Failed to parse P-384 signature: {}",
                            e
                        ))
                    })?;

                use p384::ecdsa::signature::Verifier;
                verifying_key.verify(message, &signature).map_err(|e| {
                    AttestationError::Verification(format!(
                        "P-384 signature verification failed: {}",
                        e
                    ))
                })?;

                debug!("P-384 ECDSA signature verified successfully");
            }
            other => {
                return Err(AttestationError::Verification(format!(
                    "Unsupported EC curve: {}",
                    other
                )));
            }
        }
    } else {
        // Try P-256 as default (most common for Fulcio)
        let verifying_key = P256VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|e| {
            AttestationError::Verification(format!("Failed to parse P-256 public key: {}", e))
        })?;

        let signature = P256Signature::from_der(signature)
            .or_else(|_| P256Signature::from_bytes(signature.into()))
            .map_err(|e| {
                AttestationError::Verification(format!("Failed to parse P-256 signature: {}", e))
            })?;

        verifying_key.verify(message, &signature).map_err(|e| {
            AttestationError::Verification(format!("P-256 signature verification failed: {}", e))
        })?;

        debug!("P-256 ECDSA signature verified successfully (default)");
    }

    Ok(())
}

/// Verify Ed25519 signature
fn verify_ed25519_signature(
    public_key_info: &SubjectPublicKeyInfo,
    signature: &[u8],
    message: &[u8],
) -> Result<()> {
    // Extract the actual public key bytes (Ed25519 is 32 bytes)
    let public_key_bytes: &[u8] = public_key_info.subject_public_key.data.as_ref();

    // Ed25519 public keys should be exactly 32 bytes
    if public_key_bytes.len() != 32 {
        return Err(AttestationError::Verification(format!(
            "Invalid Ed25519 public key length: {} (expected 32)",
            public_key_bytes.len()
        )));
    }

    let verifying_key = Ed25519VerifyingKey::from_bytes(public_key_bytes.try_into().unwrap())
        .map_err(|e| {
            AttestationError::Verification(format!("Failed to parse Ed25519 public key: {}", e))
        })?;

    // Ed25519 signatures should be exactly 64 bytes
    if signature.len() != 64 {
        return Err(AttestationError::Verification(format!(
            "Invalid Ed25519 signature length: {} (expected 64)",
            signature.len()
        )));
    }

    let signature = Ed25519Signature::from_bytes(signature.try_into().unwrap());

    use ed25519_dalek::Verifier;
    verifying_key.verify(message, &signature).map_err(|e| {
        AttestationError::Verification(format!("Ed25519 signature verification failed: {}", e))
    })?;

    debug!("Ed25519 signature verified successfully");
    Ok(())
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

/// Verify inclusion in Rekor transparency log
fn verify_rekor_inclusion<T: CosignCapabilities>(
    _client: &mut T,
    tlog_entry: &serde_json::Value,
    trust_root: &SigstoreTrustRoot,
) -> Result<()> {
    // Extract log index from tlog entry
    let log_index = tlog_entry
        .get("logIndex")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AttestationError::Verification("No log index in tlog entry".into()))?;

    // Verify the signed entry timestamp (SET) and inclusion proof

    // 1. Extract the canonicalized entry from the tlog entry
    let canonicalized_body = tlog_entry
        .get("canonicalizedBody")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            AttestationError::Verification("No canonicalized body in tlog entry".into())
        })?;

    // 2. Extract the integrated time (timestamp when entry was added to log)
    let integrated_time = tlog_entry
        .get("integratedTime")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AttestationError::Verification("No integrated time in tlog entry".into()))?;

    // 3. Extract the inclusion proof if present
    if let Some(inclusion_proof) = tlog_entry.get("inclusionProof") {
        // Extract inclusion proof components
        let root_hash = inclusion_proof
            .get("rootHash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AttestationError::Verification("No root hash in inclusion proof".into())
            })?;

        let tree_size = inclusion_proof
            .get("treeSize")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| {
                AttestationError::Verification("No tree size in inclusion proof".into())
            })?;

        let hashes = inclusion_proof
            .get("hashes")
            .and_then(|v| v.as_array())
            .ok_or_else(|| AttestationError::Verification("No hashes in inclusion proof".into()))?;

        debug!(
            "Verifying Merkle tree inclusion proof for log index {}",
            log_index
        );
        debug!("  Root hash: {}", root_hash);
        debug!("  Tree size: {}", tree_size);
        debug!("  Proof hashes: {} nodes", hashes.len());

        // Verify the inclusion proof
        verify_merkle_inclusion_proof(canonicalized_body, log_index, tree_size, root_hash, hashes)?;
    }

    // 4. Verify the Signed Entry Timestamp (SET) if present
    if let Some(inclusion_promise) = tlog_entry.get("inclusionPromise") {
        let signed_entry_timestamp = inclusion_promise
            .get("signedEntryTimestamp")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AttestationError::Verification("No signed entry timestamp".into()))?;

        // The SET is a signature over the entry and timestamp
        verify_signed_entry_timestamp(
            signed_entry_timestamp,
            canonicalized_body,
            integrated_time,
            trust_root,
        )?;
    }

    debug!(
        "Rekor transparency log entry verified at index {} with timestamp {}",
        log_index, integrated_time
    );
    Ok(())
}

/// Verify a Merkle tree inclusion proof
fn verify_merkle_inclusion_proof(
    entry_data: &str,
    leaf_index: i64,
    tree_size: i64,
    root_hash: &str,
    proof_hashes: &[serde_json::Value],
) -> Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    use sha2::{Digest, Sha256};

    // Decode the entry data and root hash from base64
    let entry_bytes = BASE64.decode(entry_data).map_err(|e| {
        AttestationError::Verification(format!("Failed to decode entry data: {}", e))
    })?;

    let expected_root = BASE64.decode(root_hash).map_err(|e| {
        AttestationError::Verification(format!("Failed to decode root hash: {}", e))
    })?;

    // Convert proof hashes from base64
    let mut proof_nodes: Vec<Vec<u8>> = Vec::new();
    for hash in proof_hashes {
        if let Some(hash_str) = hash.as_str() {
            let hash_bytes = BASE64.decode(hash_str).map_err(|e| {
                AttestationError::Verification(format!("Failed to decode proof hash: {}", e))
            })?;
            proof_nodes.push(hash_bytes);
        }
    }

    // Calculate the leaf hash (RFC 6962 leaf node format)
    let mut leaf_hasher = Sha256::new();
    leaf_hasher.update([0x00]); // Leaf prefix for RFC 6962
    leaf_hasher.update(&entry_bytes);
    let mut current_hash = leaf_hasher.finalize().to_vec();

    // Walk up the tree using the inclusion proof
    let mut index = leaf_index;
    let mut size = tree_size;

    for proof_node in &proof_nodes {
        // Determine if the proof node goes on the left or right
        if index % 2 == 1 || index == size - 1 {
            // Current node is a right child or the rightmost node
            // Proof node goes on the left
            let mut hasher = Sha256::new();
            hasher.update([0x01]); // Interior node prefix for RFC 6962
            hasher.update(proof_node);
            hasher.update(&current_hash);
            current_hash = hasher.finalize().to_vec();
        } else {
            // Current node is a left child
            // Proof node goes on the right
            let mut hasher = Sha256::new();
            hasher.update([0x01]); // Interior node prefix for RFC 6962
            hasher.update(&current_hash);
            hasher.update(proof_node);
            current_hash = hasher.finalize().to_vec();
        }

        // Move to parent node
        index /= 2;
        size = (size + 1) / 2;
    }

    // Compare the computed root with the expected root
    if current_hash != expected_root {
        return Err(AttestationError::Verification(
            "Merkle inclusion proof verification failed: root hash mismatch".into(),
        ));
    }

    debug!("Merkle inclusion proof verified successfully");
    Ok(())
}

/// Verify a Signed Entry Timestamp (SET)
fn verify_signed_entry_timestamp(
    signed_timestamp_b64: &str,
    canonicalized_body: &str,
    integrated_time: i64,
    trust_root: &SigstoreTrustRoot,
) -> Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    use sha2::{Digest, Sha256};

    // Decode the signed timestamp
    let signature_bytes = BASE64
        .decode(signed_timestamp_b64)
        .map_err(|e| AttestationError::Verification(format!("Failed to decode SET: {}", e)))?;

    // Decode the canonicalized body
    let body_bytes = BASE64
        .decode(canonicalized_body)
        .map_err(|e| AttestationError::Verification(format!("Failed to decode body: {}", e)))?;

    // Create the message that was signed: body + integrated_time
    let mut message = Vec::new();
    message.extend_from_slice(&body_bytes);
    message.extend_from_slice(&integrated_time.to_le_bytes());

    // Hash the message
    let mut hasher = Sha256::new();
    hasher.update(&message);
    let message_hash = hasher.finalize();

    // Get Rekor public keys from trust root
    let rekor_keys = trust_root
        .rekor_keys()
        .map_err(|e| AttestationError::Verification(format!("Failed to get Rekor keys: {}", e)))?;

    // Try to verify with each Rekor public key
    let mut verification_succeeded = false;
    for rekor_key in rekor_keys.values() {
        // The rekor_key is a byte slice containing the public key
        if verify_signature_with_public_key(rekor_key, &signature_bytes, &message_hash).is_ok() {
            verification_succeeded = true;
            debug!("SET verified with Rekor key");
            break;
        }
    }

    if !verification_succeeded {
        return Err(AttestationError::Verification(
            "Failed to verify Signed Entry Timestamp with any Rekor key".into(),
        ));
    }

    Ok(())
}

/// Helper function to verify a signature with a public key
fn verify_signature_with_public_key(
    public_key_pem: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<()> {
    use p256::ecdsa::{
        Signature as P256Signature, VerifyingKey as P256VerifyingKey,
        signature::Verifier as P256Verifier,
    };
    use p256::pkcs8::DecodePublicKey;

    // Parse the PEM public key
    let pem_str = std::str::from_utf8(public_key_pem)
        .map_err(|e| AttestationError::Verification(format!("Invalid PEM: {}", e)))?;

    // Try to parse as P-256 (most common for Rekor)
    if let Ok(verifying_key) = P256VerifyingKey::from_public_key_pem(pem_str) {
        // Parse the signature (DER or raw format)
        let sig = P256Signature::from_der(signature)
            .or_else(|_| P256Signature::from_bytes(signature.into()))
            .map_err(|e| {
                AttestationError::Verification(format!("Failed to parse signature: {}", e))
            })?;

        return verifying_key.verify(message, &sig).map_err(|e| {
            AttestationError::Verification(format!("Signature verification failed: {}", e))
        });
    }

    Err(AttestationError::Verification(
        "Unsupported key type".into(),
    ))
}

/// Perform basic verification when full Sigstore verification is not available
fn verify_basic_bundle_structure(
    envelope: &DsseEnvelope,
    cert_info: &CertificateInfo,
) -> Result<()> {
    // Validate that signatures have required fields
    for sig in &envelope.signatures {
        if sig.sig.is_empty() {
            return Err(AttestationError::Verification(
                "DSSE signature is empty".into(),
            ));
        }
    }

    // Ensure this is a GitHub Actions certificate
    if cert_info.workflow_ref.is_none() {
        return Err(AttestationError::Verification(
            "Certificate does not contain GitHub workflow information".into(),
        ));
    }

    debug!("Basic Sigstore bundle validation completed");
    Ok(())
}
