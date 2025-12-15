use crate::api::Attestation;
pub use crate::api::DsseEnvelope;
use crate::{AttestationError, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value;

/// Parse and extract information from a Sigstore bundle
pub fn parse_bundle(attestation: &Attestation) -> Result<ParsedBundle> {
    let bundle = attestation
        .bundle
        .as_ref()
        .ok_or_else(|| AttestationError::Verification("No bundle found in attestation".into()))?;

    // Extract certificate and tlog entries (common to all formats)
    let certificate = extract_certificate_from_bundle(attestation)?;
    let tlog_entries = extract_tlog_entries_from_bundle(attestation)?;

    // Check if this is a message signature bundle (cosign v3 direct blob signing)
    if let Some(message_signature) = &bundle.message_signature {
        return Ok(ParsedBundle {
            payload: Vec::new(), // No SLSA payload for message signature bundles
            dsse_envelope: None,
            certificate,
            media_type: bundle.media_type.clone(),
            tlog_entries,
            message_signature: Some(crate::api::MessageSignature {
                message_digest: crate::api::MessageDigest {
                    algorithm: message_signature.message_digest.algorithm.clone(),
                    digest: message_signature.message_digest.digest.clone(),
                },
                signature: message_signature.signature.clone(),
            }),
        });
    }

    // Check if we have a DSSE envelope
    if let Some(dsse_envelope) = &bundle.dsse_envelope {
        // Check if this is a traditional Cosign bundle (empty payload in DSSE envelope, verification material contains the bundle)
        if dsse_envelope.payload.is_empty()
            && dsse_envelope.payload_type == "application/vnd.dev.sigstore.cosign"
            && bundle.verification_material.is_some()
        {
            // Traditional Cosign bundle - extract what we can
            return Ok(ParsedBundle {
                payload: Vec::new(), // No SLSA payload for traditional Cosign bundles
                dsse_envelope: Some(dsse_envelope.clone()),
                certificate,
                media_type: bundle.media_type.clone(),
                tlog_entries,
                message_signature: None,
            });
        }

        // Standard DSSE envelope processing
        let payload = decode_payload(&dsse_envelope.payload)?;

        return Ok(ParsedBundle {
            payload,
            dsse_envelope: Some(dsse_envelope.clone()),
            certificate,
            media_type: bundle.media_type.clone(),
            tlog_entries,
            message_signature: None,
        });
    }

    // No valid format found
    Err(AttestationError::Verification(
        "Bundle has neither DSSE envelope nor message signature".into(),
    ))
}

/// Decode base64-encoded payload
fn decode_payload(payload: &str) -> Result<Vec<u8>> {
    BASE64
        .decode(payload)
        .map_err(|e| AttestationError::Verification(format!("Failed to decode payload: {}", e)))
}

/// Extract certificate from verification material
fn extract_certificate_from_bundle(attestation: &Attestation) -> Result<Option<String>> {
    let bundle = attestation
        .bundle
        .as_ref()
        .ok_or_else(|| AttestationError::Verification("No bundle found in attestation".into()))?;

    if let Some(verification_material) = &bundle.verification_material {
        if let Some(cert) = verification_material.get("certificate") {
            if let Some(raw_bytes) = cert.get("rawBytes") {
                if let Some(cert_str) = raw_bytes.as_str() {
                    return Ok(Some(cert_str.to_string()));
                }
            }
        }
    }

    Ok(None)
}

/// Extract tlog entries from verification material
fn extract_tlog_entries_from_bundle(
    attestation: &Attestation,
) -> Result<Option<Vec<serde_json::Value>>> {
    let bundle = attestation
        .bundle
        .as_ref()
        .ok_or_else(|| AttestationError::Verification("No bundle found in attestation".into()))?;

    if let Some(verification_material) = &bundle.verification_material {
        // Handle traditional Cosign bundle format
        if let Some(rekor_bundle) = verification_material.get("rekorBundle") {
            return Ok(Some(vec![rekor_bundle.clone()]));
        }

        // Handle modern Sigstore bundle format
        if let Some(tlog_entries) = verification_material.get("tlogEntries") {
            if let Some(tlog_array) = tlog_entries.as_array() {
                return Ok(Some(tlog_array.clone()));
            }
        }
    }

    Ok(None)
}

/// Parse the payload to extract SLSA provenance information
pub fn parse_slsa_provenance(payload: &[u8]) -> Result<SlsaProvenance> {
    let statement: Value = serde_json::from_slice(payload)
        .map_err(|e| AttestationError::Verification(format!("Failed to parse payload: {}", e)))?;

    // Check if it's an in-toto statement (accept both v0.1 and v1)
    if let Some(type_field) = statement.get("_type") {
        let type_str = type_field.as_str().unwrap_or("");
        if !type_str.starts_with("https://in-toto.io/Statement/v") {
            return Err(AttestationError::Verification(format!(
                "Not an in-toto statement: {}",
                type_str
            )));
        }
    }

    // Extract predicate type
    let predicate_type = statement
        .get("predicateType")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AttestationError::Verification("Missing predicateType".into()))?;

    if !predicate_type.starts_with("https://slsa.dev/provenance/") {
        return Err(AttestationError::Verification(format!(
            "Not a SLSA provenance statement: {}",
            predicate_type
        )));
    }

    // Extract workflow information from predicate
    let predicate = statement
        .get("predicate")
        .ok_or_else(|| AttestationError::Verification("Missing predicate".into()))?;

    let workflow_ref = extract_workflow_ref(predicate)?;

    Ok(SlsaProvenance {
        predicate_type: predicate_type.to_string(),
        workflow_ref,
    })
}

/// Extract workflow reference from SLSA predicate
fn extract_workflow_ref(predicate: &Value) -> Result<Option<String>> {
    // Try v1 format
    if let Some(build_def) = predicate.get("buildDefinition") {
        if let Some(ext_params) = build_def.get("externalParameters") {
            if let Some(workflow) = ext_params.get("workflow") {
                if let Some(path) = workflow.get("path") {
                    if let Some(path_str) = path.as_str() {
                        return Ok(Some(path_str.to_string()));
                    }
                }
            }
        }
    }

    // Try v0.2 format
    if let Some(invocation) = predicate.get("invocation") {
        if let Some(config_source) = invocation.get("configSource") {
            if let Some(path) = config_source.get("entryPoint") {
                if let Some(path_str) = path.as_str() {
                    return Ok(Some(path_str.to_string()));
                }
            }
        }
    }

    Ok(None)
}

#[derive(Debug)]
pub struct ParsedBundle {
    pub payload: Vec<u8>,
    pub dsse_envelope: Option<DsseEnvelope>,
    pub certificate: Option<String>,
    pub media_type: String,
    pub tlog_entries: Option<Vec<serde_json::Value>>,
    /// Message signature for direct blob signing (cosign v3 format)
    pub message_signature: Option<crate::api::MessageSignature>,
}

#[derive(Debug, Clone)]
pub struct SlsaProvenance {
    pub predicate_type: String,
    pub workflow_ref: Option<String>,
}
