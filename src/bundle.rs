pub use crate::api::DsseEnvelope;
use crate::api::Attestation;
use crate::{AttestationError, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::Value;

/// Parse and extract information from a Sigstore bundle
pub fn parse_bundle(attestation: &Attestation) -> Result<ParsedBundle> {
    let bundle = attestation
        .bundle
        .as_ref()
        .ok_or_else(|| AttestationError::Verification("No bundle found in attestation".into()))?;

    let payload = decode_payload(&bundle.dsse_envelope.payload)?;

    // Extract certificate if present
    let certificate = extract_certificate_from_bundle(attestation)?;

    // Extract tlog entries if present
    let tlog_entries = extract_tlog_entries_from_bundle(attestation)?;

    Ok(ParsedBundle {
        payload,
        dsse_envelope: Some(bundle.dsse_envelope.clone()),
        certificate,
        media_type: bundle.media_type.clone(),
        tlog_entries,
    })
}

/// Decode base64-encoded payload
fn decode_payload(payload: &str) -> Result<Vec<u8>> {
    BASE64
        .decode(payload)
        .map_err(|e| AttestationError::Verification(format!("Failed to decode payload: {}", e)))
}

/// Extract certificate from verification material
fn extract_certificate_from_bundle(attestation: &Attestation) -> Result<Option<String>> {
    let bundle = attestation.bundle.as_ref().ok_or_else(|| {
        AttestationError::Verification("No bundle found in attestation".into())
    })?;

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
fn extract_tlog_entries_from_bundle(attestation: &Attestation) -> Result<Option<Vec<serde_json::Value>>> {
    let bundle = attestation.bundle.as_ref().ok_or_else(|| {
        AttestationError::Verification("No bundle found in attestation".into())
    })?;

    if let Some(verification_material) = &bundle.verification_material {
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
            return Err(AttestationError::Verification(
                format!("Not an in-toto statement: {}", type_str)
            ));
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
}

#[derive(Debug, Clone)]
pub struct SlsaProvenance {
    pub predicate_type: String,
    pub workflow_ref: Option<String>,
}