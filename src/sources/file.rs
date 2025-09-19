use crate::api::{Attestation, DsseEnvelope, Signature, SigstoreBundle};
use crate::sources::{ArtifactRef, AttestationSource};
use crate::{AttestationError, Result};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use std::path::{Path, PathBuf};
use tokio::fs;

/// File-based attestation source for loading attestations from local files
pub struct FileSource {
    /// Path to the attestation file or bundle
    attestation_path: PathBuf,
}

impl FileSource {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            attestation_path: path.as_ref().to_path_buf(),
        }
    }

    /// Load a Sigstore bundle from a file
    pub async fn load_bundle(&self) -> Result<serde_json::Value> {
        let content = fs::read_to_string(&self.attestation_path)
            .await
            .map_err(AttestationError::Io)?;

        serde_json::from_str(&content).map_err(AttestationError::Json)
    }

    /// Load a cosign signature from a .sig file
    pub async fn load_signature(&self) -> Result<Vec<u8>> {
        fs::read(&self.attestation_path)
            .await
            .map_err(AttestationError::Io)
    }
}

#[async_trait]
impl AttestationSource for FileSource {
    async fn fetch_attestations(&self, _artifact: &ArtifactRef) -> Result<Vec<Attestation>> {
        let content = fs::read_to_string(&self.attestation_path)
            .await
            .map_err(AttestationError::Io)?;

        // Try to parse each line as JSON (JSONL format)
        let mut attestations = Vec::new();

        // Handle both JSONL format (multiple lines) and single JSON object
        let lines: Vec<&str> = content.lines().collect();
        let lines = if lines.is_empty() && !content.trim().is_empty() {
            // Single JSON object without newline
            vec![content.trim()]
        } else {
            lines
        };

        for line in lines {
            if line.trim().is_empty() {
                continue;
            }

            log::trace!("Parsing line of length: {}", line.len());
            if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(line) {
                log::trace!(
                    "Successfully parsed JSON with keys: {:?}",
                    json_value.as_object().map(|o| o.keys().collect::<Vec<_>>())
                );
                // Check if this is a Sigstore Bundle v0.3 format
                if let (Some(media_type), Some(dsse_envelope)) =
                    (json_value.get("mediaType"), json_value.get("dsseEnvelope"))
                {
                    if media_type.as_str() == Some("application/vnd.dev.sigstore.bundle.v0.3+json")
                    {
                        // Parse the nested DSSE envelope
                        if let (Some(payload_type), Some(payload), Some(signatures)) = (
                            dsse_envelope.get("payloadType"),
                            dsse_envelope.get("payload"),
                            dsse_envelope.get("signatures"),
                        ) {
                            if payload_type.as_str() == Some("application/vnd.in-toto+json") {
                                let mut parsed_signatures = Vec::new();
                                if let Some(sig_array) = signatures.as_array() {
                                    for sig_obj in sig_array {
                                        let sig_string = sig_obj
                                            .get("sig")
                                            .and_then(|s| s.as_str())
                                            .unwrap_or("")
                                            .to_string();
                                        let keyid = sig_obj
                                            .get("keyid")
                                            .and_then(|k| k.as_str())
                                            .map(|s| s.to_string());

                                        parsed_signatures.push(Signature {
                                            sig: sig_string,
                                            keyid,
                                        });
                                    }
                                }

                                let bundle = SigstoreBundle {
                                    media_type: media_type.as_str().unwrap_or("").to_string(),
                                    dsse_envelope: DsseEnvelope {
                                        payload: payload.as_str().unwrap_or("").to_string(),
                                        payload_type: payload_type
                                            .as_str()
                                            .unwrap_or("")
                                            .to_string(),
                                        signatures: parsed_signatures,
                                    },
                                    verification_material: json_value
                                        .get("verificationMaterial")
                                        .cloned(),
                                };

                                let attestation = Attestation {
                                    bundle: Some(bundle),
                                    bundle_url: None,
                                };
                                attestations.push(attestation);
                                continue;
                            }
                        }
                    }
                }

                // Check if this is a DSSE envelope (SLSA provenance format)
                if let (Some(payload_type), Some(payload), Some(signatures)) = (
                    json_value.get("payloadType"),
                    json_value.get("payload"),
                    json_value.get("signatures"),
                ) {
                    if payload_type.as_str() == Some("application/vnd.in-toto+json") {
                        // This is a DSSE envelope, parse it into a SigstoreBundle
                        let mut parsed_signatures = Vec::new();
                        if let Some(sig_array) = signatures.as_array() {
                            for sig_obj in sig_array {
                                let sig_string = sig_obj
                                    .get("sig")
                                    .and_then(|s| s.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                let keyid = sig_obj
                                    .get("keyid")
                                    .and_then(|k| k.as_str())
                                    .map(|s| s.to_string());

                                parsed_signatures.push(Signature {
                                    sig: sig_string,
                                    keyid,
                                });
                            }
                        }

                        let bundle = SigstoreBundle {
                            media_type: "application/vnd.in-toto+json".to_string(),
                            dsse_envelope: DsseEnvelope {
                                payload: payload.as_str().unwrap_or("").to_string(),
                                payload_type: payload_type.as_str().unwrap_or("").to_string(),
                                signatures: parsed_signatures,
                            },
                            verification_material: None, // SLSA files typically don't have this
                        };

                        let attestation = Attestation {
                            bundle: Some(bundle),
                            bundle_url: None,
                        };
                        attestations.push(attestation);
                        continue;
                    }
                }

                // Check if this is a simple in-toto statement (alternative format)
                if let Some(type_field) = json_value.get("_type") {
                    let type_str = type_field.as_str().unwrap_or("");
                    if type_str.starts_with("https://in-toto.io/Statement/v") {
                        // This is a raw SLSA provenance statement, wrap it in DSSE
                        let bundle = SigstoreBundle {
                            media_type: "application/vnd.in-toto+json".to_string(),
                            dsse_envelope: DsseEnvelope {
                                payload: BASE64
                                    .encode(serde_json::to_string(&json_value)?.as_bytes()),
                                payload_type: "application/vnd.in-toto+json".to_string(),
                                signatures: vec![Signature {
                                    sig: "".to_string(), // Minimal signature for parsing
                                    keyid: None,
                                }],
                            },
                            verification_material: None,
                        };

                        let attestation = Attestation {
                            bundle: Some(bundle),
                            bundle_url: None,
                        };
                        attestations.push(attestation);
                        continue;
                    }
                }

                // Check if this is a traditional Cosign bundle format
                // This check must come before parsing as Attestation since traditional Cosign
                // JSON can be parsed as Attestation but with bundle=None
                if let (Some(_base64_sig), Some(_cert), Some(_rekor_bundle)) = (
                    json_value.get("base64Signature"),
                    json_value.get("cert"),
                    json_value.get("rekorBundle"),
                ) {
                    log::debug!("Found traditional Cosign bundle format");
                    // This is a traditional Cosign bundle, create a minimal DSSE envelope for compatibility
                    let bundle = SigstoreBundle {
                        media_type: "application/vnd.dev.sigstore.bundle+json;version=0.1"
                            .to_string(),
                        dsse_envelope: DsseEnvelope {
                            payload: "".to_string(), // Empty payload for traditional Cosign bundles
                            payload_type: "application/vnd.dev.sigstore.cosign".to_string(),
                            signatures: vec![Signature {
                                sig: "".to_string(), // Signature is in the rekor bundle
                                keyid: None,
                            }],
                        },
                        verification_material: Some(json_value.clone()), // Store the entire Cosign bundle as verification material
                    };

                    let attestation = Attestation {
                        bundle: Some(bundle),
                        bundle_url: None,
                    };
                    attestations.push(attestation);
                    continue;
                }

                // Try to parse as an existing attestation format
                if let Ok(attestation) = serde_json::from_value::<Attestation>(json_value.clone()) {
                    attestations.push(attestation);
                    continue;
                }

                // Try as a raw bundle format - convert JSON to SigstoreBundle
                if let Ok(bundle) = serde_json::from_value::<SigstoreBundle>(json_value) {
                    let attestation = Attestation {
                        bundle: Some(bundle),
                        bundle_url: None,
                    };
                    attestations.push(attestation);
                }
            }
        }

        if attestations.is_empty() {
            return Err(AttestationError::Verification(
                "File does not contain valid attestations or SLSA provenance".into(),
            ));
        }

        Ok(attestations)
    }

    fn source_type(&self) -> &'static str {
        "File"
    }
}
