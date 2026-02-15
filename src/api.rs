use crate::{AttestationError, Result};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};

const GITHUB_API_URL: &str = "https://api.github.com";
const USER_AGENT_VALUE: &str = "mise-attestation/0.1.0";

#[derive(Debug, Clone)]
pub struct AttestationClient {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Debug, Serialize)]
pub struct FetchParams {
    pub owner: String,
    pub repo: Option<String>,
    pub digest: String,
    pub limit: usize,
    pub predicate_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AttestationsResponse {
    pub attestations: Vec<Attestation>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Attestation {
    pub bundle: Option<SigstoreBundle>,
    pub bundle_url: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SigstoreBundle {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    #[serde(rename = "dsseEnvelope")]
    pub dsse_envelope: DsseEnvelope,
    #[serde(rename = "verificationMaterial")]
    pub verification_material: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DsseEnvelope {
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<Signature>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Signature {
    pub sig: String,
    pub keyid: Option<String>,
}

impl AttestationClient {
    pub fn new(token: Option<&str>) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));

        if let Some(token) = token {
            let auth_value = format!("Bearer {}", token);
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&auth_value)
                    .map_err(|e| AttestationError::Api(e.to_string()))?,
            );
        }

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()?;

        Ok(Self {
            client,
            base_url: GITHUB_API_URL.to_string(),
        })
    }

    pub async fn fetch_attestations(&self, params: FetchParams) -> Result<Vec<Attestation>> {
        let url = if let Some(repo) = &params.repo {
            format!(
                "{}/repos/{}/attestations/{}",
                self.base_url, repo, params.digest
            )
        } else {
            format!(
                "{}/orgs/{}/attestations/{}",
                self.base_url, params.owner, params.digest
            )
        };

        let mut query_params = vec![("per_page", params.limit.to_string())];
        if let Some(predicate_type) = &params.predicate_type {
            query_params.push(("predicate_type", predicate_type.clone()));
        }

        let response = self.client.get(&url).query(&query_params).send().await?;

        if !response.status().is_success() {
            let status = response.status();

            // 404 means no attestations exist for this artifact
            if status == reqwest::StatusCode::NOT_FOUND {
                return Ok(Vec::new());
            }

            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AttestationError::Api(format!(
                "GitHub API returned {}: {}",
                status, body
            )));
        }

        let attestations_response: AttestationsResponse = response.json().await?;

        // Download bundles if only URLs are provided
        let mut attestations = Vec::new();
        for att in attestations_response.attestations {
            if att.bundle.is_some() {
                attestations.push(att);
            } else if let Some(bundle_url) = &att.bundle_url {
                // Download the bundle
                let bundle_response = self.client.get(bundle_url).send().await?;
                if bundle_response.status().is_success() {
                    let headers = bundle_response.headers().clone();
                    let bundle: SigstoreBundle = if headers
                        .get("content-type")
                        .and_then(|h| h.to_str().ok())
                        .map(|s| s.contains("application/x-snappy"))
                        .unwrap_or(false)
                    {
                        let bytes = bundle_response.bytes().await?;
                        let decompressed = decompress_snappy(&bytes)?;
                        serde_json::from_slice(&decompressed)?
                    } else {
                        bundle_response.json().await?
                    };

                    attestations.push(Attestation {
                        bundle: Some(bundle),
                        bundle_url: att.bundle_url.clone(),
                    });
                }
            }
        }

        Ok(attestations)
    }
}

fn decompress_snappy(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = snap::raw::Decoder::new();
    decoder
        .decompress_vec(bytes)
        .map_err(|e| AttestationError::Api(format!("Snappy decompression failed: {}", e)))
}
