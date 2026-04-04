use mockito::Server;
use sigstore_verification::AttestationClient;
use sigstore_verification::FetchParams;

#[test]
fn test_builder_default_base_url() {
    let client = AttestationClient::builder().build().unwrap();
    // Should succeed without any configuration
    assert!(format!("{:?}", client).contains("api.github.com"));
}

#[test]
fn test_builder_custom_base_url() {
    let client = AttestationClient::builder()
        .base_url("https://my-proxy.internal/github")
        .build()
        .unwrap();
    assert!(format!("{:?}", client).contains("my-proxy.internal"));
}

#[test]
fn test_builder_strips_trailing_slash() {
    let client = AttestationClient::builder()
        .base_url("https://my-proxy.internal/github/")
        .build()
        .unwrap();
    let debug = format!("{:?}", client);
    assert!(debug.contains("my-proxy.internal/github\""));
    assert!(!debug.contains("github/\""));
}

#[test]
fn test_new_delegates_to_builder() {
    let client = AttestationClient::new(Some("test-token")).unwrap();
    let debug = format!("{:?}", client);
    assert!(debug.contains("api.github.com"));
    assert!(debug.contains("test-token"));
}

#[tokio::test]
async fn test_custom_base_url_sends_requests_to_configured_host() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/repos/owner/repo/attestations/sha256:abc123")
        .match_query(mockito::Matcher::UrlEncoded("per_page".into(), "10".into()))
        .match_header("x-github-api-version", "2022-11-28")
        .match_header("authorization", "Bearer test-token")
        .with_status(200)
        .with_body(r#"{"attestations":[]}"#)
        .create_async()
        .await;

    let client = AttestationClient::builder()
        .base_url(&server.url())
        .github_token("test-token")
        .build()
        .unwrap();

    let params = FetchParams {
        owner: "owner".to_string(),
        repo: Some("owner/repo".to_string()),
        digest: "sha256:abc123".to_string(),
        limit: 10,
        predicate_type: None,
    };

    let result = client.fetch_attestations(params).await.unwrap();
    assert!(result.is_empty());
    mock.assert_async().await;
}

#[tokio::test]
async fn test_auth_headers_not_sent_to_different_host() {
    let mut api_server = Server::new_async().await;
    let mut other_server = Server::new_async().await;

    // The API server returns an attestation with a bundle_url pointing to a different host
    let bundle_url = format!("{}/bundle", other_server.url());
    let api_mock = api_server
        .mock("GET", "/repos/owner/repo/attestations/sha256:abc123")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_body(format!(
            r#"{{"attestations":[{{"bundle":null,"bundle_url":"{}"}}]}}"#,
            bundle_url
        ))
        .create_async()
        .await;

    // The other server should NOT receive auth headers
    let bundle_mock = other_server
        .mock("GET", "/bundle")
        .match_header("authorization", mockito::Matcher::Missing)
        .match_header("x-github-api-version", mockito::Matcher::Missing)
        .with_status(200)
        .with_body(
            r#"{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","dsseEnvelope":{"payload":"dGVzdA==","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"dGVzdA=="}]}}"#,
        )
        .create_async()
        .await;

    let client = AttestationClient::builder()
        .base_url(&api_server.url())
        .github_token("secret-token")
        .build()
        .unwrap();

    let params = FetchParams {
        owner: "owner".to_string(),
        repo: Some("owner/repo".to_string()),
        digest: "sha256:abc123".to_string(),
        limit: 10,
        predicate_type: None,
    };

    let result = client.fetch_attestations(params).await.unwrap();
    assert_eq!(result.len(), 1);
    api_mock.assert_async().await;
    bundle_mock.assert_async().await;
}
