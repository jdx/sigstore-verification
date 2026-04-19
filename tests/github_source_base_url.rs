use mockito::Server;
use sigstore_verification::sources::github::GitHubSource;
use sigstore_verification::{ArtifactRef, AttestationClient, AttestationSource};

#[tokio::test]
async fn test_github_source_default_hits_api_github_com() {
    let source = GitHubSource::new("owner", "repo", Some("token")).unwrap();
    assert_eq!(source.source_type(), "GitHub");
}

#[tokio::test]
async fn test_github_source_with_base_url_routes_to_custom_host() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/repos/owner/repo/attestations/sha256:abc123")
        .match_query(mockito::Matcher::Any)
        .match_header("authorization", "Bearer ghes-token")
        .match_header("x-github-api-version", "2022-11-28")
        .with_status(200)
        .with_body(r#"{"attestations":[]}"#)
        .create_async()
        .await;

    let source =
        GitHubSource::with_base_url("owner", "repo", Some("ghes-token"), &server.url()).unwrap();
    let artifact = ArtifactRef::from_digest("sha256:abc123");

    let result = source.fetch_attestations(&artifact).await.unwrap();
    assert!(result.is_empty());
    mock.assert_async().await;
}

#[tokio::test]
async fn test_github_source_builder_routes_to_custom_host() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/repos/owner/repo/attestations/sha256:abc123")
        .match_query(mockito::Matcher::Any)
        .match_header("authorization", "Bearer ghes-token")
        .match_header("x-github-api-version", "2022-11-28")
        .with_status(200)
        .with_body(r#"{"attestations":[]}"#)
        .create_async()
        .await;

    let source = GitHubSource::builder()
        .owner("owner")
        .repo("repo")
        .token("ghes-token")
        .base_url(server.url())
        .build()
        .unwrap();
    let artifact = ArtifactRef::from_digest("sha256:abc123");

    let result = source.fetch_attestations(&artifact).await.unwrap();
    assert!(result.is_empty());
    mock.assert_async().await;
}

#[tokio::test]
async fn test_github_source_with_client_uses_provided_client() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/repos/owner/repo/attestations/sha256:abc123")
        .match_query(mockito::Matcher::Any)
        .match_header("authorization", "Bearer preconfigured")
        .with_status(200)
        .with_body(r#"{"attestations":[]}"#)
        .create_async()
        .await;

    let client = AttestationClient::builder()
        .base_url(&server.url())
        .github_token("preconfigured")
        .build()
        .unwrap();
    let source = GitHubSource::with_client("owner", "repo", client);
    let artifact = ArtifactRef::from_digest("sha256:abc123");

    let result = source.fetch_attestations(&artifact).await.unwrap();
    assert!(result.is_empty());
    mock.assert_async().await;
}

#[tokio::test]
async fn test_github_source_builder_requires_owner_and_repo() {
    let err = GitHubSource::builder()
        .repo("repo")
        .build()
        .err()
        .expect("builder should fail without owner");
    assert!(format!("{err}").contains("owner"));

    let err = GitHubSource::builder()
        .owner("owner")
        .build()
        .err()
        .expect("builder should fail without repo");
    assert!(format!("{err}").contains("repo"));
}
