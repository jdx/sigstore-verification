//! Tests that `verify_github_attestation_with_base_url` routes API calls to
//! the configured host (e.g. a GitHub Enterprise Server) instead of
//! `api.github.com`.

use mockito::Server;
use sigstore_verification::{AttestationError, verify_github_attestation_with_base_url};
use std::io::Write;
use tempfile::NamedTempFile;

#[tokio::test]
async fn test_verify_with_base_url_queries_custom_host() {
    let mut server = Server::new_async().await;

    // The artifact digest depends on the file contents, so match any digest
    // path rather than precomputing it.
    let mock = server
        .mock(
            "GET",
            mockito::Matcher::Regex(r"^/repos/owner/repo/attestations/sha256:.+$".into()),
        )
        .match_query(mockito::Matcher::Any)
        .match_header("authorization", "Bearer ghes-token")
        .match_header("x-github-api-version", "2022-11-28")
        .with_status(200)
        .with_body(r#"{"attestations":[]}"#)
        .create_async()
        .await;

    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(b"test artifact contents").unwrap();
    tmp.flush().unwrap();

    let result = verify_github_attestation_with_base_url(
        tmp.path(),
        "owner",
        "repo",
        Some("ghes-token"),
        None,
        &server.url(),
    )
    .await;

    // No attestations in the mocked response — the function should report
    // `NoAttestations`, but critically it must have hit the custom host.
    assert!(matches!(result, Err(AttestationError::NoAttestations)));
    mock.assert_async().await;
}
