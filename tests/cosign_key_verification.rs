use sigstore_verification::verifiers::cosign::CosignVerifier;
use sigstore_verification::{Result, Verifier};
use tempfile::TempDir;
use tokio::fs;

#[tokio::test]
async fn test_cosign_key_verification_with_pem() -> Result<()> {
    // Create a test directory
    let temp_dir = TempDir::new().unwrap();
    let dir_path = temp_dir.path();

    // Create a test artifact
    let artifact_path = dir_path.join("test_artifact.txt");
    fs::write(&artifact_path, b"Hello, World!").await?;

    // Example P-256 public key in PEM format (this is a test key)
    let public_key_pem = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqF3TxXEIhqn6W8aJi/GyQF5JQSDL
Hp6U5m9IN5+tXR2hWREDS3HXYhdE8kjqxiKI0/KCVDbHnJqlGUEx+1vQ6w==
-----END PUBLIC KEY-----"#;

    let public_key_path = dir_path.join("cosign.pub");
    fs::write(&public_key_path, public_key_pem).await?;

    // Create a mock signature file (would normally be created by cosign)
    // This is just a placeholder - real test would need actual signature
    let signature_path = dir_path.join("test_artifact.sig");
    let mock_signature = base64_encode(vec![0u8; 64]); // Mock signature data
    fs::write(&signature_path, mock_signature).await?;

    // Test 1: Load key from file
    let verifier = CosignVerifier::new_with_key_file(&public_key_path).await?;
    assert!(!verifier.keyless);
    assert!(verifier.public_key.is_some());

    // Test 2: Load key from string
    let verifier2 = CosignVerifier::new_with_key_string(public_key_pem);
    assert!(!verifier2.keyless);
    assert!(verifier2.public_key.is_some());

    // Test 3: Verify the verifier type
    assert_eq!(verifier.verifier_type(), "Cosign-Key");
    assert_eq!(verifier2.verifier_type(), "Cosign-Key");

    // Note: Actual signature verification would fail with mock data
    // In a real test, we'd need a properly signed artifact

    Ok(())
}

#[tokio::test]
async fn test_cosign_keyless_verifier() {
    let verifier = CosignVerifier::new_keyless();
    assert!(verifier.keyless);
    assert!(verifier.public_key.is_none());
    assert_eq!(verifier.verifier_type(), "Cosign-Keyless");
}

#[tokio::test]
async fn test_cosign_with_raw_key_bytes() {
    // Test with raw Ed25519 public key (32 bytes)
    let ed25519_key = vec![0u8; 32];
    let verifier = CosignVerifier::new_with_key(ed25519_key);
    assert!(!verifier.keyless);
    assert!(verifier.public_key.is_some());
    assert_eq!(verifier.public_key.unwrap().len(), 32);
}

fn base64_encode(data: Vec<u8>) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(data)
}
