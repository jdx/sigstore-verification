use sigstore_verification::{Result, verify_cosign_signature_with_key};
use std::path::Path;

#[tokio::main]
async fn main() -> Result<()> {
    // Example: Verify an artifact using a public key

    let artifact_path = Path::new("example_artifact.tar.gz");
    let signature_path = Path::new("example_artifact.sig");
    let public_key_path = Path::new("cosign.pub");

    // This example assumes you have:
    // 1. An artifact file (example_artifact.tar.gz)
    // 2. A signature file created with: cosign sign-blob --key cosign.key example_artifact.tar.gz > example_artifact.sig
    // 3. A public key file (cosign.pub)

    match verify_cosign_signature_with_key(artifact_path, signature_path, public_key_path).await {
        Ok(true) => {
            println!("✅ Signature verification successful!");
            println!("The artifact has been verified with the provided public key.");
        }
        Ok(false) => {
            println!("❌ Signature verification returned false");
        }
        Err(e) => {
            println!("❌ Signature verification failed: {}", e);
        }
    }

    // Example: Create a verifier with an inline PEM key
    use sigstore_verification::sources::file::FileSource;
    use sigstore_verification::verifiers::cosign::CosignVerifier;
    use sigstore_verification::verify_artifact;

    let pem_key = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE... (your key here)
-----END PUBLIC KEY-----"#;

    let verifier = CosignVerifier::new_with_key_string(pem_key);
    let source = FileSource::new(signature_path);

    match verify_artifact(artifact_path, &source, &verifier, None).await {
        Ok(result) => {
            if result.success {
                println!("✅ Inline PEM key verification successful!");
                for msg in &result.messages {
                    println!("  - {}", msg);
                }
            } else {
                println!("❌ Verification failed");
            }
        }
        Err(e) => {
            println!("❌ Error during verification: {}", e);
        }
    }

    Ok(())
}
