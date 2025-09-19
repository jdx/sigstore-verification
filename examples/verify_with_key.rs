// Example demonstrating key-based Cosign verification
//
// This example shows how to verify a Cosign signature using a public key,
// which is the traditional approach (as opposed to keyless verification with Fulcio).
//
// To create test files for this example:
// 1. Generate a key pair: `cosign generate-key-pair`
// 2. Sign an artifact: `cosign sign-blob --key cosign.key artifact.txt > artifact.sig`
// 3. Run this example with the artifact, signature, and public key

use sigstore_verification::{Result, verify_cosign_signature_with_key};
use std::env;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<()> {
    // Get command line arguments
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        eprintln!("Usage: {} <artifact> <signature> <public_key>", args[0]);
        eprintln!("\nExample:");
        eprintln!("  {} artifact.txt artifact.sig cosign.pub", args[0]);
        eprintln!("\nTo create test files:");
        eprintln!("  1. Generate keys: cosign generate-key-pair");
        eprintln!(
            "  2. Sign artifact: cosign sign-blob --key cosign.key artifact.txt > artifact.sig"
        );
        std::process::exit(1);
    }

    let artifact_path = Path::new(&args[1]);
    let signature_path = Path::new(&args[2]);
    let public_key_path = Path::new(&args[3]);

    println!("🔍 Verifying artifact: {:?}", artifact_path);
    println!("📝 Using signature: {:?}", signature_path);
    println!("🔑 With public key: {:?}", public_key_path);
    println!();

    match verify_cosign_signature_with_key(artifact_path, signature_path, public_key_path).await {
        Ok(true) => {
            println!("✅ Verification successful!");
            println!("The artifact signature is valid and was signed with the provided key.");
        }
        Ok(false) => {
            println!("❌ Verification failed!");
            println!(
                "The signature does not match the artifact or was not signed with the provided key."
            );
            std::process::exit(1);
        }
        Err(e) => {
            println!("❌ Error during verification: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
