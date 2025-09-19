// Example demonstrating Rekor transparency log verification
//
// This example shows how the library verifies inclusion in Rekor transparency logs,
// including:
// - Merkle tree inclusion proofs
// - Signed Entry Timestamps (SET)
// - Integration with Sigstore trust roots

use sigstore_verification::{Result, verify_github_attestation};
use std::path::Path;

#[tokio::main]
async fn main() -> Result<()> {
    // Example: Verify a GitHub attestation which includes Rekor transparency log entries

    println!("🔍 Rekor Transparency Log Verification Example\n");
    println!("When verifying GitHub attestations, the library automatically:");
    println!("1. Extracts tlog entries from the verification material");
    println!("2. Verifies the Merkle tree inclusion proof");
    println!("3. Validates the Signed Entry Timestamp (SET)");
    println!("4. Confirms the entry was recorded in Rekor at the claimed time\n");

    // Example artifact path (would be a real file in practice)
    let artifact_path = Path::new("example_artifact.tar.gz");

    // For GitHub attestations with Rekor entries
    let owner = "example-org";
    let repo = "example-repo";

    println!("Attempting to verify artifact with Rekor transparency log...");

    match verify_github_attestation(
        artifact_path,
        owner,
        repo,
        None, // No token for public repos
        None, // No specific workflow requirement
    )
    .await
    {
        Ok(true) => {
            println!("\n✅ Verification successful!");
            println!("The artifact has been verified including:");
            println!("  • Certificate chain validation (Fulcio)");
            println!("  • DSSE signature verification");
            println!("  • Rekor transparency log inclusion proof");
            println!("  • Signed Entry Timestamp validation");
        }
        Ok(false) => {
            println!("\n❌ Verification failed");
        }
        Err(e) => {
            println!("\n❌ Error during verification: {}", e);
            println!("\nNote: This example requires a real artifact with attestations.");
            println!("In production, the Rekor verification happens automatically as part");
            println!("of the full Sigstore verification process.");
        }
    }

    println!("\n📝 Implementation Details:");
    println!("The Rekor verification includes:");
    println!("- RFC 6962 Merkle tree verification");
    println!("- Cryptographic verification of SET using Rekor public keys");
    println!("- Validation of integrated timestamps");
    println!("- Full chain of trust from Sigstore trust root");

    Ok(())
}
