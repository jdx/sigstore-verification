# Sigstore Verification

A Rust library for verifying software artifact signatures and attestations using Sigstore, Cosign, and SLSA standards.

## Features

- **GitHub Artifact Attestations**: Verify artifacts built by GitHub Actions workflows
- **Cosign Signatures**: Support for both keyless (Fulcio) and key-based verification
- **SLSA Provenance**: Verify SLSA provenance with configurable security levels
- **Rekor Transparency Log**: Full support for verifying inclusion proofs and signed entry timestamps
- **Modular Architecture**: Extensible design with traits for sources and verifiers

## Architecture

### Sources
- `GitHubSource`: Fetch attestations from GitHub's API
- `FileSource`: Load attestations from local files
- `OciSource`: (Planned) Fetch from OCI registries

### Verifiers
- `CosignVerifier`: Cosign-compatible signature verification
- `SlsaVerifier`: SLSA provenance verification
- `GitHubVerifier`: GitHub-specific attestation verification

## Usage

### GitHub Attestations
```rust
use sigstore_verification::verify_github_attestation;

let verified = verify_github_attestation(
    &artifact_path,
    "owner",
    "repo",
    Some(token),
    Some("release.yml"),
).await?;
```

### Cosign Verification

#### Keyless (Fulcio)
```rust
use sigstore_verification::verify_cosign_signature;

let verified = verify_cosign_signature(
    &artifact_path,
    &bundle_path,
).await?;
```

#### With Public Key
```rust
use sigstore_verification::verify_cosign_signature_with_key;

let verified = verify_cosign_signature_with_key(
    &artifact_path,
    &signature_path,
    &public_key_path,
).await?;
```

### SLSA Provenance
```rust
use sigstore_verification::verify_slsa_provenance;

let verified = verify_slsa_provenance(
    &artifact_path,
    &provenance_path,
    2, // Minimum SLSA level
).await?;
```

## Integration with mise

This crate is used by mise's aqua backend to provide native Rust verification of software artifacts. It completely replaces external CLI tools like `cosign`, `slsa-verifier`, and `gh attestation verify`.

### Benefits
- No external dependencies on CLI tools
- Faster verification (no process spawning)
- Better error handling and debugging
- Consistent behavior across platforms

## Security Features

- **X.509 Certificate Validation**: Verifies Fulcio-issued certificates
- **DSSE Signature Verification**: Supports P-256, P-384, and Ed25519 algorithms
- **Merkle Tree Verification**: RFC 6962 compliant inclusion proof verification
- **Signed Entry Timestamps**: Verifies Rekor transparency log timestamps
- **Trust Root Integration**: Uses Sigstore's official trust root

## Dependencies

- `sigstore`: Official Sigstore Rust library
- `p256`, `p384`, `ed25519-dalek`: Cryptographic primitives
- `x509-parser`: X.509 certificate parsing
- `reqwest`: HTTP client for API calls
- `tokio`: Async runtime

## License

MIT