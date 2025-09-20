#!/usr/bin/env bash
set -euo pipefail

# Verify that OpenSSL is not a dependency when using rustls features

FEATURE="${1:-rustls-native-roots}"

echo "Checking if OpenSSL is a dependency with feature: $FEATURE"

# We expect this command to fail with "error: package ID specification" if openssl is not found (which is good)
# Use || true to prevent set -e from exiting on the expected failure
OUTPUT=$(cargo tree --no-default-features --features "$FEATURE" -i openssl 2>&1 || true)

if echo "$OUTPUT" | grep -q "error: package ID specification"; then
  echo "✅ $FEATURE build has no OpenSSL dependency"
  exit 0
elif echo "$OUTPUT" | grep -q "openssl"; then
  # If we find openssl in the output (and it's not the error message), it IS a dependency
  echo "❌ ERROR: OpenSSL is still a dependency when using $FEATURE feature!"
  echo "Dependencies that pull in OpenSSL:"
  echo "$OUTPUT"
  exit 1
else
  # Unexpected output - show it for debugging
  echo "⚠️ Unexpected output from cargo tree:"
  echo "$OUTPUT"
  exit 1
fi