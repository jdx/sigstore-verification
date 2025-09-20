#!/usr/bin/env bash
set -uo pipefail

# Verify that OpenSSL is not a dependency when using rustls features

FEATURE="${1:-rustls-native-roots}"

echo "Checking if OpenSSL is a dependency with feature: $FEATURE"

OUTPUT=$(cargo tree --no-default-features --features "$FEATURE" -i openssl 2>&1 || true)

if echo "$OUTPUT" | grep -q "error: package ID specification"; then
  echo "✅ $FEATURE build has no OpenSSL dependency"
  exit 0
else
  echo "❌ ERROR: OpenSSL is still a dependency when using $FEATURE feature!"
  echo "Dependencies that pull in OpenSSL:"
  echo "$OUTPUT"
  exit 1
fi