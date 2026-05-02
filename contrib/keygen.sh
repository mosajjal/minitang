#!/bin/sh
# Generate a Tang-compatible JWK keyset (one signing key + one exchange key)
# in the directory passed as $1. Requires `jose` (cryptsetup-jose / latchset/jose).
#
# Usage: minitang-keygen /var/db/minitang
set -eu

dir="${1:?usage: minitang-keygen <keydir>}"
mkdir -p "$dir"
cd "$dir"

if ! command -v jose >/dev/null 2>&1; then
    echo "minitang-keygen: 'jose' binary not found in PATH" >&2
    echo "  install latchset/jose (https://github.com/latchset/jose)" >&2
    exit 1
fi

umask 077
sig=$(jose jwk gen -i '{"alg":"ES512"}' -o "tmp.jwk" && \
      jose jwk thp -i tmp.jwk)
mv tmp.jwk "${sig}.jwk"

ex=$(jose jwk gen -i '{"alg":"ECMR"}' -o "tmp.jwk" && \
     jose jwk thp -i tmp.jwk)
mv tmp.jwk "${ex}.jwk"

echo "wrote ${sig}.jwk (signing) and ${ex}.jwk (exchange) to $dir"
