#!/usr/bin/env bash
# Download the Tailwind CLI and regenerate static/css/tailwind.css from templates.
# Run this after adding new Tailwind classes to any template.
set -euo pipefail

TAILWIND_VERSION="v4.3.0"
BINARY="/tmp/tailwindcss-${TAILWIND_VERSION}"

if [[ ! -x "$BINARY" ]]; then
  echo "Downloading Tailwind CLI ${TAILWIND_VERSION}..."
  curl -fsSL "https://github.com/tailwindlabs/tailwindcss/releases/download/${TAILWIND_VERSION}/tailwindcss-linux-x64" \
    -o "$BINARY"
  chmod +x "$BINARY"
fi

cd "$(dirname "$0")/.."
"$BINARY" -i static/css/tailwind.input.css -o static/css/tailwind.css --minify
echo "Done — static/css/tailwind.css updated."
