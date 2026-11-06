#!/usr/bin/env bash
# Build the admin-only staging site (https://www-staging.sfmix.org) into .staging/:
# the Hugo site as it stands in this tree, built like CI builds production
# (.github/workflows/website.yml), plus work-in-progress concepts that are not
# part of the public site (concepts/*, served under /<name>-concepts/).
# Deployed by ansible/deploy_www_staging.playbook.yml, which runs this first.
set -euo pipefail
cd "$(dirname "$0")"
# Not always on PATH (e.g. under ansible); go install puts it in ~/go/bin.
hugo=$(command -v hugo || echo "$HOME/go/bin/hugo")

out=.staging
mkdir -p data
curl -fsSL -o data/participants_table.json https://lg.sfmix.org/participants_table.json

rm -rf "$out"
"$hugo" --quiet --minify -d "$out" --baseURL https://www-staging.sfmix.org/

# The concepts reuse the real page shell, read from an unminified build.
shell=$(mktemp -d)
trap 'rm -rf "$shell"' EXIT
"$hugo" --quiet -d "$shell" --baseURL https://www-staging.sfmix.org/
python3 -I concepts/team/build.py "$shell" "$out/team-concepts"

echo "staging site -> $(pwd)/$out"
