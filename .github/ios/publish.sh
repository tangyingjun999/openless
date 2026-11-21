#!/bin/bash
# Publish the build result as a public release asset so it can be fetched
# without an authenticated Actions API call: on success the IPA + checksums,
# on failure the tail of the build log for diagnosis.
set -uo pipefail

OUT="${GITHUB_WORKSPACE}/out"
LOG="${RUNNER_TEMP:-/tmp}/build.log"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
TAG="ios-${STAMP}"
NOTES="${RUNNER_TEMP:-/tmp}/release-notes.md"

mkdir -p "$OUT"

{
  echo "OpenLess iOS — unsigned iPhone build"
  echo
  echo "- ref: \`${GITHUB_REF_NAME:-beta}\` @ \`${GITHUB_SHA}\`"
  echo "- run: ${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID:-local}"
  echo "- runner: macOS $(sw_vers -productVersion 2>/dev/null) / $(uname -m 2>/dev/null)"
  echo "- xcode: $(xcodebuild -version 2>/dev/null | tr '\n' ' ')"
  echo
} > "$NOTES"

shopt -s nullglob
assets=("$OUT"/*.ipa)

if [ ${#assets[@]} -gt 0 ]; then
  [ -f "$OUT/SHA256SUMS" ] && assets+=("$OUT/SHA256SUMS")
  echo "- status: **SUCCESS** — install with a signing tool (Sideloadly / AltStore / TrollStore)" >> "$NOTES"
  TITLE="OpenLess iOS ${TAG} (unsigned IPA)"
else
  echo "- status: **FAILED** — build log excerpt attached" >> "$NOTES"
  TITLE="OpenLess iOS ${TAG} (build FAILED)"
  assets=()
  if [ -f "$LOG" ]; then
    tail -c 400000 "$LOG" > "$OUT/build-fail.log"
    assets=("$OUT/build-fail.log")
  else
    printf 'build.log was never created\n' > "$OUT/build-fail.log"
    assets=("$OUT/build-fail.log")
  fi
fi

echo "--- release notes ---"
cat "$NOTES"
echo "--- assets ---"
printf '%s\n' "${assets[@]}"

gh release create "$TAG" "${assets[@]}" \
  --title "$TITLE" \
  --notes-file "$NOTES" \
  --prerelease || { echo "release upload failed" >&2; exit 1; }

echo "published: ${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY}/releases/tag/${TAG}"
