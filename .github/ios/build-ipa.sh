#!/bin/bash
# Build the OpenLess iPhone app on a macOS runner and package an unsigned IPA.
# Mirrors openless-all/ios/README.zh.md "从源码构建".
set -euo pipefail

: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"
IOS="$GITHUB_WORKSPACE/openless-all/ios"
OUT="$GITHUB_WORKSPACE/out"
export OPENLESS_DERIVED_DATA="${RUNNER_TEMP:-/tmp}/ios-device"

step() { printf '\n########## %s ##########\n' "$*"; }

mkdir -p "$OUT"
cd "$IOS"

step "toolchain"
sw_vers
xcodebuild -version
python3 -V
rustc -V
rustup target list --installed

step "cmake"
if ! command -v cmake >/dev/null 2>&1; then brew install cmake; fi
cmake --version | head -1

step "bootstrap (XcodeGen, librime, KeyboardKit, boost, rust targets)"
bash scripts/bootstrap.sh

step "bootstrap-local-speech (SenseVoice model + sherpa/onnxruntime xcframeworks)"
bash scripts/bootstrap-local-speech.sh

step "build-rime host"
bash scripts/build-rime.sh host

step "build-rime device"
bash scripts/build-rime.sh device

step "build-core device"
bash scripts/build-core.sh device

step "collect-rust-licenses"
python3 scripts/collect-rust-licenses.py

step "build-predictions"
python3 scripts/build-predictions.py

step "validate-project"
python3 scripts/validate-project.py

step "xcodebuild OpenLess (Release, device, unsigned)"
bash scripts/build.sh device Release unsigned

step "package-ipa"
APP="$OPENLESS_DERIVED_DATA/Build/Products/Release-iphoneos/OpenLess.app"
ls -la "$APP"
VERSION=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Info.plist" 2>/dev/null || echo unknown)
BUILDNO=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$APP/Info.plist" 2>/dev/null || echo unknown)
IPA="$OUT/OpenLess-${VERSION}-${BUILDNO}-unsigned.ipa"
python3 scripts/package-ipa.py "$APP" "$IPA"

step "checksums"
( cd "$OUT" && shasum -a 256 ./*.ipa > SHA256SUMS && cat SHA256SUMS )
ls -la "$OUT"
echo "IPA: $IPA"
