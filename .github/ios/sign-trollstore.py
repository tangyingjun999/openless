#!/usr/bin/env python3
"""Ad-hoc sign the device product with App Group entitlements baked into the code
signature, then repackage it as an IPA for TrollStore / ldid pseudo-signing.

Why this exists
---------------
`scripts/build.sh device Release unsigned` builds with CODE_SIGNING_ALLOWED=NO,
so the product carries no entitlements at all. TrollStore re-signs an IPA with
whatever entitlements it can read out of the binary: nothing to read means no
`com.apple.security.application-groups`, so
`FileManager.containerURL(forSecurityApplicationGroupIdentifier:)` returns nil,
`SharedContainer.openMailbox()` throws, the keyboard's `mailbox` stays nil and it
shows "完全访问已开启，但暂时无法连接 OpenLess。请打开主应用后重试。" while the
voice pipeline is unreachable.

Baking the entitlement into an ad-hoc signature keeps it available to TrollStore
/ ldid without a developer certificate or a provisioning profile.
"""
import hashlib
import json
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

APP_GROUP = "group.app.openless.ios"
TEAM = "TROLLSTORE"


def entitlements(bundle_id):
    return {
        "application-identifier": f"{TEAM}.{bundle_id}",
        "com.apple.developer.team-identifier": TEAM,
        "com.apple.security.application-groups": [APP_GROUP],
    }


def run(cmd):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    subprocess.run(cmd, check=True)


def sign(bundle, entitlements_file=None):
    cmd = ["codesign", "--force", "--sign", "-", "--timestamp=none", "--verbose=1"]
    if entitlements_file is not None:
        cmd += ["--entitlements", str(entitlements_file)]
    cmd.append(str(bundle))
    run(cmd)


def dump_entitlements(bundle):
    result = subprocess.run(
        ["codesign", "-d", "--entitlements", ":-", str(bundle)],
        check=True, capture_output=True, text=True,
    )
    text = result.stdout.strip() or result.stderr.strip()
    print(f"--- entitlements: {bundle.name}\n{text}", flush=True)
    return text


def bundle_id(bundle):
    with (bundle / "Info.plist").open("rb") as stream:
        return plistlib.load(stream)["CFBundleIdentifier"]


def sign_frameworks(container):
    frameworks = container / "Frameworks"
    if not frameworks.is_dir():
        return
    for item in sorted(frameworks.iterdir()):
        if item.is_dir():
            sign(item)


def digest(stream):
    result = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        result.update(block)
    return result.hexdigest()


def package(app, output):
    if output.exists():
        output.unlink()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in sorted(app.rglob("*")):
            if path.is_symlink():
                raise SystemExit(f"unexpected symlink in device product: {path}")
            if not path.is_file() or path.name == ".DS_Store" or path.name.startswith("._"):
                continue
            archive.write(path, "Payload/" + str(path.relative_to(app.parent)))
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise SystemExit("archive CRC check failed")


def main():
    derived = Path(os.environ["OPENLESS_DERIVED_DATA"])
    workspace = Path(os.environ["GITHUB_WORKSPACE"])
    source = derived / "Build/Products/Release-iphoneos/OpenLess.app"
    if not source.is_dir():
        raise SystemExit(f"missing device product: {source}")
    out_dir = workspace / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    with (source / "Info.plist").open("rb") as stream:
        metadata = plistlib.load(stream)
    version = metadata["CFBundleShortVersionString"]
    build = metadata["CFBundleVersion"]

    work = Path(tempfile.mkdtemp(prefix="openless-trollstore-"))
    payload = work / "Payload"
    payload.mkdir()
    app = payload / "OpenLess.app"
    shutil.copytree(source, app, symlinks=True)

    ent_dir = work / "entitlements"
    ent_dir.mkdir()

    def write_entitlements(bundle):
        path = ent_dir / (bundle.name + ".plist")
        with path.open("wb") as stream:
            plistlib.dump(entitlements(bundle_id(bundle)), stream)
        return path

    # Inside out: nested frameworks, then extensions, then the app itself.
    sign_frameworks(app)
    plugins = app / "PlugIns"
    if plugins.is_dir():
        for appex in sorted(p for p in plugins.iterdir() if p.suffix == ".appex"):
            sign_frameworks(appex)
            sign(appex, write_entitlements(appex))
    sign(app, write_entitlements(app))

    verified = [app] + ([p for p in sorted((app / "PlugIns").iterdir()) if p.suffix == ".appex"]
                        if (app / "PlugIns").is_dir() else [])
    for bundle in verified:
        dump_entitlements(bundle)

    output = out_dir / f"OpenLess-{version}-{build}-trollstore.ipa"
    package(app, output)
    shutil.rmtree(work, ignore_errors=True)

    with output.open("rb") as stream:
        checksum = digest(stream)
    with zipfile.ZipFile(output) as archive:
        entries = len(archive.namelist())
    print(json.dumps({"ipa": str(output), "version": version, "build": build,
                      "app_group": APP_GROUP, "bytes": output.stat().st_size,
                      "sha256": checksum, "files": entries}, indent=2))

    sums = out_dir / "SHA256SUMS"
    ipas = sorted(out_dir.glob("*.ipa"))
    with sums.open("w") as stream:
        for ipa in ipas:
            with ipa.open("rb") as handle:
                stream.write(f"{digest(handle)}  ./{ipa.name}\n")
    print(sums.read_text())


if __name__ == "__main__":
    main()
