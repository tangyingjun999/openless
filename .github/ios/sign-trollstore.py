#!/usr/bin/env python3
"""Pseudo-sign the device product the way TrollStore expects, with the App Group
entitlement baked into every executable, then repackage it as an IPA.

Why this exists
---------------
`scripts/build.sh device Release unsigned` builds with CODE_SIGNING_ALLOWED=NO,
so the product carries no entitlements at all. TrollStore re-signs an IPA with
whatever entitlements it can read out of the binaries: nothing to read means no
`com.apple.security.application-groups`, so
`FileManager.containerURL(forSecurityApplicationGroupIdentifier:)` returns nil,
`SharedContainer.openMailbox()` throws, the keyboard's `mailbox` stays nil and it
shows "完全访问已开启，但暂时无法连接 OpenLess。请打开主应用后重试。" while the
voice pipeline is unreachable.

Signing strategy: `ldid -S<plist>` is the canonical pseudo-signature (that is the
format TrollStore itself reads and writes). `codesign --sign -` is kept as a
fallback because recent macOS can emit entitlements as DER, which ldid cannot
re-parse. Whatever path is used, the entitlements are dumped afterwards so the
build log proves what ended up inside the binary.

The packaged bundle also gets its CFBundleVersion bumped by one so the installed
build is distinguishable in TrollStore's app info.
"""
import hashlib
import json
import os
import platform
import plistlib
import shutil
import stat
import subprocess
import tempfile
import urllib.request
import zipfile
from pathlib import Path

APP_GROUP = "group.app.openless.ios"
TEAM = "TROLLSTORE"
LDID_TAG = "v2.1.5-procursus8"
MACHO_MAGICS = {
    b"\xcf\xfa\xed\xfe",  # MH_MAGIC_64
    b"\xce\xfa\xed\xfe",  # MH_MAGIC
    b"\xca\xfe\xba\xbe",  # FAT_MAGIC
    b"\xbe\xba\xfe\xca",  # FAT_CIGAM
}


def entitlements(bundle_id):
    return {
        "application-identifier": f"{TEAM}.{bundle_id}",
        "com.apple.developer.team-identifier": TEAM,
        "com.apple.security.application-groups": [APP_GROUP],
    }


def run(cmd, check=True, capture=False):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    return subprocess.run(cmd, check=check, capture_output=capture, text=True)


def ldid_path():
    """Locate a usable ldid, downloading a prebuilt one if the runner lacks it."""
    candidates = [os.environ.get("LDID"), shutil.which("ldid"),
                  "/opt/homebrew/bin/ldid", "/usr/local/bin/ldid"]
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            print(f"ldid: using {candidate}", flush=True)
            return Path(candidate)
    arch = "arm64" if platform.machine() in ("arm64", "aarch64") else "x86_64"
    url = f"https://github.com/ProcursusTeam/ldid/releases/download/{LDID_TAG}/ldid_macosx_{arch}"
    target = Path(tempfile.mkdtemp(prefix="ldid-")) / "ldid"
    try:
        print(f"ldid: not installed, fetching {url}", flush=True)
        with urllib.request.urlopen(url, timeout=120) as response:
            target.write_bytes(response.read())
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        # arm64 macOS refuses to exec a binary without any signature at all.
        run(["codesign", "--force", "--sign", "-", str(target)], check=False)
        probe = run([str(target)], check=False, capture=True)
        if probe.returncode == 127 or "command not found" in (probe.stderr or ""):
            raise RuntimeError(probe.stderr)
        print(f"ldid: downloaded {target}", flush=True)
        return target
    except Exception as error:  # noqa: BLE001 - fall back to codesign below
        print(f"ldid: unavailable ({error}); falling back to codesign", flush=True)
        return None


def is_macho(path):
    try:
        with path.open("rb") as stream:
            return stream.read(4) in MACHO_MAGICS
    except OSError:
        return False


def sign(binary, entitlements_file, ldid):
    if ldid is not None:
        cmd = [str(ldid), "-S" + str(entitlements_file)] if entitlements_file else [str(ldid), "-S"]
        result = run(cmd + [str(binary)], check=False, capture=True)
        if result.returncode == 0:
            return "ldid"
        print(f"! ldid failed on {binary}: {result.stderr.strip()}", flush=True)
    cmd = ["codesign", "--force", "--sign", "-", "--timestamp=none", "--verbose=1"]
    if entitlements_file is not None:
        cmd += ["--entitlements", str(entitlements_file)]
    run(cmd + [str(binary)])
    return "codesign"


def dump_entitlements(bundle, ldid):
    info = plistlib.load((bundle / "Info.plist").open("rb"))
    executable = bundle / info["CFBundleExecutable"]
    if ldid is not None:
        result = subprocess.run([str(ldid), "-e", str(executable)],
                                capture_output=True, text=True)
        text = (result.stdout + result.stderr).strip()
    else:
        result = subprocess.run(["codesign", "-d", "--entitlements", ":-", str(executable)],
                                capture_output=True, text=True)
        text = (result.stdout + result.stderr).strip()
    print(f"--- entitlements: {bundle.name}\n{text}", flush=True)
    return text


def read_plist(path):
    with path.open("rb") as stream:
        return plistlib.load(stream)


def bump_build(bundle, build):
    info = bundle / "Info.plist"
    metadata = read_plist(info)
    metadata["CFBundleVersion"] = build
    with info.open("wb") as stream:
        plistlib.dump(metadata, stream)


def bundle_id(bundle):
    return read_plist(bundle / "Info.plist")["CFBundleIdentifier"]


def executables(container):
    info = read_plist(container / "Info.plist")
    name = info.get("CFBundleExecutable")
    path = container / name if name else None
    return {path} if path is not None and path.is_file() else set()


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
    derived = os.environ.get("OPENLESS_DERIVED_DATA")
    if not derived:
        derived = str(Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "ios-device")
    source = Path(derived) / "Build/Products/Release-iphoneos/OpenLess.app"
    if not source.is_dir():
        raise SystemExit(f"missing device product: {source}")
    workspace = Path(os.environ["GITHUB_WORKSPACE"])

    source_metadata = read_plist(source / "Info.plist")
    version = source_metadata["CFBundleShortVersionString"]
    # Offset keeps consecutive side-loaded builds distinguishable even though the
    # project version stays put; 0.1.0 (16) is upstream, (17) was the first
    # ad-hoc signed attempt, (18)+ come from this ldid-based signer.
    offset = int(os.environ.get("OPENLESS_BUILD_OFFSET", "2"))
    build = str(int(source_metadata["CFBundleVersion"]) + offset)

    work = Path(tempfile.mkdtemp(prefix="openless-trollstore-"))
    payload = work / "Payload"
    payload.mkdir()
    app = payload / "OpenLess.app"
    # ditto keeps the bundle layout while dropping resource forks, extended
    # attributes and quarantine flags, which the signers refuse to seal.
    run(["ditto", "--norsrc", "--noextattr", "--noqtn", str(source), str(app)])

    plugins = app / "PlugIns"
    appexes = sorted(p for p in plugins.iterdir() if p.suffix == ".appex") if plugins.is_dir() else []
    for bundle in [app] + appexes:
        bump_build(bundle, build)
    print(f"packaging version {version} build {build}", flush=True)

    ent_dir = work / "entitlements"
    ent_dir.mkdir()

    def entitlements_file(bundle):
        path = ent_dir / (bundle.name + ".plist")
        with path.open("wb") as stream:
            plistlib.dump(entitlements(bundle_id(bundle)), stream)
        return path

    ldid = ldid_path()
    main_binaries = {}
    for bundle in [app] + appexes:
        for binary in executables(bundle):
            main_binaries[binary.resolve()] = entitlements_file(bundle)

    # Sign every Mach-O in the bundle: frameworks and dylibs plain, the app and
    # its extensions with the App Group entitlements.
    signed = {}
    for path in sorted(p for p in app.rglob("*") if p.is_file() and is_macho(p)):
        ent = main_binaries.get(path.resolve())
        signed[path.name] = sign(path, ent, ldid)
    print(f"signed {len(signed)} Mach-O files: {json.dumps(signed, indent=2)}", flush=True)
    print(f"signer: {'ldid' if ldid is not None else 'codesign-only'}", flush=True)

    if ldid is None:
        # codesign only produces a usable entitlements blob when it seals the
        # bundle itself, so redo the containers from the inside out.
        for bundle in appexes + [app]:
            run(["codesign", "--force", "--sign", "-", "--timestamp=none",
                 "--entitlements", str(entitlements_file(bundle)), str(bundle)])

    dumps = {bundle.name: dump_entitlements(bundle, ldid) for bundle in [app] + appexes}

    out_dir = workspace / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    output = out_dir / f"OpenLess-{version}-{build}-trollstore.ipa"
    package(app, output)
    print(f"built {output}", flush=True)

    with output.open("rb") as stream:
        checksum = digest(stream)
    with zipfile.ZipFile(output) as archive:
        entries = len(archive.namelist())
    print(json.dumps({"ipa": str(output), "version": version, "build": build,
                      "app_group": APP_GROUP, "bytes": output.stat().st_size,
                      "sha256": checksum, "files": entries,
                      "signer": "ldid" if ldid is not None else "codesign",
                      "entitlements_dumped": {k: bool(v) for k, v in dumps.items()}},
                     indent=2))

    sums = out_dir / "SHA256SUMS"
    with sums.open("w") as stream:
        for ipa in sorted(out_dir.glob("*.ipa")):
            with ipa.open("rb") as handle:
                stream.write(f"{digest(handle)}  ./{ipa.name}\n")
    print(sums.read_text())


if __name__ == "__main__":
    main()
