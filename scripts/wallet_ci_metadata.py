"""Derive CI artifact paths from the wallet's checked-in, matching versions."""
import json
import os
from pathlib import Path
import re
import tomllib


def metadata(repo: Path, platform: str) -> dict[str, str]:
    wallet = repo / "apps/wallet"
    base = json.loads((wallet / "src-tauri/tauri.conf.json").read_bytes())
    override = json.loads((wallet / "src-tauri/tauri.rcnet.conf.json").read_bytes())
    config = {**base, **override}
    version = config["version"]
    product = config["productName"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", version):
        raise ValueError("unsupported wallet version")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]*", product):
        raise ValueError("unsafe wallet product name")
    versions = [json.loads((wallet / "package.json").read_bytes())["version"]]
    lock = json.loads((wallet / "package-lock.json").read_bytes())
    versions.extend((lock["version"], lock["packages"][""]["version"]))
    for manifest in (wallet / "src-tauri/Cargo.toml", repo / "crates/cmfd-node/Cargo.toml"):
        versions.append(tomllib.loads(manifest.read_text())["package"]["version"])
    if any(actual != version for actual in versions):
        raise ValueError("wallet, node, Tauri and npm versions disagree")
    if platform == "Windows":
        return {"version": version,
                "bundle_path": f"target/release/bundle/nsis/{product}_{version}_x64-setup.exe",
                "deb_path": "",
                "bootstrap_path": f"target/runtime-bootstrap/commonfoundry-rc-runtime-bootstrap-windows-x86_64-v{version}.zip"}
    if platform == "Linux":
        return {"version": version,
                "bundle_path": f"target/release/bundle/appimage/{product}_{version}_amd64.AppImage",
                "deb_path": f"target/release/bundle/deb/{product}_{version}_amd64.deb",
                "bootstrap_path": f"target/runtime-bootstrap/commonfoundry-rc-runtime-bootstrap-linux-x86_64-v{version}.tar.gz"}
    raise ValueError("unsupported desktop CI platform")


if __name__ == "__main__":
    values = metadata(Path(__file__).resolve().parents[1], os.environ["RUNNER_OS"])
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8", newline="\n") as output:
        for key, value in values.items():
            output.write(f"{key}={value}\n")
    print(json.dumps(values))
