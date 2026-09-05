"""Bind unchanged proof sources/dependencies to RC4; RC5 core tests run separately."""
import json
import subprocess
import tomllib
from pathlib import Path

BASE = "557c12f351fbca59d3b473c2cda7a604706ac7c6"
REPO = "Common-Foundry-1/CommonFoundry"


def run(*args):
    return subprocess.check_output(args, text=True).strip()


head = run("git", "rev-parse", "HEAD")
subprocess.run(["git", "merge-base", "--is-ancestor", BASE, head], check=True)
subprocess.run(["git", "diff", "--exit-code", BASE, head, "--",
                "tools/production-v4-prover", "crates/cmfd-consensus/src/forgematrix*",
                "third_party"], check=True)
before = tomllib.loads(run("git", "show", f"{BASE}:Cargo.lock"))["package"]
after = tomllib.loads(Path("Cargo.lock").read_text())["package"]
current = {(row["name"], row["version"], row["source"]): row for row in after if "source" in row}
for row in before:
    if "source" not in row:
        continue
    expected = dict(row)
    # The native file dialog enables an existing macOS foundation feature.
    # No package version, source, checksum, or proof dependency changes.
    if row["name"] == "objc2-foundation" and row["version"] == "0.3.2":
        expected["dependencies"] = sorted(set(row["dependencies"]) | {"libc"})
    if current.get((row["name"], row["version"], row["source"])) != expected:
        raise SystemExit(f"Previously pinned dependency changed: {row['name']}")
baseline = json.loads(run("gh", "run", "view", "33936910124", "--repo", REPO,
                          "--json", "headSha,conclusion"))
if baseline != {"headSha": BASE, "conclusion": "success"}:
    raise SystemExit("The RC4 baseline release checks are not verified")
commit = json.loads(run("gh", "api", f"repos/{REPO}/commits/{head}"))
if not commit["commit"]["verification"]["verified"]:
    raise SystemExit("RC5 source commit does not have a verified signature")
print("RC4 proof sources and existing external dependencies are unchanged; RC5 core/runtime gates remain required.")
