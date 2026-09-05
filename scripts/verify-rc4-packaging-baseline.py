"""Reuse completed RC4 code tests only for this explicitly bounded packaging repair."""
import json
import subprocess

BASE = "4c45ddf1a0c99382dc175c8fd06d5b68e4bc6658"
PARALLEL = "6f57aa9bdb62bc6e540ee6704503c86b2720742d"
REPO = "Common-Foundry-1/CommonFoundry"
ALLOWED = {
    ".gitattributes", ".github/workflows/ci.yml",
    ".github/workflows/rc4-release-packages.yml",
    "packaging/releases/v0.1.0-rc.4.inventory",
    "scripts/package-standalone-miner.ps1", "scripts/package-standalone-miner.sh",
    "scripts/release_integrity.py", "scripts/tests/test_runtime_bootstrap_integrity.py",
    "scripts/verify-rc4-packaging-baseline.py", "docs/release-integrity.md",
}


def run(*args):
    return subprocess.check_output(args, text=True).strip()


subprocess.run(["git", "merge-base", "--is-ancestor", BASE, "HEAD"], check=True)
changed = set(run("git", "diff", "--name-only", BASE, "HEAD").splitlines())
if changed - ALLOWED:
    raise SystemExit(f"Code changed beyond packaging; new code validation required: {sorted(changed - ALLOWED)}")
original = json.loads(run("gh", "run", "view", "33885284381", "--repo", REPO, "--json", "headSha,jobs"))
if original["headSha"] != BASE or len(original["jobs"]) != 9:
    raise SystemExit("Original RC4 build evidence is not the expected run")
for job in original["jobs"]:
    if job["name"] != "rust" and job["conclusion"] != "success":
        raise SystemExit(f"Original platform gate did not pass: {job['name']}")
    if job["name"] == "rust":
        # The later serial GPU compilation exhausted its disk. All preceding
        # code checks passed; the remaining suites ran on fresh parallel hosts.
        steps = {step["number"]: step for step in job["steps"]}
        if any(steps[number]["conclusion"] != "success" for number in range(4, 26)):
            raise SystemExit("Original code validation is incomplete")
parallel = json.loads(run("gh", "run", "view", "33926307696", "--repo", REPO, "--json", "headSha,conclusion,jobs"))
if parallel["headSha"] != PARALLEL or parallel["conclusion"] != "success" or len(parallel["jobs"]) != 4:
    raise SystemExit("Parallel RC4 validation is not complete")
for job in parallel["jobs"]:
    if job["conclusion"] != "success" or not any(
        step["name"] == "Verify signed release source" and step["conclusion"] == "success"
        for step in job["steps"]
    ):
        raise SystemExit("Parallel validation did not verify the original release source")
print(f"Unchanged RC4 application, consensus and dependency sources verified against {BASE}")
print("Packaging repair must still pass native package, wallet and integrity checks.")
