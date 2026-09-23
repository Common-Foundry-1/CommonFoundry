# Preparing the reviewed mainnet pool dashboard

`scripts/package_mainnet.py` requires the built `apps/pool-dashboard/dist` tree
and a canonical `DASHBOARD-ASSETS.json` bound to the exact frozen source commit.
The ignored development `dist/` directory is **not** release evidence. Prepare
this asset set only after the source freeze, with this helper included in that
commit and the checkout clean:

```text
python scripts/prepare_mainnet_dashboard.py \
  --repo /absolute/path/to/CommonFoundry \
  --commit <full-40-character-frozen-commit> \
  --dist /absolute/path/to/new-stage/dashboard \
  --manifest /absolute/path/to/new-stage/DASHBOARD-ASSETS.json \
  --evidence /absolute/path/to/new-stage/DASHBOARD-BUILD-EVIDENCE.json
```

Use the local Python executable if `python` is not on `PATH`; use absolute paths
on either operating system. In PowerShell, place the arguments on one line or
replace the trailing `\` characters with PowerShell backticks. Place all three
output paths **outside** the source repository; they must not already exist.
The helper reads only regular tracked dashboard blobs from that commit, checks
the package and npm v3 lockfile identities, stages them in an isolated temporary
directory, runs `npm ci --ignore-scripts --no-audit --no-fund` and `npm run build`, and rejects
any change to the staged source. It allows only the packager's dashboard asset
names, sizes and tree shape, copies the validated build to the new `--dist`,
then writes canonical create-new evidence and manifest files. Any ignored
`node_modules` or `dist` already in the checkout is excluded.

To check an *existing* candidate dist, use new manifest/evidence output names
and `--verify-dist`. The helper still performs a fresh isolated build and
compares every asset byte identity with that dist. It never blesses a stale
tree just because its own inventory is internally consistent. Pass the reviewed
manifest and matching dist to both native runs of `scripts/package_mainnet.py`
via `--dashboard-manifest` and `--dashboard-dist`.

The install suppresses dependency lifecycle scripts to reduce package-install
side effects. The project build script itself still runs (`tsc -b && vite
build`); if a future dependency requires a post-install script, this workflow
will fail rather than silently enable it. npm output is capped at 1 MiB and
commands have timeouts.

`DASHBOARD-BUILD-EVIDENCE.json` records the commit, exact lockfile digest,
source-tree digest, Node/npm executable paths and versions, combined command-output
digests, and manifest digest. It is a **first-person build record**, not a
signature, independent reproduction, mainnet approval, or proof that npm
dependencies are trustworthy. Review it with the assets and the lockfile. A
separate operator must independently rebuild and review the final packages
for the mainnet reproduction gate described in
[`mainnet-plan-approvals.md`](mainnet-plan-approvals.md). This helper does not
apply launch pins, publish source or binaries, or start mining.
