# Plan: sample files in Docker volumes

Status (2026-10-07): milestones 1 and 2 built and checked (the helper ran in a container
on real volumes); milestone 3 built and its tests pass; the end-to-end comparison of
milestone 2 not yet run. For
`./cupella agent` (the API harness) only;
Claude Code and Codex keep host directories. A storage mode in which every file
that comes from a sample (`data/`, `work/`, harness transcripts and refusal records) lives
in Docker volumes instead of the host file system. Only the report output
(`reports/`) stays on the host. Scripts, docs, prompts, the image, and `cache/` stay where
they are. It is the default for a new workspace (2026-10-07) unless `--harness claude` or
`--harness other` is given; those and `--store host` get bind-mounted host directories,
and the checkout always has them.

## Contents

- Why
- Is it possible
- Design
- What changes
- Agents
- Engines
- Costs and limits
- Milestones
- Open questions

## Why

- No sample bytes or sample-derived text (decompiled code, strings, harness transcripts)
  on the host file system: host indexers, backup, antivirus, and editors never see them.
- The invariant "never parse sample files with host tools" becomes technical: with a
  rootful Docker daemon the volume data is under `/var/lib/docker/volumes/`, readable only
  by root, so `grep`, `strings`, or an agent's host tools cannot reach it by accident.
- Cleanup is one command (`docker volume rm`), and a workspace's samples cannot leak
  into another workspace's tree.

## Is it possible

Yes, for every `./cupella` script and for the API harness, which is the only agent this
mode supports (see "Agents").

- Every script already runs in a container that sees `data/` and `work/` only through
  mounts (`cupella`, the `analysis` mount set and the per-command mounts), so swapping
  bind mounts for volume mounts is local to the wrapper.
- The per-sample mounts (`run-decryptor.sh` and `try-proposal`: the sample read-only with
  one writable subdirectory; `claims-promote.py`, `claims-merge.py`, `report-build.py`:
  single files read-only) need a subdirectory or file of a volume. Docker's
  `--mount type=volume,src=V,dst=D,volume-subpath=P[,readonly]` does both. Checked on
  2026-10-07 with Docker 29.7.2 (API 1.55): a read-only directory, a read-only single
  file, and a writable subdirectory all mount as expected; a write to the read-only one
  fails. `volume-subpath` needs Docker Engine 26 or later.
- Host-side code that touches `work/` or `data/` directly: 17 places in `cupella` (existence
  and symlink checks before mounting), `host/model-compare.py`, `host/workspaces.sh`,
  `host/gate.sh`, `host/check.sh`, the host tests, and the harness tools and logs
  (`harness/tools.py`, `agent.py`). Each needs the same operation done inside a container.

## Design

- **Mode.** `./cupella setup --workspace DIR` (or with `--store volume`) records `store: volume` in
  `.cupella-workspace` and implies `--harness api`: no `CLAUDE.md`, `.claude/`, or agent
  types are generated there, and `WORKSPACE.md` says to run `./cupella agent`. Volume mode is for workspaces only: the checkout keeps host
  directories, because benchmarks and the gate (`bench/`, `data/ghera/`, `work/_gate*`)
  run there.
- **Volumes.** Two per workspace, named from a hash of its path: `cupella-<id>-data` and
  `cupella-<id>-work`. `setup` creates them and sets their owner to the calling user
  (one `docker run --user 0 ... chown`), so later containers keep running as that user.
- **Mounts.** The wrapper builds mounts from one function: `store_mount <area> <subpath>
  <dst> [ro]` emits `-v "$ws/<area>/<subpath>:<dst>[:ro]"` in host mode and
  `--mount type=volume,src=cupella-<id>-<area>,dst=<dst>,volume-subpath=<subpath>[,readonly]`
  in volume mode. Every current `-v "$ws/work..."` and `-v "$ws/data..."` goes through it.
- **Checks before mounting.** The wrapper's `[ -d ]`, `[ -f ]`, `[ ! -L ]` tests on
  sample paths run in a helper container (`store_test`), one `docker run` per command
  (about 0.3 s), or in the store helper below when the harness runs.
- **Store helper.** `harness/store_helper.py`, run by `./cupella store-serve` in a
  container (`cupella-store-<id>-<pid>`, no network, the image, the work volume
  read-write at `/repo/work`, the data volume read-only at `/repo/data`, no `cache/`):
  one JSON request per line on stdin, one answer per line on stdout. Operations:
  `resolve`, `stat`, `list`, `glob`, `walk`, `read` (line range), `text`, `binary`,
  `grep` (over a file list), `write` (and append), `mkdir`. It resolves paths inside the
  container and returns paths relative to `/repo`; the host keeps the policy and the
  helper does only resolution and I/O. Every I/O request names an already resolved path
  in `data/` or `work/`; the helper refuses one that resolves elsewhere by then, writes
  only under `work/`, creates no directory through a link, and opens files with
  `O_NOFOLLOW`. The harness (`harness/store.py`, `VolumeStore`) keeps a pool of up to six
  helpers, started on demand, so parallel subagents do not wait on each other's `grep`.
  `./cupella store-serve` refuses a terminal on stdin, and no role may run it (it is
  neither a script nor in `CUPELLA_COMMANDS`).
- **Resolution across the two.** A path whose first component is `data` or `work` is
  resolved by the helper; any other by the host. A volume path that leaves the volume
  (`work/../reports/x`, or a link to `/repo/reports/x`) continues on the host; a host
  path that lands in `data/` or `work/` (`reports/../work/x`, a host link into `work/`)
  is resolved once more by the helper. A path above the workspace, or a volume link to
  anywhere outside `/repo`, is outside. The policy then checks the result as in host
  mode.
- **Getting samples in.** `./cupella import <host file> [subdir]` copies a file into the
  data volume (a container with the file mounted read-only); it never changes or deletes
  the host file. The user deletes the download. `sample-archive.py` works unchanged
  inside the volume.
- **Getting things out.** `./cupella export <name> <path>...` copies named text files (a
  cited source file, a decrypted strings file, a directory of them) of one sample and its
  child samples to `exports/<name>/` on the host, keeping their paths
  (`exports/<name>/work/<name>/...`), by the user's explicit request only. A container
  does the copy (`scripts/export-files.py`): it sees that sample's `work/` directories
  read-only and only `exports/<name>/` writable, copies regular text files (16 MB each,
  256 MB in all), skips and lists links, binary files, and files already exported (never
  overwritten). Agents never run it (neither `export` nor `export-files.py` is in their
  commands, and the wrapper refuses `export-files.py` by name) and never read `exports/`
  (`DENY_READ`). `exports/` is separate from `reports/`, so that what is sample-derived
  is plain, and gitignored. `reports/` stays a host directory mounted into the report
  scripts as now; `./cupella md-view.py reports/<name>.md` reads a report on the terminal.
- **Looking and cleaning up.** `./cupella store ls` shows the store, the two volumes and
  their sizes (`du` in a container), the samples in `work/`, and the files in `data/`
  (names and sizes, listed in a container); `store ls --all` lists
  every Cupella volume on the engine with the workspace it was made for and whether that
  workspace still exists. `./cupella store rm` deletes both volumes, `store rm work` only
  the work volume (recreated empty), each after typing the workspace's volume id on a
  terminal; `reports/` and `exports/` stay. `./cupella workspaces rm DIR` deletes a whole
  workspace: its volumes (by name and by the `cupella.workspace` label), the directory,
  and its entry in the checkout's list, after asking for the directory's name. None of
  these is an agent command (the harness refuses `workspaces rm` and `--prune`).

## What changes

| Part | Change |
|------|--------|
| `cupella` | done: `store_mount` and `store_stat` for all work/data uses; `import`, `export`, `store ls [--all]`, `store rm [all\|work]` (after a confirmation); `setup --store volume` (the default for a new workspace); `store-serve` |
| `scripts/export-files.py` | done: the copy behind `./cupella export`, in a container |
| `harness/store.py` | done: `HostStore` (host directories) and `VolumeStore` (helper pool for `data/` and `work/`, host for the rest); chosen from `store=` in `.cupella-workspace` |
| `harness/store_helper.py` | done: the helper ("Store helper") |
| `harness/tools.py` | done: `read_file`, `grep`, `list_dir`, `write_file`, `edit_file`, `append_file`, and `run`'s logs and `stdout_to` go through the policy's store |
| `harness/policy.py` | done: `resolve()`, the link check before a write, the earlier-file check (mtime), and sample-name checks ask the store; matching stays on the host |
| `harness/repair.py` | done: path and sample repairs look up names through the store |
| `harness/agent.py` | done: transcripts, `runs/`, `usage.tsv`, `events.log`, `config.json`, and `work/_stops/` written through the store; the main agent's `usage.tsv` read through it; `--check` writes no session |
| `host/harness-test.py` | done: the policy, tool, and repair cases on both stores (the helper run locally on a scratch directory), plus volume cases: resolution across host and volume, links, writes below a link, unresolved reads, writes to `data/`, session files in the volume, nothing of `data/` or `work/` on the host |
| `host/model-compare.py` | done: moves, metrics, and its result files through the store (`move`, `lexists`, `listdir`, `read_text`, `write_text`); report files are kept aside in `reports/_archive/model-compare/<run>/` (host), `work/` outputs in `work/_bench-models/<run>/`, so every move is a rename on one side |
| `host/workspaces.sh` | done: "vol" in the APK column for a volume workspace (counting would take a container per workspace) |
| `host/gate.sh`, `host/check.sh` | unchanged: they always run on the checkout, which keeps host directories |
| `host/export-test.sh` | done: `./cupella export` on a throwaway workspace, run by `./cupella check` |
| `scripts/` | unchanged: they see `/repo/work` and `/repo/data` either way |
| Docs | done: `WORKSPACE.md` of a volume workspace says to use `./cupella agent`, that `work/` paths are not host paths, and names `import`, `md-view.py`, `export`, `store ls`, `store rm`; the agents' instructions are unchanged (the harness maps them) |

## Agents

- **API harness (`./cupella agent`):** the only supported agent. Its tools go through
  the store helper; the model sees the same paths and results as in host mode.
- **Claude Code, Codex, and other harnesses:** not supported in volume mode. Their file
  tools read the host file system and find nothing under `work/`. A volume workspace is
  set up without their files, and `./cupella setup --store volume --harness claude` is
  refused. The user can still run `./cupella <script>` by hand there.

## Engines

Checked 2026-10-07 against the vendors' documentation and release notes; only Docker
Engine on Linux was tested here.

| Engine | Subpath mounts | Option name | Where volumes live | Isolation from host tools |
|--------|----------------|-------------|--------------------|---------------------------|
| Docker Engine, rootful (Linux) | Engine 26.0+ (API 1.45, 2024-03) | `volume-subpath=` | `/var/lib/docker/volumes/`, root only | yes; tested on 29.7.2: directory, single file, read-only, read-write |
| Docker Engine, rootless | same | `volume-subpath=` | under the user's home | no: readable by the user's tools |
| Docker Desktop (macOS) | 4.29+ (Engine 26.0.0, 2024-04-08) | `volume-subpath=` | ext4 inside the VM's disk image under `~/Library/Containers/com.docker.docker/` | yes: macOS tools see one opaque disk image; reading a volume needs a container |
| Podman | 5.4+ for `type=volume` (5.1 added it for `type=image`) | `subpath=` | rootful: `/var/lib/containers/storage/volumes/`; rootless (the common setup): `~/.local/share/containers/storage/volumes/` | rootful yes; rootless no |

- The wrapper picks the option name from the engine: `volume-subpath=` for Docker,
  `subpath=` for Podman (`CUPELLA_DOCKER=podman`); `setup --store volume` checks the
  version (Docker server 26+, Podman 5.4+) and refuses an older one.
- Docker documents subpaths as directories that must already exist; a single-file subpath
  worked on Docker 29.7.2 but is not documented, and Podman's documentation only says
  "a specific subpath within the volume". The report scripts that mount one file
  (`facts.json`, `reports/<name>.json`) mount the sample's directory read-only instead
  where a file subpath fails, which the setup check tests once.
- Podman rootless maps user IDs; the wrapper's `--user "$(id -u):$(id -g)"` may need
  `--userns=keep-id` there, and the volume owner fix at setup uses Podman's `chown`
  (`U`) mount option instead of a root container. Untested.
- Anyone who can run containers can read the volumes (a Docker group member or Docker
  Desktop user is root-equivalent anyway): volume mode keeps sample files away from host
  tools and indexers, not away from that user.
- Disk: on Linux a decompression bomb now fills the Docker data partition rather than the
  workspace's; the per-file limit (`APK_FSIZE`) still applies. Docker Desktop's VM disk
  has a fixed maximum size, which caps the damage.
- Docker Desktop on macOS: volumes are also faster than bind mounts there, since bind
  mounts cross the VM boundary; whether Time Machine backs up the VM disk image depends on
  the user's exclusions.

## Costs and limits

- One `docker run` per wrapper existence check: about 0.3 s more per script call. The
  helper makes harness tool calls a round trip over a pipe, a few milliseconds.
- Opening a cited file to check a finding needs `./cupella export` or `./cupella shell`;
  report paths like `work/<name>/jadx/...` are not host paths in this mode.
- Requires Docker Engine 26+, Docker Desktop 4.29+, or Podman 5.4+ ("Engines").
- The model provider still receives every file the agent reads (`harness-api.md` "Safety");
  volume mode protects the host disk, not the API traffic.
- `unpack.sh -f` keeps agent outputs inside the volume as now; `work/` stays disposable,
  but deleting it means `store rm work`, not `rm -r`.
- `exports/` puts sample-derived text back on the host: only what the user names, and
  only text.

## Milestones

1. **Wrapper.** Done 2026-10-07: `store_mount`/`store_add`, `store_stat`, `store_children`,
   `store_mkdir`, and `store_ready` in `cupella`; `setup --store volume` (creates and chowns
   the volumes, checks the engine version, implies `--harness api`, keeps the store on
   later setups); `./cupella import`. On F-Droid in a volume workspace and a host
   workspace made the same day: `scan.txt`, `facts.json`, `structure-leads.txt`,
   `flows.txt`, `behavior-facts.txt`, the manifest, native, and tracker summaries, and
   the rendered report identical. `try-proposal`, `run-decryptor.sh` (a trivial decryptor),
   `claims-promote.py --list`, `claims-merge.py`, `claims-check.py`, and `cite-check.py`
   ran; the setup self-test passed inside the volumes. On the host the workspace held only
   its config, the doc copies, `reports/`, and proposal code. `native-decompile.sh` was
   not run (F-Droid ships no app native code).
2. **Store helper and harness.** Built 2026-10-07: `harness/store.py`,
   `harness/store_helper.py`, `./cupella store-serve`, tools, policy, repairs, and the
   harness's own files through the store, and `host/harness-test.py` on both stores
   (see "What changes"). `host/harness-test.py` passes on both stores, and
   `./cupella check --no-gate` passes (2026-10-07). A first `./cupella agent --once`
   in a volume workspace (2026-10-07) listed `work/` and `data/` through the helper in a
   container, with the session files in the work volume. Not yet run: the end-to-end
   check. Done when
   `./cupella agent` produces the same report on one sample in both modes, and nothing
   sample-derived appears under the workspace on the host (`find` for `work/`, `data/`).
3. **Tools around it.** Built 2026-10-07: `./cupella export` (`scripts/export-files.py`),
   `store ls [--all]`, `store rm [all|work]`, `model-compare.py` and `workspaces.sh`
   through the store, `exports/` denied to agents and gitignored, `host/export-test.sh`
   and new cases in `host/harness-test.py` (moves, exports, user-only commands), docs.
   `./cupella check --no-gate` passes with them (2026-10-07). `store ls` ran on
   real volumes (2026-10-07). Not yet run: `store rm` on real volumes, `export` from a volume, and `model-compare` in a
   volume workspace.

## Open questions

- Whether the store helper should also serve the wrapper's existence checks during a
  harness session (faster) or the wrapper keeps its own `store_stat` (simpler; the
  current choice: each `./cupella` call from the harness is a separate process).
- Podman and Docker Desktop are documented, not tested: single-file subpaths, Podman's
  user mapping, and the setup-time ownership fix need one run on each.
