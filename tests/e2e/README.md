# End-to-End Tests

Comprehensive tests that run against a live litevirt cluster. These exercise the full stack: CLI, gRPC handlers, REST API, state replication, networking, migration, and error handling.

## Prerequisites

- A running cluster with 4 hosts (2 minimum, 4 recommended)
- `lv` binary in PATH
- `LV_HOST` pointing to one cluster node
- A base image already pulled (default name: `ubuntu`)
- Admin-level credentials

## Quick start

Two variables are **required** and the suite silently skips without them:
`LITEVIRT_E2E=1` opts in to touching a live cluster, and `LV_BIN` must point at
the binary under test so a stale system-wide `lv` is never exercised by mistake.
Miss either and the run prints one line and exits 0, which reads like a pass:

```
E2E: set LITEVIRT_E2E=1 to run live e2e tests; skipping
E2E: LITEVIRT_E2E=1 but LV_BIN is not set — point LV_BIN at the binary under test
```

```bash
# Build fresh binaries
make build

# Opt in, and pin the binary under test
export LITEVIRT_E2E=1
export LV_BIN=$PWD/bin/litevirt

# Set target
export LV_HOST=root@10.0.50.10

# Run all tests (30 min timeout)
go test ./tests/e2e/ -v -timeout 30m -count=1

# Run only fast tests (skip migration, failover, backup)
E2E_SKIP_SLOW=1 go test ./tests/e2e/ -v -timeout 15m -count=1

# Run specific phase
go test ./tests/e2e/ -v -timeout 10m -run TestREST
go test ./tests/e2e/ -v -timeout 10m -run TestCompose
go test ./tests/e2e/ -v -timeout 10m -run TestError
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LITEVIRT_E2E` | (required) | Must be `1`. Without it the suite skips without running anything. |
| `LV_BIN` | (required) | Path to the litevirt/lv binary under test. Enforced so a run can never silently exercise a stale system-wide `lv`. |
| `LV_HOST` | (required for remote mode) | SSH target for CLI, e.g. `root@10.0.50.10`. Omit when running ON a cluster node. |
| `E2E_IMAGE` | `ubuntu` | Base image name for test VMs |
| `E2E_HOSTS` | (auto-detected) | Comma-separated host names |
| `E2E_REST_URL` | `http://<first-host>:7446` | REST API base URL |
| `E2E_REST_TOKEN` | (skip REST tests) | API token for REST tests |
| `E2E_SKIP_SLOW` | `0` | Set to `1` to skip migration/backup tests |

## Test phases

| Phase | Tests | What it covers |
|-------|-------|----------------|
| 0 | Setup | Discover cluster topology |
| 1 | Cluster & hosts | status, health, digest, host inspect/drain/undrain/labels/config/stats |
| 2 | Images | list, push to other host |
| 3 | VM lifecycle | create, start, stop, restart, delete, force-stop, logs |
| 4 | VM hot-update | CPU/memory update on running VM |
| 5 | Snapshots | create, list, restore, delete |
| 6 | Migration | Live migrate, cold migrate between hosts |
| 7 | Networks | Create/delete bridge, VM with custom network |
| 8 | Compose stacks | Deploy, scale up/down, rolling update, teardown |
| 9 | Users & RBAC | User CRUD, token create/revoke |
| 10 | Monitoring | Audit log, Prometheus metrics |
| 11 | REST API | All endpoints: health, hosts, VMs, snapshots, users, auth |
| 12 | State convergence | VM visible from different hosts, digest consistency |
| 13 | Error handling | Nonexistent resources, duplicates, invalid images, bad auth |
| 14 | Concurrent ops | Parallel VM creation across hosts |
| 15 | Backup & restore | Full backup to file, restore to new VM |
| 16 | Disk/NIC ops | Attach/detach disk, attach/detach NIC |
| 17 | Web UI | Port reachability check |
| 18 | Ansible | Inventory output validation |

## Cleanup

Tests clean up after themselves via `t.Cleanup()`. All test resources use the prefix `e2e-` with a unique PID-based suffix for easy identification.

If tests are interrupted, clean up manually:

```bash
# Find and remove leftover test VMs
lv ls | grep e2e- | awk '{print $1}' | xargs -I{} lv rm {} --force

# Find and remove test networks
lv network ls | grep e2e- | awk '{print $1}' | xargs -I{} lv network rm {} --force

# Find and remove test users
lv user ls | grep e2e- | awk '{print $1}' | xargs -I{} lv user delete {}

# Remove test labels
for h in $(lv host ls | awk 'NR>1{print $1}'); do
  lv host label rm $h e2e-test e2e-rest 2>/dev/null
done
```

## Partition-safety drills (nested lab)

`drill_*_test.go` turn the kvm003 partition-safety drills
(docs/design/partition-pause.md §8, docs/design/recovery-claims.md §7.3) into
tests. They cut the cluster LAN with nftables, freeze daemons and power hosts
off, so they do not run on a cluster node: they run on the machine that hosts
the nested lab (`~/litevirt-lab`, see its `lab.sh`) and reach every node over
its NAT'd SSH port, which the cluster-LAN rules never touch.

Every claim about where a workload executes is read from `virsh` and `lxc-ls`
on every node, sampled once a second (`lab_harness_test.go`), never only from
litevirt's own view. The central assertion is that in no sample does any
workload execute on two hosts at once; a paused or frozen copy is not
executing.

### Running

```bash
# on the laptop: build the test binary and ship it to the lab host
CGO_ENABLED=0 go test -c -o e2e-drills.test ./tests/e2e/
scp e2e-drills.test kvm003-f3:litevirt-lab/

# on kvm003-f3, in ~/litevirt-lab
export LITEVIRT_E2E=1
export LV_BIN=/usr/local/bin/litevirt     # the binary ON THE NODES (lab mode)
export E2E_LAB_DIR=$PWD                   # enables lab mode
export E2E_EVIDENCE_DIR=~/drill-evidence/e2e-<sha>
./e2e-drills.test -test.v -test.timeout 90m -test.run 'TestDrill[0-5]|TestDrillBlip'
```

Run them one at a time or in that order; each one starts by requiring the lab
at rest and ends by restoring it. Lab mode skips every other e2e test (they
drive a local `lv`).

| Variable | Default | |
|---|---|---|
| `E2E_LAB_DIR` | (required) | lab checkout with `lab.sh` and `cluster_key`; turns lab mode on |
| `LV_BIN` | (required) | in lab mode, the `lv` path on the nodes |
| `E2E_LAB_NODES` | `5` | nodes are `node-1`..`node-N` |
| `E2E_LAB_PORT_BASE` | `2230` | node N's SSH is `127.0.0.1:(base+N)` |
| `E2E_EVIDENCE_DIR` | (none) | per drill: `samples.log` (every sample), `timeline.txt`, extra evidence |
| `E2E_DRILL_IMAGE` / `E2E_DRILL_MEMORY` | `cirros` / `128M` | the drills' own test VMs |
| `LITEVIRT_E2E_DESTRUCTIVE` | (none) | `1` also runs drill 6, which destroys and rebuilds hosts |

### The drills

Timings come from `internal/health` (`T_pause`, `W(n)`, `E`, `F`) and the
design's §4.1 derivation; `checkDesignTimings` fails a drill whose restated
probe constants drift from them.

| Test | What it proves | Takes |
|---|---|---|
| `TestDrill0_LabAtRest` | lab at rest; the sampler agrees with litevirt about every running workload | seconds |
| `TestDrill1_SplitTwoThree` | {node-1,node-2} \| {node-3..5}: the minority pauses no sooner than `T_pause` and no later than `D_M+Δ+T_pause+Δ+E`; replacements start no sooner than `(F−1)·P+W`; the replacement disk has the recorded size; after the heal the superseded copies stop and keep their disks; never twice; no `vm_dual_run` | ~8 min |
| `TestDrillBlip_FleetWide` | every node cut off from every other: a blip under `T_pause` pauses nothing; a long blip pauses every recoverable workload (a container on the LXC host included), fences nothing, replaces nothing and resumes everything in place; no `partition_pause_failed` on a host without LXC | ~6 min |
| `TestDrill2_FrozenLeaseHolderWhileAHostFails` | the failover lease holder is SIGSTOPped (fence strategy `manual`) past its lease while another host loses power: one recovery, one proof, and the thawed holder mints nothing under its stale term | ~8 min |
| `TestDrill3_VoterRemovedAfterAFence` | a fenced host is `lv cluster voter rm`ed, then a second host fails: its workloads recover by claims decided in the reduced generation, accepted only by its members; the voter is added back | ~8 min |
| `TestDrill4_OwnerReachableVetoesTheClaim` | the coordinator reaches its fence quorum for a host the other voters still reach: they refuse with `recovery_claim_owner_reachable`, no proof is minted, the workload never moves (owner runs `partition_pause: false`, restored after) | ~7 min |
| `TestDrill5_LegacyRecoveryWithClaimsOff` | `recovery_claim: false` on every host (rolling restarts): a powered-off host's workloads recover once, by a proof without a claim certificate; the flag is restored | ~12 min |
| `TestDrill6_ForceReconfigureAndRebuild` | destructive: three of five hosts lost, fences confirmed, `lv cluster voter force-reconfigure` to the two survivors, recovery with no workaround, `lv host rm --dead`, the workloads still recorded on the removed hosts recovered or removed, rebuild with `lab.sh destroy/create/up`, `lv host add` (a host fenced during its join fails the drill), `lv cluster voter add` back to five, the removed lab workloads put back | ~40 min |

Findings the drills used to skip or work around are fixed on main, and the
drills now assert them directly: N3 (recovery on a forced 2-voter generation)
and N4 (a stale claim destination) in drill 6, N7 (disk rows follow the VM)
in drills 1, 2, 3 and 5, P1 (the coordinator relies on an owner's partition
pause only on its latest probe answer) in drill 4, and R1 (a rebuilt host
fenced during its join) in drill 6.

Drill 6 cannot add a rebuilt host back while workloads are still recorded on
its removed name: `lv host add` refuses it (R4). After `lv host rm --dead` it
waits for the coordinator to recover what it can, then removes what is left
(a policy-none VM, a container no survivor can run, a VM the survivors have no
room for) with `lv rm --force` and `lv ct rm`. Once the hosts are back it
brings the removed VMs' stacks up again from their `lv compose export` (the
plan must create only) and re-creates the containers from their create spec.

On main-e004c250 drill 6 fails at that clearing step, and the restore cannot
finish: `lv rm` and `lv ct rm` forward to the workload's recorded host, and a
removed host resolves neither from cluster state nor from gossip ("cannot
reach host node-3: look up host ... not found in cluster state or gossip"),
so a policy-none VM or a relocate-skipped container recorded on a removed
host can be neither recovered nor removed, and its name cannot be added back.
It also fails earlier on recovery: nothing recovers on the forced 2-voter
generation until `lv host rm --dead`, because the coordinator judges the
operator's confirmation to predate the outage (observer streaks are measured
as `consecutive_failures × P`, and a powered-off host fails a probe about
every 3 s, not every P = 2 s). Drills 2 and 3 fail `disk rows follow the
replacement` on a returning host whose startup hardware backfill re-writes
the disk row from its stale replica.

### Leaving the lab as it was found

Each drill registers a restore before it injects anything: clear the drill
nftables table on every node, power every node on, SIGCONT a frozen daemon,
put back any `config.yaml` it changed (`config.yaml.e2e-orig`, one restart at
a time, 25 s apart), restore fence strategies, `lv host undrain` hosts left
fenced, `lv cluster voter add` removed voters, delete its own test VMs and
containers (and any domain or disk file they left on a node), wait for no
paused guest, start any pre-existing workload that was running before, then
verify: every host `HOST_ACTIVE`, every host a voter, no drill nftables
table, no config backup, original fence strategies. Placement is not restored:
a failed-over VM stays where failover put it.

If a run is killed, the same state can be checked by hand:

```bash
for n in 1 2 3 4 5; do ./lssh $n 'nft list tables | grep -E "e2e_drill|drill"; ls /etc/litevirt/*.e2e-orig'; done
./lssh 1 'lv host ls; lv cluster voter ls'
```
