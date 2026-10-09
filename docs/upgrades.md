# Upgrades

> Companion to [installation.md](installation.md) §Upgrading. This doc focuses
> on **what makes a litevirt self-upgrade safe** — pre-flight gates, the
> `upgrading` host state, the auto-rollback mechanism, and operator playbooks.
>
> Scope: upgrades of `litevirt` and `lv` only. Host-OS / kernel / Ceph /
> libvirt upgrades have separate considerations covered in
> [operating-model.md](operating-model.md).

---

## TL;DR

```sh
# Recommended path:
lv host preflight-upgrade host-b      # check first
lv host upgrade --binary ./litevirt  # upgrade all hosts (preflight runs again automatically)
```

If the new binary panics on startup, systemd's `OnFailure` hook restores
the previous binary automatically. If pre-flight blocks the upgrade, the
output tells you why; pass `--force` only after addressing the cause.

---

## Why upgrades are safe by default

Six guarantees the upgrade pipeline enforces:

1. **No VM dies on a steady-state upgrade.** QEMU is a child of `libvirtd`,
   not `litevirt`. The systemd unit ships `KillMode=process`, and the
   daemon self-checks this at startup — refusing to start under any unit
   that would cgroup-kill its children.

2. **No false-positive fence during the restart window.** The host marks
   itself `upgrading` in the cluster state before re-exec — and also on any
   graceful shutdown (SIGTERM from `systemctl restart/stop`), so a plain daemon
   restart isn't mistaken for a failure either. Failover coordinators on peer
   hosts skip fence candidacy for `upgrading` hosts, but only up to a timeout
   (2 min): a host that entered `upgrading` and never came back is still fenced,
   so its VMs aren't stranded. The new daemon transitions back to `active` on
   healthy startup, and a host left `offline` by a transient blip is
   auto-recovered to `active` once a fresh quorum sees it healthy.

3. **Auto-rollback on a panicking binary.** If the new daemon panics
   past systemd's `StartLimitBurst=10` within 5 minutes, the
   `litevirt-rollback.service` companion unit fires automatically:
   restores `/usr/local/bin/litevirt.old` over the bad binary, resets
   the failed state, restarts. It only does so while an upgrade is
   actually in progress — see the sentinel gate below. Logged to journal
   with tag `litevirt-rollback`.

4. **A forward-migrated DB does NOT block an older binary.** `schema_state.version`
   in Corrosion tracks what version migrated this DB, but a daemon that
   expects an older `CurrentSchemaVersion` than the DB has still starts.
   Migrations are additive-only (CI-enforced), so the older binary tolerates
   columns it does not know about, and that tolerance is what makes a rolling
   upgrade reversible.

   Rolling a binary back is **not** gated on the schema. What a
   rollback still needs care with is replicated statement shapes a downgraded
   node cannot decode — see the capability notes below.

5. **Schema-skew check in CRDT replication.** Every `PushMutations`
   request carries the sender's DB-applied schema version. A receiver
   refuses the push (`FailedPrecondition`) whenever the sender's schema is
   *strictly ahead* of its own — even by one — because the sender's writes
   may reference columns the receiver lacks. The check is asymmetric: a
   sender that is *behind* is accepted (additive-only migrations mean it
   touches a subset of the receiver's columns). Multi-version (N-step)
   rolling upgrades stay safe because the pre-stage pass equalizes every
   node's schema before any binary swap, so the live gap is 0 — not because
   of any version tolerance.

6. **Pre-flight gate.** `lv host upgrade` runs `PreflightUpgrade` and
   refuses on blocking conditions (in-flight migrations, leader-lease
   holdings with pending fences, large replication backlog, big clock
   skew, witness-host risk). Pass `--force` to override.

---

## The pre-flight gate

Before the binary swap, the daemon scans for conditions that would make
a restart unsafe. Findings are tagged `block` (refuses) or `warn`
(proceeds with logged warning).

### What it checks

| Code | Severity | Condition |
|---|---|---|
| `vm-transient` | block | Any VM on this host in `migrating | starting | creating | stopping | rebuilding` state. |
| `migrate-incoming` | block | Any VM migrating *into* this host (the destination side dies if the daemon restarts). |
| `leader-with-pending-fence` | block | This host holds the failover lease AND a non-success fence row was written in the last minute. |
| `replication-backlog` | warn | `mutation_log` has > 50,000 rows; restart will extend replication lag. |
| `clock-skew` | warn | This host has > 5 s skew with any peer; HLC reset on restart could land badly. |
| `witness-restart` | warn | This is a witness host for an even-N cluster; restart interrupts the tiebreak. |

### Manual pre-flight

```bash
lv host preflight-upgrade host-b
```

Reports findings without performing the upgrade. Use this before
scheduled maintenance to know what state the cluster needs to be in.

### Override

```bash
lv host upgrade --force
```

Skips `block`-level findings (warnings are still printed and logged).
Use this only when you understand the risk — for example, you've
*already* confirmed the in-flight migration is going to be aborted.

---

## How a normal upgrade flows

```
1. lv host upgrade --binary ./bin/litevirt
        │
        ▼
2. CLI lists cluster hosts; identifies which are outdated.
        │
        ▼
3. For each host (connected host last):
        a. Open SSH session to the host.
        b. Stream binary over gRPC ─→ daemon receives chunks, SHA-256.
        c. Daemon runs PreflightUpgrade (unless --force).
              ↳ blocks → operator addresses or --force.
        d. Backup current binary to /usr/local/bin/litevirt.old.
        e. Atomic rename: staging → /usr/local/bin/litevirt.
        f. Refresh systemd unit (KillMode=process + rollback OnFailure).
        g. Mark host state = "upgrading" (peers won't fence it).
        h. Send response, signal ReExecCh.
        i. Daemon main loop returns ErrReExec → cmd/litevirt
           calls syscall.Exec(binary) → PID is preserved for systemd.
        │
        ▼
4. New daemon startup:
        a. Pre-flight check: KillMode=process? Else refuse.
        b. InitSchema: applies any new migrations. Refuse if the local
           schema_state.version > binary's CurrentSchemaVersion.
        c. Mark host state = "active" (peers stop suppressing fence).
        d. Resume serving gRPC.
        │
        ▼
5. CLI verifies the new daemon is healthy via Ping; moves to next host.
```

The connected host (the one `LV_HOST` points at) is upgraded **last** so
the operator's gRPC connection stays alive throughout the rolling
upgrade. The self-upgrade still works because the SSH session and the
daemon process are independent.

---

## Auto-rollback

### How it triggers

The systemd unit has:

```
[Unit]
StartLimitBurst=10
StartLimitIntervalSec=300
OnFailure=litevirt-rollback.service

[Service]
Restart=always
RestartSec=5
RestartPreventExitStatus=10
```

If the new binary panics on startup, systemd restarts it. Ten failures within
5 minutes trip `StartLimitBurst`, the unit enters `failed` state, and
`OnFailure=` fires the rollback service. The burst is deliberately generous:
a burst of *external* restarts (a package manager's needrestart during an apt
run) must not trip the limit, because that would fire the rollback against a
perfectly healthy binary.

`Restart=always`, not `on-failure`. systemd counts termination by SIGHUP,
SIGINT, SIGTERM or SIGPIPE as a **clean** exit, and `on-failure` restarts on
none of them — so a SIGHUP from needrestart or unattended-upgrades left the
daemon dead with the unit reporting `Result=success` and `NRestarts=0`, and
nothing brought it back (kvm001, 2026-07-24, ~3h). The daemon also ignores
SIGHUP and SIGPIPE outright, so the two guards are independent.

`RestartPreventExitStatus=10` is the exception `Restart=always` needs:
`lv uninstall <hostname>` removes the unit files and the binary and then exits 10,
and without this systemd would restart a unit with no `ExecStart` left.

### What the rollback service does

The rollback is **gated on the `.upgrade-pending` sentinel**: it restores the
previous binary only when an upgrade is actually in progress. Without that gate
any failed state — including a restart storm against a perfectly healthy binary
— would downgrade it and could burn the only `.old` (the 2026-07-15 outage).

```
[Service]
ExecStart=/bin/sh -c '\
  if [ ! -f /usr/local/bin/litevirt.upgrade-pending ]; then \
    logger -t litevirt-rollback "litevirt entered a failed state but no upgrade is in progress (no sentinel) — NOT rolling back the binary; leaving it for systemd/operator"; \
    exit 0; \
  fi; \
  if [ -f /usr/local/bin/litevirt.old ]; then \
    logger -t litevirt-rollback "RESTORING previous litevirt binary after failed upgrade"; \
    mv /usr/local/bin/litevirt.old /usr/local/bin/litevirt; \
    systemctl reset-failed litevirt.service; \
    systemctl start litevirt.service; \
  else \
    logger -t litevirt-rollback "no .old binary to roll back to; leaving litevirt in failed state"; \
    exit 1; \
  fi'
```

### What the rollback is conditional on — and what has not been verified

The rollback fires only when **both** conditions hold:

1. **The `.upgrade-pending` sentinel exists.** Without it the rollback service
   deliberately does nothing and leaves the failed binary in place, logging that
   it declined. That is the intended behaviour, not a fault: a failed state with
   no upgrade in progress must not silently downgrade a healthy binary.
2. **`/usr/local/bin/litevirt.old` exists.** With the sentinel present but no
   `.old`, the service logs that there is nothing to roll back to and exits
   non-zero, leaving the unit failed.

So a daemon that will not start is **not** evidence that a rollback was
attempted. Read the journal before concluding anything.

**This path has not been confirmed end to end through a live systemd upgrade.**
The unit wiring, the sentinel gate and the shell logic are as documented and
reviewed, but no rollout has yet driven a real panic-loop through it on a live
host. Treat the behaviour above as **expected**, not verified, and check the
journals rather than assuming it ran.

**Before relying on the auto-rollback after `recovery_claim_v1` has latched**,
make sure every host's config sets `enforcement.recovery_claim: true`
explicitly: the previous build reads a missing key as `false`, and it is not
WAL-quarantined for it (see *Recovery claims latch after the roll* below).

**Restoring `.old` restores the previous binary's behaviour in full** — including
any limitations that build had. A rollback is a return to a known state, not a
repair: whatever the older binary refused, mis-handled or did not yet implement,
it will refuse, mis-handle and not implement again. In particular a build carrying
prerelease behaviour that a later build deliberately refuses to migrate is exactly
the build the cluster returns to.

### Verifying a rollback fired

Check **both** journals. They answer different questions, and the rollback
service's own log is the only place its *decision* is recorded:

```bash
journalctl -t litevirt-rollback          # did the rollback run, decline, or find no .old?
journalctl -u litevirt-rollback.service  # the unit's own start/exit status
journalctl -u litevirt.service           # why the daemon failed in the first place
systemctl status litevirt                # should be active again, on the .old binary
litevirt --version                       # confirms the rolled-back version
```

A `litevirt.service` journal showing repeated startup failures with **nothing**
in the `litevirt-rollback` journal means the rollback service never fired at all
— check `OnFailure=` wiring and whether the unit actually reached `failed`
state rather than being restarted indefinitely.

The systemd rollback unit handles the **panic-loop** case: a binary that
crashes/exits on startup. The **post-upgrade health watchdog** (below) covers
the complementary "starts but doesn't function" gap. Together they do NOT cover:

- Subtle regressions that don't trip either mechanism (e.g., wrong placement
  decisions — the binary is intrinsically functional). Catch these with
  metrics + alerts, not auto-rollback.

## Post-upgrade health watchdog

When the upgrade RPC (or the `from_peer` self-upgrade) swaps in a new binary, it
arms a node-local **sentinel** next to the binary (`<binary>.upgrade-pending`).
On the re-exec, the new daemon's watchdog — armed *first*, before any
potentially-hanging init, so a hung boot is still caught — verifies the binary is
**intrinsically functional**: it self-`Ping`s the local gRPC endpoint over real
mTLS (the local host cert; the cert includes `127.0.0.1`) until a deadline.

- **Healthy** (Ping succeeds before the deadline) → clears the sentinel and flips
  the host `upgrading → active`. (On an upgrade boot the host deliberately stays
  `upgrading` until this confirmation; version/resources are written immediately
  regardless.)
- **Unhealthy** (local gRPC never answers within the deadline — e.g. a hung
  `InitSchema`, or a daemon that serves but is wedged) → restores `<binary>.old`
  over the running path and exits non-zero so systemd restarts the **restored**
  binary. This is a **one-attempt** flap guard: the sentinel records the attempt,
  so if the restored binary is *also* unhealthy the watchdog gives up rather than
  flap, deferring to `StartLimitBurst` / the failover coordinator.

**Scope — binary-intrinsic faults only.** Environmental faults (libvirt down,
replication backlog, broken PKI) are deliberately NOT gated by the watchdog:
they'd break the previous binary equally, so rolling back would just flap.

**Config.** `upgrade_watchdog_enabled` (default `true`) and
`upgrade_health_deadline_sec` (default `120`, wide enough for a slow N-step
schema migrate). Override-disable with `LITEVIRT_UNSAFE_NO_UPGRADE_WATCHDOG=1`.
Outcomes are exported as `litevirt_upgrade_watchdog_total{outcome}`
(`confirmed` / `confirm_failed` / `rollback` / `giveup` / `no_old`).

**Binary path.** The watchdog targets the **actually-running** binary
(`os.Executable()`, matching the upgrade swap and the re-exec), so it is correct
for any install path. The systemd rollback *unit* still references the canonical
`/usr/local/bin/litevirt` (as does its `ExecStart`); on a standard systemd
install these coincide.

---

## What can go wrong (and how to recover)

### Pre-flight blocks the upgrade

```
$ lv host upgrade
Error: upgrade pre-flight blocked 1 condition(s); pass --force to override or address them first
```

Run `lv host preflight-upgrade <host>` to see the specific finding.
Common causes:

| Finding | Fix |
|---|---|
| `vm-transient` | Wait for the in-flight VM operation to complete |
| `migrate-incoming` | Wait for the migration; abort if stuck |
| `leader-with-pending-fence` | Resolve the fence (or wait for it to time out) |

### `KillMode` self-check refuses startup

```
preflight: unsafe systemd unit: KillMode="control-group" (want "process"); ...
```

The systemd unit was edited and `KillMode` is wrong. Fix:

```bash
sudo cp /etc/systemd/system/litevirt.service /tmp/litevirt.service.bak
# Edit /etc/systemd/system/litevirt.service so KillMode=process
sudo systemctl daemon-reload
sudo systemctl restart litevirt
```

Or override (development / non-systemd hosts only — VMs are at risk!):

```bash
LITEVIRT_UNSAFE_NO_KILLMODE_CHECK=1 systemctl restart litevirt
```

### Schema-version refusal

```
schema downgrade refused: DB schema version is 5, binary expects 1
```

Someone is starting an older binary against a DB that a newer binary
already migrated. Either run the matching binary version, or restore the
DB from a snapshot taken before the forward migration.

### Schema-skew refusal in replication

Peer logs:

```
pushMutations: schema skew too large; refusing
sender_schema=5 local_schema=1
```

This host is too far behind. Upgrade it, or temporarily isolate it
from CRDT replication while the gap is closed.

### Rollback didn't fire automatically

If 3 panics in 10 min didn't trigger `OnFailure`, check:

```bash
systemctl show litevirt -p StartLimitBurst -p OnFailure
```

If the values are wrong, the unit on disk has drifted from the canonical
template. Run a clean upgrade — `updateSystemdUnit` (in
`internal/grpcapi/upgrade.go`) writes the canonical unit file.

### Manual rollback (anytime)

```bash
ssh root@<host>
mv /usr/local/bin/litevirt.old /usr/local/bin/litevirt
systemctl reset-failed litevirt
systemctl restart litevirt
```

---

## Operator playbook for cluster-wide upgrades

A typical rolling upgrade across, say, 5 hosts:

1. **Pre-check.** On a workstation:
   ```bash
   make build                            # produce the new binary
   for h in $(lv host ls --names); do
     lv host preflight-upgrade $h
   done
   ```
   Resolve any `block` findings before proceeding.

2. **Upgrade.**
   ```bash
   lv host upgrade --binary ./bin/litevirt
   # CLI sequences hosts; connected host last.
   # Each takes ~10 s + the time PreflightUpgrade waits.
   ```

3. **Verify.**
   ```bash
   lv host ls                  # all VERSION columns match
   journalctl -t litevirt-rollback   # should be empty
   ```

4. **Post-check.** Spot-check a VM lifecycle:
   ```bash
   lv restart <one-vm>
   ```

For larger fleets (50+ hosts), upgrade in waves of 10 with a verification
pass between waves. A daemon-side rolling-upgrade orchestrator is on
the roadmap; today the CLI does it serially.

### Seeding a rolling upgrade, and the bare-restart hazard

Two operational gotchas, both learned the hard way:

**1. `lv host upgrade` with no host args rolls the `--binary` to every host not
already on its version.** The "target version" is read from the binary itself
(it's probed with `litevirt --version`), so the common case — build a new
binary and roll it to a cluster that's currently uniform on the old version —
just works:

```bash
lv host upgrade --binary ./bin/litevirt --yes   # rolls to every outdated host
```

Naming hosts is still supported and **always (re)deploys** them regardless of
version — useful to re-seed the same version after a manual change, or to
control order:

```bash
lv host upgrade host-01 --binary ./bin/litevirt --yes
```

**2. NEVER seed by hand-restarting the daemon on a healthy host:**

```bash
# ☠️  DO NOT DO THIS on a live cluster:
cp litevirt.new /usr/local/bin/litevirt && systemctl restart litevirt
```

A bare `systemctl restart` bypasses the `upgrading` state that
`lv host upgrade` sets. The failover **leader** sees the host vanish for a
few seconds and opens a fence against it. The fence usually can't complete
(SSH-poweroff fails), so it lingers as a stale `partial` record — and a
stale fence record on the leader then *blocks the leader's own upgrade*
(`leader-with-pending-fence`). Always upgrade through `lv host upgrade`,
which marks the host `upgrading` (the coordinator skips `offline`,
`maintenance`, `fenced`, and `upgrading` hosts). If you must hand-restart a
host, put it in maintenance first (`lv host drain <host>`), restart, then
return it.

**Overriding a stale block.** `--force` is sent to the daemon, so a
genuinely-stale server-side block can be overridden:

```bash
lv host preflight-upgrade <host>             # confirm the block is stale first
lv host upgrade <host> --binary <new> --force --yes
```

Only force after confirming the finding is a false positive (e.g. a fence
record from minutes ago for a host that's actually healthy).

### Secrets move to the sensitive lane after the roll

Three secrets used to live only in columns of public inventory tables:
`hosts.ipmi_pass`, `users.password_hash` and `tokens.token_hash`. Schema v56
adds three tables that only the peer-only sensitive lane carries —
`host_fence_credentials`, `user_credentials` and `token_credentials` — and the
secrets move into them **on their own, after the last host has upgraded**. No
flag starts it; the `credentials_split_v1` capability token does.

The ordering is fixed by what a host still on the previous release can do. It
cannot decode a statement on a credential table (the apply fails closed and its
replication stream stalls), and it reads a secret from the old column and
nowhere else. So while any host the cluster replicates to — including one
parked in `maintenance` — runs the previous release:

- nothing is written to the credential tables;
- every password change, token and IPMI password is written to the old column,
  exactly as before, so every host fences, logs in and validates tokens the way
  it did.

`credentials_split_v1` is mandatory and replication-gated: it latches only once
every memberlist member advertises it. From then on, on each host:

- every writer writes the secret to **both** places, in one batch under one
  `updated_at`: the credential table and the old column;
- a pass that runs at start and every minute copies an old-column secret into
  the credential table only where the credential table has **no row** for it.
  It **never clears the old column**;
- readers take the credential row whenever one exists, and the old column only
  when none does.

Readers and the pass never compare the credential row's `updated_at` with the
public row's. The public row's `updated_at` moves on every unrelated write to
it, such as a host's version report or a user's role change. When one of those
reaches a host ahead of a password rotation, that host's last-writer-wins check
refuses the rotation's public-row half, so it holds the OLD password on a NEWER
public row. A rule that preferred the newer row would serve the rotated-out
password, and the pass would copy it over the credential row.

This is the dual-write step of a column move, and the release stops there.
Every old column still holds the current secret, so the public rows, and the
operator-safe state dump built from them, **still carry the secrets in this
release**. Clearing the old columns is a later release's step, behind a second
mandatory, replication-gated token (see
[design/credentials-clear.md](design/credentials-clear.md)).

Latches form per host, so for a few seconds after one host latches its
neighbour may not have yet. A password or IPMI change made through that
neighbour in that window goes to the old column only. Such a write is
recognisable from the write itself: a latched host always writes the
credential row in the same replicated batch, so a batch that sets a secret
with no credential-table statement came from a host that had not latched. Every
host that applies such a batch absorbs the secret into its credential row,
locally, under the batch's own `updated_at` and only if that is newer. A latched
host may create the row; a host that has not latched only updates a row it
already holds, which includes the host the change was made through. A rotated
password therefore stops working everywhere the rotation has reached, with no
pass-interval delay. A host that missed the batch (for example, it repaired the
public row from anti-entropy instead) picks up the absorbed credential row
through sensitive-lane anti-entropy, because every host that applied the batch
wrote the same row.

**What the two copies buy on a rollback.** A rollback below a latched token
is still not clean. A binary rolled back below a capability token this host
already latched enters **WAL quarantine** at startup (the capability-rollback
preflight; its log line says "entering WAL quarantine"). It keeps running, but
it emits no replicated writes until it is upgraded again or reseeded. It also
cannot decode the credential tables' statements that latched peers keep
sending. What dual-writing changes is narrower:

- a host on the previous release, whether it has not upgraded yet or was
  rolled back, reads only the old columns, and they are current. It still
  validates API tokens, checks passwords and fences with the current IPMI
  password, including for secrets set or rotated after the latch. Under
  quarantine a password login still cannot complete, because minting the
  session is a replicated write. With the old columns cleared, as the first
  `credentials_split_v1` build did, that host lost all three;
- upgrading that host again loses nothing. The credential tables and the old
  columns both hold every secret.

A host that ran the **pre-release build that cleared the old columns** (the
first `credentials_split_v1` build) holds empty old columns. This release
reads its credential rows, so nothing is lost while it stays on this release or
later. Until each secret is written again it gets none of the rollback benefit
above: rolled back, its old-column reader finds nothing. A
password change, or an IPMI password set again with
`lv host config <host> --ipmi-pass`, puts the value back in the old column. An
API token's hash cannot be rewritten; replace the token with a new one and
revoke the old.

Until the token latches, `litevirt_ha_degraded{reason="capability_rollout_pending"}`
is set, as it is for every mandatory token mid-roll. If it stays set after the
roll, a host is still on the previous release — most often one in
`maintenance`.

### Host state moves to its own row after the roll

A host's state (`joining`, `active`, `draining`, `maintenance`, `upgrading`,
`offline`, `fenced`) and its isolation epoch used to live only in the `hosts` row, beside
the version, schema and resources the host reports about itself. That row has
one `updated_at`, and replication applies a write only if it is newer than the
row, so a state change and a concurrent version report could lose each other:
the host that applied the newer one first refused the older one. Schema v57
adds `host_membership`, one row per host with its own `updated_at`. State and
isolation are copied into it **on their own, after the last host has
upgraded**. No flag starts it; the `host_membership_split_v1` capability token
does.

The ordering is fixed the same way as for secrets. A host on the previous
release cannot decode a statement on `host_membership`, and it reads state
only from `hosts.state`. So while any host the cluster replicates to —
including one parked in `maintenance` — runs the previous release:

- nothing is written to `host_membership`;
- every drain, fence, maintenance, boot and isolation is written to `hosts`,
  exactly as before.

`host_membership_split_v1` is mandatory and replication-gated. Once it has
latched on a host, that host:

- runs a pass at start and every 10 seconds that gives every host a
  `host_membership` row, stamped with the `hosts` row's `updated_at` so every
  host's copy is identical. The pass copies; it never clears or changes the
  `hosts` columns;
- after its first complete pass, writes every state and isolation change to
  **both** `host_membership` and the `hosts` columns, in one batch with one
  `updated_at`. The `hosts` half uses the previous release's statements, so a
  host rolled back one release still reads every change;
- reads state and isolation — for `lv host ls`, the voter set, fencing, relay
  election and replication refusal alike — from `host_membership`, falling
  back to `hosts` for a host that has no row yet. Before its first pass it
  reads `hosts`, as before.

A reader never compares the two copies. The `hosts` copy still shares its
row's clock with the host's own reports, so on a host that refused the `hosts`
half of a fence because a version report was newer, the `hosts` row is the
newer one and its state is the stale one. Readers take `host_membership`, and
nothing moves a `hosts` value into it merely because that value differs or
its row is newer.

Latches form per host, so for a few seconds after one host latches its
neighbour may not have yet. A drain or fence made through that neighbour in
that window goes to `hosts` only, as does any write from a host rolled back
one release. Such a write is recognised by where it came from: a latched
host's writes always carry their `host_membership` statement in the same
replicated batch, so a batch that writes `hosts` state or isolation without
one came from a host that was not writing `host_membership` yet. A latched
host applying such a batch writes the change into its own `host_membership` row in
the same transaction, with the write's own `updated_at`, if that is newer than
the row, creating the row if it has none. It does not replicate that change:
every host that sees the batch computes the same row from it, and anti-entropy
carries the row to one that did not.

A host that has not latched yet does the same to a `host_membership` row it
already holds — one a latched peer wrote — but never creates one. That includes
its own writes: the host that fences another through the old columns alone
updates its own copy of that host's row in the same transaction, so when it
latches it reads the fence at once rather than a latched peer's older copy.

Two changes still wait for anti-entropy, typically a minute or two. One is a
change that reached a host before that host held any `host_membership` row for
the host concerned; a peer's older copy arriving later is then what it serves.
The other is a change that reached a latched host only through anti-entropy
repair of the `hosts` row (which moves rows, not batches). If no latched host
received the batch itself, that second change is not absorbed anywhere and is
lost, exactly as it could be before v57.

An absorb that fails fails its write: a replicated batch is rolled back and
back-pressured, and a local write returns the error. It never commits the
`hosts` half without the `host_membership` half.

**What the two copies buy on a rollback.** The `hosts` columns stay current,
so a host on the previous release reads the right state, voter set and
isolation. As for `credentials_split_v1`, a binary rolled back below the
latched token still enters WAL quarantine at startup and emits no replicated
writes until it is upgraded again or reseeded, and it cannot decode the
`host_membership` statements that latched peers keep sending. Upgrading it
again loses nothing. Roll forward.

Retiring the `hosts` copy is a later release's step, behind a second token; see
[design/host-membership-retire-old-columns.md](design/host-membership-retire-old-columns.md).

### An unverified fence records `offline` after the roll

A host recorded `fenced` used to mean "a fence succeeded", whatever the fence
was. An SSH poweroff that nothing verified recorded it just as an IPMI
power-off observed off did, and readers took the state as proof the host was
off (colonelpanik/litevirt#253). Two things change:

- **At once, on each upgraded host:** nothing takes a `fenced` state as proof
  of power-off unless the host's newest fence is proof-grade (`ipmi`, or
  `lv host fence-confirm`). Owner-assert asks an SSH-fenced host whether it
  runs a workload, `lv host rm --dead` refuses a host whose `fenced` state
  rests on an SSH fence, and the voter-loss condition asks such a host which
  machine it is. This reads the rows every fence already wrote; nothing is
  backfilled.
- **After the last host has upgraded:** the mandatory, replication-gated
  `fence_state_v1` token latches, and from then on an SSH, watchdog or
  best-effort fence records the host `offline`, not `fenced`. Recovery is
  unchanged: the coordinator still reschedules on such a fence, a successor
  resumes from it, and the host is not put back in service automatically
  once its workloads have moved. Until the token latches — while any host
  the cluster replicates to, one parked in `maintenance` included, runs the
  previous release — such a fence keeps recording `fenced`, because a
  coordinator on that release resumes a recovery only from `fenced`.

What an operator sees after the latch: `lv host ls` lists an SSH-fenced host
as `offline`. Bring it back with `lv host undrain <host>` as before. An
`offline` host whose newest fence **failed** is still put back in service
when a quorum sees it healthy again, as before; one whose newest fence
succeeded waits for `lv host undrain`, exactly like a `fenced` host — this
now includes a host fenced with `lv host fence`, which records it `offline`.
A host that boots again still records itself `active` from its own daemon, as
before; what waits is a host that answers without having restarted, which is
the host an unverified fence may never have powered off.

A binary rolled back below the latch enters WAL quarantine, as below every
latched token. See [What a fence records](migration-failover.md#what-a-fence-records).

### Gossip encryption is a separate roll, after the upgrade

The upgrade itself changes nothing on the gossip wire: `enforcement.gossip_encryption`
defaults to `false`, and an existing cluster has no `gossip.key` until
`lv host install-gossip-key` puts one on every host. Turning it on is three more
rolling restarts, one per stage (`install`, `staged`, `true`), and it must not
start until **every** host runs a build with the flag — a host on an older build
stays plaintext and the `staged` roll cuts it off. Rolling a binary back below
this release on a host whose stage is `staged` or `true` does the same, so walk
the stage back to `install` fleet-wide first. The sequence, and why no stage may
be skipped, is in [auth.md](auth.md#turning-it-on-in-an-existing-cluster).

### Region-scoped failover needs every host upgraded

Schema v58 adds `cluster_policies`, a replicated table holding the
cluster-wide failover scope (`lv cluster failover-scope`). A host on the
previous release cannot decode a statement on it, and its failover
coordinator would not honour the policy if it held the lease. So
`lv cluster failover-scope region` refuses until the `failover_scope_v1`
capability token has latched, which it does on its own once every host the
cluster replicates to — including one parked in `maintenance` — runs this
release. Nothing is written to the table before then, and the scope stays
`cluster`, exactly as before.

`failover_scope_v1` is mandatory and replication-gated, like
`host_membership_split_v1`. It has no flag: the policy row is the opt-in, and
`lv cluster failover-scope cluster` is the stand-down. A binary rolled back
below the latched token enters WAL quarantine, as below every latched token.
Roll forward.

### Replica matching while the roll is in progress

An upgraded host matches replicas by record and, for a file with no record,
by its exact `<vm>-<disk>-<YYYYMMDD-HHMMSS>` name (docs/storage.md). A failover
coordinator or replication run on a host not yet upgraded still lists, prunes
and promotes by name prefix, as before, against every host — upgraded ones
answer it as they always did. That ends when the coordinator's host is
upgraded. The records epoch, after which a file with no record on shared
storage is never taken by its name, starts only once every host has started
this release and every host holding a pool on that storage has noted it.

### The voter set becomes explicit after the roll

Schema v59 adds `voter_configs`, one immutable row per generation of an
explicit voter set, and three tables every host keeps to itself: its promises
and accepts (`local_recovery_claims`), the identity of that state
(`local_voter_incarnation`) and which generations it has adopted
(`local_voter_adoption`). Nothing writes `voter_configs` until the
`voter_config_v1` capability token has latched. It is mandatory and
replication-gated, so it cannot latch while any host the cluster replicates to
— one parked in `maintenance` included — runs the previous release. A host
advertises it only once it can vote durably: its `state.db` is at
`synchronous=FULL` (the daemon now opens it that way) and its host signing key
loads.

Once it has latched and every host is voting-eligible and reachable, the
leader-lease holder decides generation 1 from the hosts that vote today, and
every host adopts it. From then on the voter set changes only through
`lv cluster voter add`, `lv cluster voter rm` and `lv cluster voter reset`; see
[Operating model](operating-model.md) → "The voter set is explicit once genesis
has run". While genesis waits, `ha.voter.genesis_pending` says why.

There is no flag to turn it off: a host with it off would count a different
majority from its peers. `lv cluster voter reset` is the decided exit back to
the derived set. It is not a rollback tool: a binary rolled back below the
latched token enters WAL quarantine at startup, as below every latched token,
whether or not a voter generation exists.

### Recovery claims latch after the roll

Schema v60 adds `runtime_action_proofs.claim_certificate`, the majority
certificate that authorizes an ownership-transfer proof; v61 adds
`local_abandoned_proofs` and v62 `local_voter_seals`, two tables each host
keeps to itself (a recovery destination's signed abandonments, and the voter
generations it sealed in a forced reconfiguration). v63 adds
`local_incarnation_claims`, a third host-local table: once the mandatory,
replication-gated `claim_incarnation_v1` token latches, a recovery claim is
keyed by the workload's incarnation (its `created_at`) as well as its name and
owner epoch, so a workload deleted and re-created under the same name is never
answered by the previous one's decision. Nothing writes the new
column until the `recovery_claim_v1` capability token has latched. It is
replication-gated, so it cannot latch while any host the cluster replicates to
runs the previous release, and — unlike `voter_config_v1` — it is **not**
mandatory: it has a flag, `enforcement.recovery_claim`, and latches only once
every host advertises it.

The flag defaults **on**: a config without the key has it on, so an upgrade
needs no config change, and an explicit `false` still wins. Builds before this
default had it off, and turning claims on was an operator step. What happens
now:

1. During the roll nothing changes. A host on the previous build advertises
   the token only if its config sets `enforcement.recovery_claim: true`
   explicitly, so on a cluster that never set the key it cannot latch. Each upgraded host reports
   `litevirt_ha_degraded{reason="unsupported_member"}` until the last host is
   upgraded, as for `partition_pause_v1`.
2. After the last host restarts, `voter_config_v1` latches and genesis
   completes (`lv cluster voter ls` shows generation 1).
3. `recovery_claim_v1` then latches. A host advertises it once
   `split_brain_gate_v1` has latched and it can vote durably. When
   `ha_degraded` clears everywhere and `not_enforcing` is empty, the next
   failover is claim-gated.
4. Validate with a partition drill before relying on it.

Once enforced, a recovery decided for a destination that then dies waits for
`lv host rm --dead <dest>` instead of moving on to another host
(`ha.claim.stranded` names the command); an exact half of the voters cannot
certify a recovery; and a host most voters can still reach is not recovered.
To keep an explicit voter set without claims, set
`enforcement.recovery_claim: false` on every host before the roll finishes.
One host with an explicit `false` holds the latch off for the whole cluster.

To stand down, set the flag to an explicit `false` on **every** host and
restart (a missing key means on): coordinators
mint uncertified proofs and destinations accept them, exactly the pre-claim
behaviour; voters keep answering and keep their history, and the voter set does
not move. A flag off on only some hosts is not a degraded mode but the hazard
the token exists to prevent — such a host reports `recovery_claim_v1` in
`PingResponse.not_enforcing` and its peers raise `ha_degraded`. A host left
on an explicit `false` while the others keep the default holds the latch off
and keeps `ha_degraded{reason="unsupported_member"}` raised on **every other
host** for as long as it stays that way: opt out on every host, or on none.
Alerting on `unsupported_member` also fires for the length of every roll.

Once enforced, two stalls surface only as a reason on the gate-refusal metric
and a WARN log, not as a health condition: `recovery_claim_owner_reachable` (a
host most voters still reach is not recovered) and `recovery_claim_no_majority`
(no majority of the voter set certified the claim, an exact half included).
`lv cluster claim <kind>/<name>` shows each voter's answer; the unblocks are in
[design/recovery-claims.md](design/recovery-claims.md) §6.

**Rolling a host back, or rejoining one, after the latch.** WAL quarantine does
**not** cover this token. The build before this default already knows
`recovery_claim_v1`, so the rollback preflight finds nothing to quarantine,
and that build reads a config **without** the key as `false`. A host rolled
back to it — by hand or by the auto-rollback below — or a host that was offline
through the roll and rejoins on it, therefore mints and runs recovery proofs
without a certificate: the second owner the token exists to prevent. Before
rolling a host back to an older build, or bringing back one that missed the
roll, add `enforcement.recovery_claim: true` **explicitly** to its config; the
older build honours an explicit key. Clusters founded with `lv host init` on
this build already carry the explicit key. `lv doctor fence` warns when the
token has latched and any host does not enforce it, and names the host.

## Schema upgrades: `litevirt schema-migrate`

The daemon refuses to start when its `CurrentSchemaVersion` is OLDER
than the cluster DB's version (downgrade guard), and aborts replication
batches that reference missing tables / columns (forward-skew guard).

**Schema changes are additive-only.** CRDT-replicated tables (everything in
`internal/corrosion/schema.go`) may only **grow**: a new `CREATE TABLE`, or an
`ALTER TABLE … ADD COLUMN` that is **nullable (implicit `NULL`) or has an
explicit `DEFAULT`**, so a row written by an older peer stays valid. **Never rename a column, drop a column, change a column's
type, or change a primary key** on a replicated table. Crescent's
last-writer-wins apply path addresses columns *by name*, so in a mixed-version
cluster a renamed or dropped column is simply *missing* on the not-yet-upgraded
peers, and mutations that reference it are silently dropped or mis-applied
there. A rename is also invisible to the safety nets — it can leave the column
*count* unchanged, so it slips past both the forward-skew check and the
version-bump guard, which catch *growth* without a `CurrentSchemaVersion` bump,
not in-place edits.

To rename or retype a replicated column, do it as a multi-release dual-write
migration — never a single change:

1. `ADD COLUMN` the new column (with a default); bump `CurrentSchemaVersion` and
   add a `History:` line.
2. Dual-write old + new, and read new-with-fallback-to-old. Roll that out to
   **every** node.
3. In a *later* release — after every supported version is past step 2 —
   backfill and stop writing the old column. Leave the dead column in place;
   dropping it is itself a non-additive change and rarely worth the risk.

**`lv host upgrade` handles this for you.** Before swapping any binary it
runs a **pre-stage pass**: it streams the new binary to every target and
runs that binary's `schema-migrate` against the live `state.db` (idempotent,
WAL + busy-timeout — safe while the old daemon is up). Only after every node's
schema is forward-staged does it begin the rolling restart, so a freshly-
upgraded node can never write a column a not-yet-upgraded peer is missing.
If pre-staging fails on any host the upgrade aborts **before** any binary is
swapped, so you can fix it and re-run. Daemons too old to support the
pre-stage RPC report `Unimplemented` and are skipped (they migrate themselves
on restart; a single-version skew self-heals) — so the very upgrade that
introduces this feature still works as a plain rolling restart. Pass
`--no-prestage` to skip the pass (not recommended for multi-version jumps).

You generally do **not** need to run `schema-migrate` by hand. It
remains available for manual control or recovery — e.g. forward-staging a
long-offline node that's ≥2 versions behind before it rejoins:

```bash
make build                                   # produces bin/litevirt

# On a host, pointed at the cluster DB (safe to run while the daemon is up):
sudo litevirt schema-migrate /var/lib/litevirt/state.db
sudo litevirt schema-migrate --dry-run /var/lib/litevirt/state.db   # preview only

# Read-only validator that reports what's missing on the cluster:
scripts/upgrade-validate.sh
```

If you skip pre-staging entirely (`--no-prestage`, or a manual binary swap),
a node running the OLD binary silently drops cross-node mutations referencing
schema the NEW binary added until it's restarted. The drop shows up in
metrics — a growing `litevirt_mutation_log_rows` on the sender and a stalled
`litevirt_replication_min_watermark_seq`.

The migrate tool's safety net is a CI guardrail (`internal/corrosion/
migrate_tool_test.go`) that every entry in `schemaDDL` / `schemaMigrations`
must be parseable by the same DDL parser the tool uses — so a future
schema change can't silently make the migration tool lie.

### CI guardrails

These checks run on every push and pull request (`.github/workflows/ci.yml`)
to keep the invariants above from rotting. Run them locally with
`make ci-guards`.

1. **Schema growth requires a version bump.** If a CREATE TABLE / ALTER /
   index is added to `internal/corrosion/schema.go` without bumping
   `CurrentSchemaVersion`, the forward-skew guard above goes blind to it and
   peers silently drop the new rows. The `schema-guard` job diffs the schema
   arrays between the base and head revisions with an AST-based tool
   (`scripts/ci/schemacheck`, driven by `scripts/ci/check-schema-bump.sh`) and
   fails on growth-without-bump. Counting is by AST element, so reformatting or
   reordering an array never trips it.

2. **History stays in lockstep with the version.** A unit test
   (`TestSchemaHistoryDocumentsCurrentVersion`) asserts the `History:` comment
   block documents every version `v1..CurrentSchemaVersion` — the audit trail
   operators read before a staged rollout.

3. **Docs don't reference commands or metrics that don't exist.** A
   claim-vs-code triangulation test (`cmd/litevirt/docs_triangulation_test.go`)
   walks every `lv`/`litevirt` invocation and every `` `litevirt_*` `` metric
   in `README.md` + `docs/*.md` and fails if one doesn't resolve in the cobra
   tree or appear as a string literal in the code. Intentional exceptions use
   a `ci:skip-cmd` / `ci:skip-metric` line marker or the `knownAbsentIdentifiers`
   allowlist (for documented-but-roadmap metrics).

4. **Every replicated statement is one a peer can still apply.**
   `scripts/ci/stmtshapecheck` statically enumerates every SQL statement our
   builders send down the replicated path, fingerprints each with the same
   primitive the runtime uses at apply time, and makes three separate
   assertions about it:

   - **registered** — the fingerprint is in the checked-in compatibility
     ledger. An unregistered shape does not fail on the receiving peer, it
     *back-pressures*: the apply fails closed, the batch rolls back and that
     peer's replication watermark stops advancing, head-of-line blocking every
     later statement on the stream.
   - **emitted** — a builder nothing calls never reaches a peer at all, so a
     registered shape with no caller is a feature that silently does nothing
     (`reachable.go`).
   - **gated, if it is a table's first-ever shape** (`newtables.go`). A table
     that carried no accepted shape at the previous release, and carries one
     now, is the shape a not-yet-upgraded peer cannot resolve *by
     construction* — and the receiver on the old binary is the one that
     stalls. The guard fails until the table is acknowledged in
     `firstShapeAcks` with the mechanism that keeps the write off that peer's
     stream: a capability latch that cannot form until the roll completes, or
     a local-only write on a table anti-entropy already carries (anti-entropy
     performs no ledger check, so a row that every node derives identically
     converges without replicating a statement at all).

   `scripts/ci/check-ledger-drift.sh` covers the opposite direction: a
   fingerprint that *disappeared* from the ledgers while a supported peer can
   still emit it.

## See also

- [installation.md](installation.md) — base upgrade scenarios + apt
  packaging
- [operating-model.md](operating-model.md) — what the cluster guarantees;
  recovery playbook

## Isolating and reseeding a node

A node whose local state was produced **outside the cluster's current
compatibility regime** — rolled back below a capability token the cluster had
already latched, or isolated by an operator — must not inject that state back.
Such a node already self-quarantines (it WAL-quarantines and stops advertising
its capabilities), but a self-muting node is exactly the one whose
self-assessment you cannot rely on. The isolation epoch is the other half: the
*cluster* records the fact, so every peer refuses that node independently.

```bash
# From a HEALTHY peer — the observation must not come from the suspect.
lv host isolate node-3 --reason rolled_back_latch

lv host ls          # peers now refuse node-3's replication
```

While a host is isolated, every peer refuses its mutation pushes and will not
merge from it via anti-entropy. State dumps and digests stay readable *by* the
isolated node on purpose — that is how it reseeds.

```bash
lv host drain node-3        # reseed discards replicated state; never under a live VM
lv host reseed node-3       # run from a HEALTHY peer; --source pins which one
```

Reseed discards the node's replicated state, pulls a full dump from a healthy
peer, and **verifies convergence** before anything is cleared. Only a verified
reseed ends the quarantine: a partial pull leaves the host isolated, because
half a reseed is worse than none. The epoch clear is written by the healthy peer
that drove the reseed — the isolated node's own writes are refused, so a
self-written clear could never reach the cluster.

Per-node evidence (`audit_log`, `host_health`, `clock_skew`) is exempt from the
convergence comparison: those legitimately differ between any two healthy nodes,
and requiring them to match would make every reseed fail.

The whole regime is gated on `isolation_epoch_v1`
(`enforcement.isolation_epoch`, default off). A pre-latch cluster does none of
this, so it can be rolled out incrementally — enable the
flag fleet-uniformly, since the token latches only under config uniformity.
