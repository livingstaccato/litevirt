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
   so its VMs aren't stranded. A failing run that began while the host was
   `upgrading` keeps the rest of those 2 minutes even if the host is recorded
   `active` before it serves, if the failover leader saw it `upgrading`. The
   new daemon transitions back to `active` on healthy startup, and a host
   left `offline` by a transient blip is auto-recovered to `active` once a
   fresh quorum sees it healthy.

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

## First start after upgrading to a build with file restore

The first start of a build with single-file restore (and file restore not
disabled) creates the `litevirt-restore` system account, loads the
`litevirt-restore-qemu` AppArmor profile where AppArmor is enabled, creates
`/var/cache/litevirt-restore` and `/run/litevirt/file-restore`, and removes
`/var/lib/litevirt/file-restore/cache` left by an earlier build. To avoid the
account being created by the daemon, create it beforehand
([installation.md](installation.md#what-file-restore-changes-on-the-host)); to
avoid all of it, set `file_restore: {enabled: false}` before upgrading.

Every start also kills any process running as one of the uids reserved for
restore VMs (`file_restore.uid_base`, 64 uids from 3800000000) — but only
after checking that range is no one else's: not the containers' id-map range,
no `/etc/subuid` or `/etc/subgid` range, no account `getent passwd` knows.
If you moved `containers.idmap_base` high enough that its range covers the
reserved uids, an explicit `file_restore.uid_base` inside it refuses to load
the config; with the default, the daemon starts and file restore is refused,
naming the overlap — move `file_restore.uid_base`.

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

A host rolled back below the release that added `lv lb create --snat` SNATs
every load balancer made with `lv lb create` that it serves, including one set
to `--snat=false` ([compose.md](compose.md#snat-via-vip)).

### Rolling back a host in a live firmware move

Do not roll back the litevirt binary on a host whose
`<data_dir>/fwmig-inflight/` holds a file. Each file is the source's record of
a live move of a Secure Boot / vTPM VM
([migration](migration-failover.md#secure-boot--vtpm-vms)), and a build
without live firmware migration ignores it: the record stops refusing a start
of the VM's source copy. Check first:

```bash
ls <data_dir>/fwmig-inflight/
```

Let the move finish, or wait until its `firmware_migration_*` condition is
resolved, before rolling back. If a host was rolled back (by hand or by the
auto-rollback) with a file there, upgrade it again before doing anything else
with that VM.

A target rolled back mid-move answers the source's calls as unknown; the
source parks the move `target_unreachable` and keeps both copies.

A target rolled back below the leftover record ignores
`<data_dir>/fwmig-leftover/`; its reconciler may then wipe the NVRAM and TPM
state of a leftover an owed DISCARD names. Check `ls <data_dir>/fwmig-leftover/`
first, and resolve each file with `lv doctor firmware-move <vm> --discard-target`.

### Rolling back after a release token latched

A rolled-back binary that finds a durable activation marker for a capability
token it has never heard of enters **WAL quarantine**: it stays up, but emits
no replicated writes and advertises no capabilities until it is upgraded again
or reseeded. That is right for a token whose latch changed what the cluster
writes. It used to apply to every token, including one whose feature nobody
had touched.

From release `release_2026_11_v1` on, the features of a release share **one
release token** instead of one token each, and each feature carries a **used
bit**:

- The release token (`release_2026_11_v1` for this release) is mandatory and
  replication-gated. It latches by itself once every host the cluster
  replicates to — a host in `maintenance` included — runs this release; there
  is nothing to run. Latching it changes nothing on its own. Every later build
  keeps ADVERTISING it, unconditionally and for good: a host on this release
  refuses the pushes of a sender that does not declare a release token in use.
- **Mid-upgrade, nothing looks broken.** A feature of the release is refused,
  with `the cluster upgrade must finish first (<feature> needs <token>): not on
  this release yet: <host> (<its build version>), … — see lv cluster
  upgrade-status`, until the token has latched. `lv cluster upgrade-status`
  opens with the rollout (`Rollout: N of M hosts on <token>; K feature(s)
  waiting for the rest`, then each lagging host and its version), and the
  informational health condition `release_rollout_pending` (`lv health`; it does
  not degrade the cluster's health) names the lagging hosts until they have
  rolled. Both count the hosts the latch waits on — every voting-eligible host
  and every host the cluster replicates to — so a powered-off host parked in
  `maintenance` is not listed. The condition is kept from cached answers, one
  host asked per health cycle, so it can trail a host's roll by a few cycles;
  `lv cluster upgrade-status` asks every host afresh. No runbook step is needed. Before its
  first write anywhere, the cluster records that it is used — a replicated row
  — and **every voter and every host the cluster replicates to must confirm it
  holds that record** before the write runs. A host that does not confirm in
  time refuses the write (`Unavailable`; retry), naming the host; for a voter
  the message adds that, if it is gone for good, `lv cluster voter rm <host>` is
  the way out — unless the host said it is in release probation, a live host
  that applies nothing until it lifts: the message says that instead and points
  at `lv cluster upgrade-status`. If the record cannot be written at all, the
  write is refused too. Every host that writes the feature's data puts its own
  copy of the record on its own replication stream first. The record is never
  cleared: nothing proves the feature's data has all gone.
- A first use also re-checks, live, that every host the cluster replicates to
  still advertises the token. A host rolled back after the latch therefore
  holds every **first** use off for as long as it runs; features already in use
  keep working.
- Once a feature is in use, an upgraded host **refuses replication** from a
  peer that cannot keep its data. A push is judged by what the sender declares
  in it (every push carries the sender's advertised capabilities; an older
  build carries none). A push always declares this build's release tokens — from
  the first push after a restart, and while self-fenced — so an upgraded sender
  is never refused. Relayed entries and anti-entropy pulls are judged by their
  origin's last declared or answered list, which is refreshed in the background
  (trusted 30s, a lacking or silent peer re-asked with backoff), never by a dial
  on the push path; a newly bad origin is therefore caught up to 30s late. A
  **self-fenced** peer advertises nothing while it is fenced, but it is not
  WAL-quarantined and its build keeps the data: its empty answer is taken as
  no news, so it keeps its last known list, is never refused for it and raises
  no alarm, and a relay stream carrying its entries is never held up. Only a
  peer that is WAL-quarantined, or advertises a list without the token, is
  refused; an origin whose state is unknown never holds up a relay stream. The refusal is back-pressure,
  nothing is dropped, and it raises
  `litevirt_ha_degraded{reason="release_feature_peer_refused"}` with an event
  naming the peers, again whenever a new peer joins them. Upgrade that host
  again, or remove it.
- The release token's marker carries a rollback rule, `rollback:
  safe_if_unused`. A binary that understands the rule (this release and later)
  rolled back below a release token quarantines **if one of that token's
  features has been used** — or if any feature it does not declare is recorded
  used under a token it does know. If its own replica shows no use, it does not
  take that on trust: it starts in **release probation** — on EVERY boot below
  that marker, whatever an earlier boot found, since every release token's
  marker holds the same bytes and nothing on disk can say the host was not away
  through a first use since. In probation it emits no replicated writes (they
  fail with "this node is in release probation"), and it applies no replicated
  state either: a peer's push is refused (back-pressure, retried, nothing
  dropped) and anti-entropy takes nothing, because a first use's data can
  reach it with its record pruned away. It is not quarantined: it keeps advertising, its Ping reports
  `release_probation` and never `wal_quarantined`, and no peer isolates it. It
  pulls the cluster's used records from the voters until it holds answers from
  a **majority of the whole voter set, its own seat counted** when it is a
  voter: one other voter of three, two of four or five. Its own replica is
  never an answer, nor is a WAL-quarantined voter; a voter that is in
  probation too does count, so hosts rolled back together lift together. A
  three-host cluster rolled back as a whole with one host dead therefore lifts
  on the two survivors. It then lifts (`release probation lifted` in the log),
  or quarantines if a use is there. In a two-voter cluster the one other voter
  is enough; a one-voter cluster lifts on its own check, since no other voter
  could have acknowledged a use. A host whose replica holds no voter at all
  asks a majority of its admitted members instead; with none to ask, it lifts
  only if its replica holds no other host (a one-host cluster whose host is in
  `maintenance`), and otherwise stays in probation. Nothing about a lift is
  remembered: the next boot below the marker is a probation again, which costs
  one round (5s) when the voters answer — a whole-cluster restart included,
  since probation voters count. Anti-entropy passes are skipped while in
  probation (they could take nothing), and one runs right after the lift, so
  the replica catches up then rather than one interval later.

  The voter set is this host's own view, which may be stale after an absence.
  So the probation pull also merges each answering voter's voter view — the
  voter generations, `hosts` and `host_membership`, none of which carries a
  release feature's data — and each voter's Ping says which voter generation it
  has adopted. When one is newer than this host's, the host adopts the newer
  generations (each certificate verified, as always) and counts against the new
  set; it never lifts while a voter reports a generation it cannot adopt yet.
  A derived voter set that the merged `hosts` rows changed is recomputed too.
  Voters that were REMOVED while down (`lv cluster voter rm`, a
  force-reconfigure) and missed a use, then come back on this release with none
  of the current voters reachable, can still vouch for each other from their
  stale view and lift together with no holder of the record among them; the
  upgraded hosts still refuse their writes, and anti-entropy brings them the
  record, which quarantines them.

  While it waits, the log line `release probation: a voter majority could not
  be asked yet` names each voter it could not count and why (unreachable,
  WAL-quarantined), and `lv cluster upgrade-status` shows the same list in the
  probation's reason. A voter majority that stays unreachable keeps it in
  probation: remove a voter that is gone for good with `lv cluster voter rm`
  on a healthy host, or set `LITEVIRT_UNSAFE_SKIP_ROLLBACK_CHECK=1` and restart
  this one.
- A first use is acknowledged by every voter (one in `maintenance` included)
  and every host the cluster replicates to, so whichever voters a probation asks
  later, a majority of them holds it. A powered-off host that is neither does
  not hold a first use up; a voter that is gone for good does, until it is
  removed from the voter set (`lv cluster voter rm`). So does a host in release
  probation, which applies nothing pushed to it until it lifts — normally one
  5s round, well inside the 30s a first use waits; the refusal names it as in
  probation.

**Forward rolls refuse nothing.** While the cluster rolls to the NEXT release,
the hosts still on this one see the new hosts advertise a release token they do
not know. That token cannot latch — let alone have a used feature — while they
do not advertise it, so they only take a look at the advertising host's used
records, in the background, and keep writing. A use found there (one recorded
while they were away) quarantines them, as any use arriving does.

**A release token's feature set is frozen when the release ships.** A build
that knows a token but not one of its features cannot keep that feature's
data, yet it advertises the token, counts toward its latch and is accepted as a
sender: the first use would not be refused, and every such host would
acknowledge it and then quarantine itself. So a feature added after a release
ships — in a patch release too — is declared under the next release token,
never a shipped one, and a test pins every release token's list. All
twenty-three features of `release_2026_11_v1` are declared in this release (`lv
cluster upgrade-status` lists them): `vm_limits`, `vm_disk_nic_io`,
`email_target_secret`, `login_policy`, `drain_failback`, `firewall_ipv6`,
`nic_guards`, `usb_mounts_memory`, `backup_zstd`, `container_replication`,
`iscsi_lun_claim`, `pit_overlay`, `redfish_fence`, `ha_disarm`, `nic_mtu`,
`replication_rate`, `returning_boot`, `firewall_synflood`, `firewall_log`,
`firewall_tag_groups`, `host_incarnation`, `automation_stream` and
`sg_projects`. `host_incarnation` is used the
first time a removed host is re-added with `lv host add` after the latch
(below).

One feature is one used bit: the first write of any of its data marks it used,
and a rollback below the release then quarantines. So a feature written by
default is kept apart from one written only on request. Per-NIC anti-spoofing
guards are on by default for every new NIC, so they are their own feature,
`nic_guards`, used from the first NIC created after the latch; IPv6
security-group and firewall rules are `firewall_ipv6`, used only once someone
writes one. `usb_mounts_memory` is one bit for VM USB devices, VM memory
hot-add and container host mounts and devices: any one of them in use makes a
rollback below the release quarantine. `login_policy` is used by default too:
account disable and expiry, the second-factor policy and enrollment codes are
written on request, but the same feature carries what the login rules write
on their own — a directory account's identity binding at its first login, the
second factor a login presented, and the credential cut-offs a user create or
delete writes — so it is used from the first such login, create or delete
after the latch. Logins, creates and deletes are never refused for it: until
the feature opens they run as on the previous release. `pit_overlay` is used by default
too: the first copy of a running VM's disk after the latch for which no
backup session can be made (a replication run or a volume move) makes an
external-snapshot overlay and marks it used. Until the feature opens such a
copy is made as on the previous release (`qemu-img convert -U`, marked not
point-in-time), and a copy that could not place an overlay anyway marks
nothing.
`ha_disarm` is used by default too: once the release token has latched, the
failover lease holder records its use with no data write, so a later
`lv cluster ha disarm` does not need every host reachable. From then on a
coordinator, armed or not, decides no fence and no recovery for a scope (the
cluster, or the host's region) in which it counts fewer than a majority of the
voters live, and the skip is counted as `error_class="no_quorum"`
([migration-failover.md](migration-failover.md#disarming-ha-for-planned-maintenance)).
`returning_boot` is used by default the same way: once the release token has
latched, the failover lease holder records its use with no data write. From
then on a host that boots while recorded `fenced`, `offline`, `maintenance`,
`draining` or `joining` is recorded `upgrading` until its daemon serves, not
`active` at once; until then it boots `active`, as on the previous release,
whose failover leader clears a fenced host it has handled only once the host
is `active`
([migration-failover.md](migration-failover.md#resuming-a-recovery-from-a-recorded-fence)).

**`release_2026_12_v1`** is the next release's token, with the same rules. A
rollback below it lands on a `release_2026_11_v1` build, which reads the rule, so
it quarantines only for a feature of it that was used. Its one feature so far is
`fence_ssh`, and it is used by default: every host publishes its managed fence
SSH row as soon as the token latches, which pins its sshd keys for every fence
aimed at it ([migration-failover.md](migration-failover.md#managed-fence-ssh)).
So from the latch on, a rollback below `release_2026_12_v1` quarantines. To keep
the ability to roll back, set `enforcement.fence_ssh: legacy` in every host's
config before the last host upgrades. The daemon reads it at start, so restart
the daemon of a host that already runs this build: a host in `legacy` publishes no row, so nothing uses the
feature (and every host keeps fencing as before the upgrade, pinned toward any
host that does publish). `lv cluster upgrade-status` lists `fence_ssh` with
whether it is used, and its token once latched. Its rollout summary (hosts on the
release, features waiting) counts `release_2026_11_v1` only.

**What this does not change.** A binary built before `release_2026_11_v1`
understands no rollback rule. Rolled back below any token it does not know —
this release's token included — it quarantines, used or not. Tokens other than
release tokens carry no rule and block a rollback once latched, as before.

**Quarantine stops writes, not misreads.** A quarantined host emits nothing the
cluster could take, but it still acts on what it holds locally. A host that
applied a feature's data it cannot interpret — before the quarantine came up,
or on a build from before this mechanism — may still run that host's workloads
without it (a VM defined without the limits a feature set, for example). So a
host quarantined below a release feature in use must be **drained** of the
workloads the feature touches (`lv host drain`), then upgraded again or reseeded;
reseeding alone does not correct a workload already running.

**`lv stop` on a quarantined host.** A stop's `operator-stop` record is a
replicated write, which the quarantine refuses, so the host cannot record
the stop as the operator's. Once the quarantine lifts, the reconciler records
the stopped VM from libvirt's reason instead. A clean guest shutdown is
recorded as one and stays down. A killed domain is recorded as an
out-of-band destroy, and its restart policy starts it again. So, while the
quarantine holds:

- `lv stop` asks the guest to shut down, as elsewhere. It answers an error
  saying the stop was not recorded, but the guest stays down. An `onboot` VM
  starts again at the host's next boot.
- If the guest does not shut down within its timeout, it is **not**
  force-killed. The stop answers `FailedPrecondition` and the guest keeps
  running.
- `lv stop --force` kills the guest, as elsewhere, but first records the
  stop on the host itself (below). It answers the VM `stopped`, with a
  detail saying the stop is recorded on this host only. Until the
  quarantine lifts the VM's row still reads `running`, so `lv ls` shows it
  running while `lv inspect` shows the live, stopped domain.
- `lv start` is refused with `FailedPrecondition`: a start cannot be
  recorded either, and a guest started now would run while the cluster's
  record of it says otherwise.

Release probation lifts by itself (`lv cluster upgrade-status`). Any other
quarantine needs the host upgraded again or reseeded.

**`lv stop --force` on a quarantined host.** Before it kills the guest, the
forced stop writes a marker under the daemon's `data_dir`,
`operator-stops/<vm>.json`: written to a temp file, fsynced, renamed, and
the directory fsynced. The marker names the host, the VM's incarnation
(its row's `created_at`) and its owner epoch, so it never holds a VM deleted
and created again under the same name, nor one that left the host and came
back under a later ownership. If the marker cannot be written (a full `data_dir`,
EIO), the stop is refused with `FailedPrecondition`, says why, and the guest
keeps running: a guest is never killed without its marker.

While the marker is there, nothing on that host starts the VM: not its
restart policy, not a health-check restart, not a replace cutover's handoff
(which finishes with the VM down), not the reconciler's self-heal
or `onboot` start (also after a daemon restart or a host reboot: the marker
is on disk), and not `lv start`. `lv start` is refused with
`FailedPrecondition` while the quarantine holds, because neither the stop
nor the start could be recorded; the marker leaves only through the recorded
stop. Other hosts are not involved: the host is alive, so failover does not
act, and the VM's row still names it.

Once the quarantine lifts, the host's next reconcile pass records the stop
on the VM's row as the operator's (`stopped` / `operator-stop`, through the
same write an ordinary `lv stop` makes), adds a `vm.stopped` event, and
then removes the marker. An `lv start` that comes first records the stop the
same way, then starts the VM. The record is written only while the row is
still on this host, of that incarnation and at that owner epoch. A marker
whose VM was deleted meanwhile, or created again, or moved to another host,
or owned again under a later generation, is removed with nothing recorded;
so is one whose guest is running again (started by something that does not
read the marker), since a stop is never recorded over a running guest.

A marker that cannot be read or parsed **fails closed**: its VM is held
stopped on that host, the stop is not replayed, the daemon logs an error,
`litevirt_operator_stop_markers{state="corrupt"}` counts it, and once the
host can write it raises `operator_stop_marker_corrupt`
([diagnostics.md](diagnostics.md#corrupt-operator-stop-marker-operator_stop_marker_corrupt)).
`litevirt_operator_stop_markers{state="pending"}` counts markers still
waiting for their replay.

**Limit: a rolled-back binary ignores the marker.** A build older than this
one does not know the file. Rolled back onto such a build while a marker is
held, the host's restart policy and reconciler act on the row alone, so the
killed guest may be started again, as before this change, and the marker is
left on disk. Upgrading again replays it if it still applies (or removes it
if the guest runs again).

**Before you roll back**, ask the cluster what would block it:

```bash
lv cluster upgrade-status
```

It lists every token latched on the connected host with two answers:
`BLOCKS ROLLBACK` for the build directly below that token, and `IF RULE-AWARE`
for a target build that reads rollback rules. For `release_2026_11_v1`,
`BLOCKS ROLLBACK` is always `yes`: every build below it predates rules. `IF
RULE-AWARE: no` on a later release token means a host rolled back onto this
release would keep running (after one probation round). Every release feature
is listed with whether it is used and the host that last recorded it. A
feature listed as *not known to this build* is a newer release's that has been
used: this build is the one that would be quarantined, and is, if it is the
binary answering.

**Residuals.**
- An origin a receiver has never heard from is not judged, so its entries
  relayed by another host are accepted until it first answers (asked in the
  background); a known origin that turns bad is caught up to 30s late. As an
  anti-entropy SOURCE, a peer never heard from is asked first, and one that
  answers with nothing while not WAL-quarantined (self-fenced) is not pulled
  from until it declares what it keeps; the pass pulls from another peer.
- An origin KNOWN not to carry a used release token refuses the whole relayed
  push that carries its entries, so the other origins' entries on that relay
  stream wait behind it — back-pressure, nothing dropped, anti-entropy
  carrying them meanwhile — until that host is upgraded again or removed. A
  push is acknowledged as a whole, so skipping one origin's entries would lose
  them. `release_feature_peer_refused` names the host.
- A host with no marker that was away through the next release's latch and
  first use, and comes back on this release, emits replicated writes until its
  first Ping of a newer host leads it to their used records. Upgraded hosts with
  the use refuse those writes, so this is defence in depth only.
- A probation asks the newest voter generation. A first use is acknowledged by
  the voters of its time and by every replication recipient; a voter added later
  received the record by replication before it could vote, unless it joined from
  a reseed taken before the use — which a reseed from a current peer is not.

A data directory may hold `release_probation_lifted.<token>` from a
pre-release build of this mechanism; nothing reads it, and it can be deleted.

`LITEVIRT_UNSAFE_SKIP_ROLLBACK_CHECK=1` skips the startup check, the recorded
uses and the startup probation included, as before (see
[configuration.md](configuration.md)). A use that arrives by replication after
startup still quarantines the node at run time; that ends with an upgrade back
to a build that knows the token, a reseed, or a restart with the override set.

---

## Pending OS updates

litevirt does not patch a host's operating system, but it tells you which hosts
are behind. Each daemon asks the host's package manager what its cached index
says is upgradable (`apt list --upgradable`, or `dnf check-update` plus
`dnf updateinfo list --security`), every `host_updates.interval_minutes`
(default 360), and installs nothing. By default it does not refresh the index
either: that is a network call and takes the apt lock, so it runs only with
`host_updates.refresh_index: true`; without it the report is as fresh as the
host's own refresh timer (`apt-daily.timer`, `dnf-makecache.timer`).

The result is published three ways:

- `lv host ls` shows an `UPDATES` column (`-` not reported or no apt/dnf, `?`
  the last check failed, `0`, `5`, or `5 (2 security)`), and `lv host inspect
  <host>` prints a note and carries the counts in its labels
  (`litevirt.os-updates`, `litevirt.os-security-updates`).
- The `litevirt_host_pending_updates{host,kind}` gauge (`kind` is `all` or
  `security`), emitted for every host that has reported. A host whose last check
  failed emits nothing rather than a zero that reads as fully patched.
- A `host.security_updates` (warn) notification when the host has security
  updates pending, or `host.updates` (info) when only other updates are, sent
  when the counts change. A daemon restart does not repeat a notification the
  published counts already cover. Route them with `lv notify route add
  --pattern 'host.*' --target <target-id>`.

A security update is one offered from a security suite (`*-security` on
apt) or listed by `dnf updateinfo --security`. Patch the host with its own
package manager; drain it first (`lv host drain`) when the update needs a
reboot. A release check for litevirt itself is not part of this.

A live move of a Secure Boot / vTPM VM needs the same libvirt, QEMU, swtpm,
libtpms and OVMF on both hosts, and on the source it compares the versions
the guest's processes were started from. While those packages are updated
host by host, such a VM does not move live between an updated and a
not-updated host. Nor does it move off a host whose packages were updated
after the guest started, until it is restarted (`lv stop <vm>`,
`lv start <vm>`). A target running a litevirt build without live firmware
migration refuses the move too. The refusal names
the first difference and gives the cold move (`lv stop <vm>`, then
`lv migrate <vm> <host> --cold`).

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

A bare `systemctl restart` gets only guarantee 2: the SIGTERM records the
host `upgrading`, and the failover coordinators skip it for 2 minutes from
that write. **A daemon stopped for longer than that without a drain gets its
host fenced**: powered off, with its VMs recovered elsewhere. That holds
whoever records the host `active` meanwhile: a failing run that began while
the host was `upgrading` keeps the rest of those 2 minutes, and a host that
still does not answer when they end is fenced. The run keeps them only if the
failover leader saw the host `upgrading`; a leader that did not (it took over
meanwhile) allows 13 s from the activation
([migration-failover.md](migration-failover.md)). The restarted daemon records
the host `active` itself once it serves; `lv host undrain` is refused while it
does not answer. Always upgrade through `lv host upgrade`. If you must
hand-restart a host, or stop its daemon for longer, put it in maintenance
first (`lv host drain <host>`), restart, then return it.

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

This is the dual-write step of a column move. Every old column still holds
the current secret, so the public rows, and the operator-safe state dump built
from them, **still carry the secrets until the second step below**: clearing
the old columns, behind a second mandatory, replication-gated token (see
[The old secret columns are emptied](#the-old-secret-columns-are-emptied) and
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

### The old secret columns are emptied

The second step of the move takes the secrets out of the public rows. It
starts **on its own, after every host runs a build carrying the
`credentials_clear_v1` capability token**; no flag starts it, and none stops
it. The token is mandatory and replication-gated, like `credentials_split_v1`:
it latches only once every memberlist member advertises it, a host parked in
`maintenance` included, so no host that still reads only the old columns ever
receives a clear. A host advertises it only after it has completed its first
credentials split pass, so no old column anywhere is cleared before every
host has a credential row for every secret it holds.

Once it has latched on a host (and `credentials_split_v1` has too):

- every writer writes the secret to the credential table and an empty value
  to the old column, in the same statements as before;
- the pass that runs at start and every minute empties every old column that
  still holds a value — a deleted user's hash, a revoked token's hash and a
  removed host's BMC password included. Each clear goes out in one replicated
  batch with the credential row it hands over to, credential row first;
- each clear is stamped just after the public row's own `updated_at`, not
  with the current time, so a revoke or delete a peer made just before the
  clear, still in flight, still wins when it arrives;
- password, token and IPMI readers do not change: they already take the
  credential row whenever one exists;
- an LDAP or OIDC login under a name that already has a users row reads the
  credential row to decide whether that row is a local account, because an
  empty `password_hash` no longer means "no local password". A host that has
  received the account's users row but not yet its credential row (the two
  are repaired separately) refuses that login with "its credential has not
  reached this node yet" until it has, rather than guess. An external user
  that existed before `credentials_split_v1` latched is given an empty
  credential row by the first split pass of the hosts that held it before the
  clear, so it keeps logging in. A host added after the clear refuses such a
  login until that credential row has reached it, usually within one
  anti-entropy cycle.

From then on no public row, and no operator-safe state dump, carries a
password hash, an API token hash or an IPMI password. `lv user reset-admin`
follows the same latch when it writes the local database directly.

A host's latch forms a few seconds before or after its neighbours'. A host
that has not latched yet still writes secrets to both places; the next pass
on a latched host empties that old column again.

**Rollback.** One build back — to the build that dual-writes — is the
supported rollback. That binary enters WAL quarantine like any rollback below
a latched token, and it still validates tokens, checks passwords and fences,
because it reads the credential row whenever one exists and the credential
rows hold every secret. Upgrading it again loses nothing. **A rollback two
builds back, to a build before `credentials_split_v1`, is unsupported once
`credentials_clear_v1` has latched**: that build reads only the old columns,
which are empty, so it has no IPMI password, password hash or token hash to
read. The startup rollback preflight refuses such a binary only if it carries
the preflight.

A host rolled back one build also loses one safeguard: that build recognises a
re-minted admin account's credential (colonelpanik/litevirt#224) only by the
hash on the refused users row, which is empty once the re-minting host has
cleared. Under WAL quarantine it still merges anti-entropy, so during a
re-mint incident it can take the re-minted credential. Resolve the re-mint
(`lv user reset-admin` on the host you trust) before rolling a host back.

**A host that was switched off across the latch.** The latch is confirmed
against hosts that are in the cluster's membership at the time. A host that
was off throughout is not asked, and if it runs a build before
`credentials_split_v1` it holds no marker for either token, so the rollback
preflight does not stop it either. Back online on that build, it reads only
the old columns, which are now empty: it cannot fence by IPMI and its logins
fail. Do not bring it back with its old data. The safe path is to remove it
and add it again as a fresh host: `lv host rm <host>` from a running host,
wipe its data directory, then `lv host add` it on this build, so it joins
with an empty database and takes every row, credential rows included, from
the cluster. (Bringing it back on the dual-write build reads empty secrets;
bringing it back with its old database on this build is safe for logins —
evidence that a user is external is kept per user and bound to that user's
row as it stood, including its last write, so a local account cleared since,
or a name deleted and created again since, is never taken for one; such a
login is refused until the account's credential arrives — but it holds stale
state for everything else until anti-entropy has caught up.)

**External users after the roll.** An LDAP or OIDC user created before
`credentials_split_v1` latched has no credential row until a host that held it
then runs its first split pass on this build. If no such host does — for
example, the old hosts were replaced by new ones instead of being upgraded in
place — logins under that name are refused with `FailedPrecondition` until an
administrator runs `lv user mark-external <username>` (docs/auth.md). Upgrade
at least one existing host in place before retiring the rest to avoid it.

Until the token latches,
`litevirt_ha_degraded{reason="capability_rollout_pending"}` is set, as for
every mandatory token mid-roll.

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

### The `hosts` copy of host state is retired

The second step stops writing the `hosts` copy. It starts **on its own, after
every host runs a build carrying the `host_membership_retire_v1` capability
token**; no flag starts or stops it. The token is mandatory and
replication-gated: it latches only once every memberlist member advertises
it, a host in `maintenance` included, so no host that reads state only from
`hosts` stops seeing fences and drains.

Once it has latched on a host that is writing `host_membership`, a state
change, a fence, an isolation and the clearing of an isolation write
`host_membership` alone. They no longer move the `hosts` row's `updated_at`,
so they cannot cost a concurrent version or resource report on any replica.
The `hosts` columns are left as they are, never cleared (`hosts.state` is
`NOT NULL`), and they stop following. Adding a host, re-admitting one and a
host's boot report still write `hosts.state` in their existing statements,
because those statements write the rest of the row anyway.

Readers change in two ways, both so that the frozen copy is never taken as
current:

- every host reads its state and isolation from its `host_membership` row
  whenever one exists, including a host whose own `host_membership_split_v1`
  latch has not formed yet;
- on a host that has latched `host_membership_retire_v1`, a host with no
  `host_membership` row reads as `unknown`: not `active`, so nothing is
  placed on it, but still counted in every quorum's denominator. The split
  pass no longer fills such a row from the `hosts` copy there, and a
  hosts-only write fills one only when it carries the whole row (adding the
  host) or both state and isolation; a state change made on that host writes
  only to an existing row. The row arrives from its peers by replication or
  anti-entropy. Until it does, the failover coordinator on that host neither
  fences nor recovers such a host (it logs the skip), and the host never
  counts as a live voter there unless it is a member of an adopted voter
  generation.

Before the retire latch, a split pass that fills a missing `host_membership`
row from the `hosts` copy stamps it decades in the past, so it fills an
absence and never replaces a newer fence or drain.

A host whose own `host_membership_split_v1` latch has not formed yet still
writes `hosts` alone, and every latched host still takes such a write into
its `host_membership` row as described above.

**Rollback.** One build back, to the build that dual-writes, is supported: it
enters WAL quarantine and reads state and isolation from `host_membership`
once it has completed a split pass. Until then that build reads the `hosts`
copy, which no longer follows, so a fence or drain made after the retire
latch is invisible to it for that first pass interval (about 10 seconds).
**A rollback two builds back, below `host_membership_split_v1`, is
unsupported once `host_membership_retire_v1` has latched**: that build reads
`hosts.state` only, and it no longer follows.

**A host that was switched off across the latch.** The latch is confirmed
against hosts in the cluster's membership at the time; a host that was off
throughout is not asked. If it runs a build before
`host_membership_split_v1` it holds no marker for the token, the rollback
preflight does not stop it, and back online it reads `hosts.state`, which no
longer follows: it can count a fenced host as active. Upgrade such a host to
at least the dual-write build before you power it on again. See
[design/host-membership-retire-old-columns.md](design/host-membership-retire-old-columns.md).

### A host's own reports move to their own row after the roll

With state and isolation gone to `host_membership`, the `hosts` row still
held two kinds of value under one `updated_at`: the configuration an operator
sets (address, role, region, fencing, capacity overrides, labels) and what the
host's own daemon reports about itself (version, schema version, CPU, memory
and disk totals, capacity policy hash). A host's boot report and an
operator's concurrent `lv host` change could therefore lose each other, the
same way a fence and a version report used to. Schema v65 adds
`host_runtime`, one row per host with its own `updated_at`, and two mandatory,
replication-gated capability tokens move the reports into it **on their own,
after the last host has upgraded**. No flag starts either.

**`host_runtime_split_v1`.** While any host the cluster replicates to —
including one parked in `maintenance` — runs the previous release, nothing is
written to `host_runtime` and every report goes to `hosts`, exactly as before.
Once the token has latched on a host, that host:

- runs a pass at start and every 10 seconds that gives every host a
  `host_runtime` row copied from `hosts`, stamped decades before the `hosts`
  row's `updated_at`, so a copy only fills an absence and never replaces a
  real report;
- after its first complete pass, writes every report to **both**
  `host_runtime` and the `hosts` columns, in one batch with one `updated_at`.
  The `hosts` half uses the previous release's statements;
- reads the version, schema version and totals — for `lv host ls`, placement,
  the upgrade gates and the self-upgrade watcher, the UI and MCP views alike —
  from a host's `host_runtime` row whenever it has one, whatever the `hosts`
  copy says, and from `hosts` only for a host with no row.

A report written to `hosts` alone, by a host whose own latch has not formed
yet, is recognised by its batch, which carries no `host_runtime` statement,
and every host that applies the batch — the writer included — takes it into
the `host_runtime` row it holds, with the write's own `updated_at`, if that is
newer. A host re-admitted with `lv host add` after `lv host rm` is a new
machine: every host retires the old machine's `host_runtime` row as it applies
the re-admission, and the new machine's first report brings the row back.

**`host_runtime_retire_v1`.** The dual write keeps a report from being lost,
but its `hosts` half still moves the `hosts` row's clock, so a newer report can
still make a replica refuse an operator's older, concurrent region or role
change. The second token stops that. A host advertises it only once it has
completed a `host_runtime_split_v1` pass, so it latches only once every
replication recipient writes and reads `host_runtime`. From then on a version
or resource report writes `host_runtime` alone, and so does the boot report
once `host_membership_retire_v1` has latched as well (until then it still
writes the boot state to `hosts.state`, and nothing else there). An operator's
change and a host's report then never share a clock. The `hosts` columns are
never cleared; they keep the values they had at the latch. Adding a host and
re-admitting one still write the whole `hosts` row, as before.

The retire latch repairs nothing that diverged before it. A region or role
change that a replica refused during the dual-write window, because a newer
report had moved the `hosts` row's clock, stays refused there: that replica
holds the old value under the same `updated_at` as one that applied the
change, and nothing settles the tie until the operator's next write to that
host. Re-apply such a change once the retire token has latched.

A host's boot report always writes its whole `host_runtime` row, so a host
that was removed while it was down and re-added with its data directory
intact brings its row back on every node with its first boot, even though
every other node retired the old one when it applied the re-admission.

Its `hosts` row converges too. On its old database the host's own row is
still live, so its daemon re-records its new certificate serial instead of
re-admitting, and every write it makes from then on is newer than the
re-admission, which that host therefore never applies; every other host
applies the same writes over the re-admission's reset row. The two rows end
up under one `updated_at` with different content, which used to be an
unresolved `control_plane` tie for good, with the host keeping the removed
machine's labels, region, role, fence settings and `grpc_port`. A
re-admission now records its own time as the row's `created_at`, on every host
that applies it, and a tie between two `hosts` rows whose `created_at` differ
by more than five minutes goes to the later one, whole: the re-admitted row,
with every write the host has made since. Anti-entropy pulls whole rows, so a
host that pulled the re-added host's row before its writes arrived used to
take the stale row outright — it is newer — and where every survivor did, the
cluster settled on it with no tie to report. A host holding the re-admitted
row now keeps it against a row whose `created_at` is more than five minutes
earlier; the re-added host's writes still reach it by replication.

The five minutes are the clock skew the cluster's hybrid clock already
tolerates (`hlc.MaxSkewMS`). The re-admission's time is the cluster's clock,
which can run up to that far ahead of a host's own, while a host re-added on
an empty database stamps its row with its own clock when it first starts; its
row is the newer one and keeps its own settings, its `grpc_port` among them.
The cost is narrow: a host that was added and then removed and re-admitted
within five minutes falls back to plain last-writer-wins, as before this
change.

Mid-roll, this needs at least one host on this build to have applied the
re-admission, and that is necessary rather than sufficient. A host on a build
with the re-admission reset but without this change settles a tie between a
stamped and an unstamped row on the stamped one only where the two rows
otherwise agree; one that pulled the stale row whole (it has no such guard)
differs in control-plane columns too, and leaves the tie unresolved until it
is upgraded. A host on a build without the reset (v1.9.0 and earlier) leaves
the tie unresolved, as before. An older-build host can also erase the stamp by
pulling a newer, unstamped row from another older-build host. Where no host
stamped, the tie stays as it was.

The two `created_at` values come from two hosts' clocks. If the host's
original `created_at` is later than the re-admission's — a clock skew larger
than its whole first membership — the stale row wins whole, on every host.

**The host incarnation counter (`host_incarnation`).** Once the release token
has latched, `hosts.incarnation` numbers a host's admissions instead. A host is
at incarnation 0 until a removed host is re-added; `lv host add` of a host
whose tombstone is at N then records it at N+1. Every node orders two copies of
a host's row by incarnation first, then by the re-admission's `created_at`,
then by certificate serial, whatever their `updated_at`: a write made against an
earlier incarnation is refused (`litevirt_merge_apply_rejected_total`, reason
`older_incarnation`), and anti-entropy keeps the later incarnation's row. The
five-minute rule above still decides between two rows that are both at
incarnation 0. A re-admission that issues a number needs:

- the release token latched on the node `lv host add` runs against;
- a live voter majority on that node, counted without the host being re-added;
- a peer it can pull the host's row from first;
- an `lv` of this release or later, which installs its own build on the host.
  A previous release's `lv host add` would install a build that cannot keep an
  incarnation, and the host would stay joining, refused by every peer.
  Removing the last previous-build host latches the release, so re-add such a
  host with this release's `lv`; a host already admitted on an older build
  joins after `lv host upgrade <host>`. The daemon takes `lv`'s word for the
  build: `lv host add` pushes the `litevirt` beside its own executable, or
  `/usr/local/bin/litevirt` when there is none, so an `lv` run without this
  release's `litevirt` beside it can install an older build; that host also
  stays joining until `lv host upgrade <host>`.

Otherwise `lv host add` is refused with the reason. Over a tombstone at 1 or
higher it is never written the way the previous release writes it. `lv host rm`
takes the same majority and pull, and is refused when the row names another
certificate than the one it revoked. This release's `lv host rm` asks the
daemon before it revokes, and revokes nothing when the removal would be
refused; once it has revoked, it retries a removal that fails `Unavailable`
twice, over about 30 seconds, then prints the command that finishes it. A
previous release's `lv host rm` does not ask: against this release's daemon it
still revokes the certificate and publishes the CRL first, and a refusal then
leaves the host revoked with its row live. Run `lv host rm` with this
release's `lv`. On a node that has not caught up with the
cluster since it started, `lv host rm`, `lv host config`, `lv host label`,
`lv host drain`, `lv host undrain` and `lv host isolate` are refused; `lv host
fence` is not, and its result names the incarnation, serial, strategy and BMC
it fenced through. A daemon whose own row names another certificate than the
one installed (and not its renewal), or whose own row is removed, makes no
write to that row until the cluster's row for its certificate reaches it
(`own_row_held`, [diagnostics.md](diagnostics.md#own-row-held-own_row_held)).
An `lv host add` of a host removed at incarnation 0 that cannot use
`host_incarnation` at that moment (not every host runs the release yet, or a
host has not acknowledged its first use) re-admits the host as the previous
release does, and prints why.

The re-added host publishes a missing capability label again (`litevirt.lxc`,
`litevirt.tpm`, `litevirt.secureboot`) within a minute of the re-admitted row
reaching it; it does not need a restart. A label set to another value with
`lv host label` is an override, and the daemon leaves it alone until its next
start, which publishes what its probes find, as it always has.

**Rollback.** Both tokens ship in the same build, so a binary rolled back
below them is below both. It enters WAL quarantine at startup, as below every
latched token, emits no replicated writes, and cannot decode the
`host_runtime` statements its peers keep sending. Before the retire latch it
still reads current reports from the `hosts` columns; after it, it reads every
host's version, schema version and totals as they were at the latch — never
older than the build that latched it, so a newer peer still reads as newer.
Nothing is lost: `host_runtime` keeps every report, and upgrading the host
again reads it. Roll forward.

**A host that was switched off across either latch.** Each latch is confirmed
against the hosts in the cluster's membership at the time; a host that was
off throughout is not asked. If it runs a build before
`host_runtime_split_v1`, it holds no marker for either token, the rollback
preflight does not stop it, and back online it reads every peer's version,
schema version and totals from the `hosts` columns — current only up to the
retire latch, frozen after it — and places workloads and gates upgrades on
them. Its own reports, written to `hosts` alone, are still absorbed by the
upgraded hosts. Upgrade such a host to this build before you power it on
again.

### An unverified fence records `offline` after the roll

A host recorded `fenced` used to mean "a fence succeeded", whatever the fence
was. An SSH poweroff that nothing verified recorded it just as an IPMI
power-off observed off did, and readers took the state as proof the host was
off (colonelpanik/litevirt#253). Two things change:

- **At once, on each upgraded host:** nothing takes a `fenced` state as proof
  of power-off unless the host's newest fence is proof-grade (`ipmi`, or
  `lv host fence-confirm`). Owner-assert asks an SSH-fenced host whether it
  runs a workload, `lv host rm --dead` no longer counts a proof-grade fence
  from an earlier life of a host whose `fenced` state now rests on an SSH
  fence, and the voter-loss condition asks such a host which machine it is. This reads the rows every fence already wrote; nothing is
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

What an operator sees after the latch: the host's recorded state (the
`host_membership` row, and the assurance `lv doctor fence` and `lv host fence`
print) is `offline` for an SSH-fenced host. `lv host ls` shows `HOST_OFFLINE`
for `offline` and `HOST_FENCED` for `fenced` (a server on an earlier release
shows `HOST_OFFLINE` for both, and `HOST_DRAINING` for `upgrading`). Bring the host back
with `lv host undrain <host>` as before. An
`offline` host whose newest fence **failed** is still put back in service
when a quorum sees it healthy again, as before; one whose newest fence
succeeded waits for `lv host undrain`, exactly like a `fenced` host — this
now includes a host fenced with `lv host fence`, which records it `offline`.
A host that boots again still records itself `active` from its own daemon, as
before; what waits is a host that answers without having restarted, which is
the host an unverified fence may never have powered off.

**`lv host fence` now authorises automatic recovery**, at once on an upgraded
leader, latched or not. When the operator's fence succeeds, the failover leader
treats it as it treats its own fence — under the same safe-fence policy,
`litevirt.fence_requires_confirmation` label and recovery claims — and only
while it still **stands**: some observer has watched the host fail without a
break since **before** the fence, and nobody has seen it answer since. Then an
`ssh` or `best-effort` fence is resumed from without fencing again, and an
`ipmi` fence is resumed from while under 5 minutes old and otherwise renewed
with a fresh power-off first. On the previous release an operator fence moved
nothing, and the host's workloads stayed where they were.

An observer's failing run is held in memory, so a daemon restart starts it
over, and a rolling upgrade restarts every observer. So for a host an operator
fenced **before** the upgrade that is still down:

- an `ssh` or `best-effort` fence no longer stands once the roll completes, and
  is **not** resumed from: the workloads stay where they are, as on the
  previous release. Confirm the host is off and run
  `lv host fence-confirm <host>`; the coordinator then fences it afresh for
  the outage and recovers its workloads. (Mid-roll, an upgraded leader can
  still resume from it while an observer that has not restarted yet holds an
  unbroken run.)
- an `ipmi` fence is renewed with a fresh power-off and then recovered, on the
  first leader cycle after the roll that finds the host still down.

The same holds for an operator fence of a host that was still answering when
it was fenced: every observer's run began after the fence, so an `ssh` fence is
never recovered from automatically (use `lv host fence-confirm`), and an
`ipmi` one is renewed and recovered. If you do not want an IPMI-fenced host's
workloads recovered at the upgrade, `lv host undrain` it before upgrading, or
move them with `lv host drain`.

`lv host fence` served by an upgraded node writes the host's state and its
fence row as one replicated entry, so every leader cycle sees both. Served by a
node that has not been upgraded yet, mid-roll, it still writes them as two
entries, as on the previous release: an upgraded leader whose cycle lands
between them sees the host `offline` with no successful fence row, treats it as
handled and moves nothing. That fails closed; run `lv host fence-confirm` once
the host is confirmed off.

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

### Health-aware relays need every host upgraded

This release lets the failover lease holder demote a host whose probes keep
failing from relay duty, by writing a `relay_demoted/<host>` row in
`cluster_policies` (colonelpanik/litevirt#175;
[operating-model.md](operating-model.md#replication)). A host on the previous
release decodes that row but ignores it, so it would keep the demoted host as
a relay while every upgraded host dropped it — two relay sets in one cluster.
So nothing is demoted until the `relay_health_v1` capability token has
latched, which it does on its own once every host the cluster replicates to —
including one parked in `maintenance` — runs this release, and until
`failover_scope_v1` has latched too. Until then relays are chosen exactly as
before.

`relay_health_v1` is mandatory and replication-gated, like
`failover_scope_v1`, with no flag: a flag would let one node elect a different
relay set from its peers. A demotion withholds the relay role only, and a host
is restored on its own after 10 minutes below the demotion bar. The
state is listed by `lv cluster relay-restore` with no argument, and the
stand-down is `lv cluster relay-restore <host> [--hold <duration>]` (admin):
it clears the demotion at once for the whole cluster and, with a hold, keeps
the lease holder from demoting the host again until the hold runs out. A
binary rolled back below the latched token enters WAL quarantine, as below
every latched token. Roll forward.

### Concurrent spec edits are resolved after the roll

Two edits of one VM's spec made from the same generation, one on each side of
a partition, used to leave each host holding whichever reached it first until
anti-entropy kept the newer one. A spec edit entering on a host that does not
own the VM is now made on the owner, which serialises them; an owner that
cannot be reached still takes the edit where it entered. Once the
`spec_conflict_v1` capability token has latched — on its own, once every host
the cluster replicates to, including one parked in `maintenance`, runs this
release — an edit also carries the owner epoch it was made at, a statement a
host on the previous release cannot decode, records in the spec (`spec_edit`)
when it was made and the content it was made from, and every host resolves
two edits at one generation the same way (see
[operating-model.md](operating-model.md#replication)). Until then edits are
replicated exactly as before.

`spec_conflict_v1` is mandatory and replication-gated, with no flag: every
host must resolve one conflict the same way. A binary rolled back below the
latched token enters WAL quarantine, as below every latched token. Roll
forward.

### Project security groups wait for the roll

`lv sg create <name> --project <p>` creates a group only `p`'s workloads may
bind (docs/firewall.md). Its row carries a column a host on the previous
release cannot decode, so it is the release feature `sg_projects`: refused
with FailedPrecondition until `release_2026_11_v1` has latched, and its first
use is recorded before the group is written. Global groups are created as
before throughout, and every existing group stays global.

### Stack firewall changes need sg.write only after the roll

On this release, `lv compose down` and `lv compose up` of a stack need
`sg.write` at `/` to remove or withdraw the stack's firewall, wherever it is:
a host keeps a stack's security groups, ip sets, rules and default-deny when
the teardown's caller did not hold it, and a deploy without it cannot
withdraw what the stack's last deploy with it declared
(`stack.firewall_teardown_held`, docs/diagnostics.md). That holds only once
every host runs this release. A host on the previous release checks neither:
an Operator's `lv compose down` or `lv compose up` on it changes the stack's
firewall as before, and its stack reconciler removes the firewall it holds
of any stack being torn down, whoever began the teardown. A stack whose last
deploy with `sg.write` ran on the previous release has no recorded intent,
and its file alone says what it asks for. Finish the roll before relying on
the check; an Admin's `lv compose up` from an upgraded host records the
intent of a stack deployed before it. During the roll, a stack torn down on a
host still on the previous release leaves the intent its last deploy with
`sg.write` recorded in force for the stack's name: the upgraded hosts turn
a default-deny it asked for back on, owned by the name, a later deploy of
that name without `sg.write` is refused, and the name raises
`stack.firewall_teardown_held`. An Admin's `lv compose down --name <stack>`
from an upgraded host clears it. Likewise, an Admin's `lv compose up` on a
host still on the previous release records no intent: when it drops the
stack's firewall or default-deny, the upgraded hosts keep the default-deny
the recorded intent asks for and raise the condition. Run it again from an
upgraded host.

### A stack's default-deny is never removed by the reconciler

On this release the stack reconciler gives the cluster default-deny back to
a stack that asks for it whenever no default is in force, however new the
removal, and never removes a deny on its own. Until `failover_scope_v1` has
latched no firewall intent is recorded, and a stack's file alone says whether
it asks: an `lv compose up` that drops `default-deny` can leave the deny on,
owned by the stack, when a reconciler pass runs while it is recorded. The
stack reconciler raises `stack.firewall_deny_unasked` naming the stack, and
`lv firewall default-deny off` turns the deny off (docs/diagnostics.md).

### Firewall rules, ip sets and default policies need sg.write

On this release, `lv firewall cluster-rule add/rm`,
`lv firewall host-rule add/rm`, `lv firewall ipset add/rm` and
`lv firewall default-deny`, and the same actions in the web UI, need `sg.write` at `/` (Admin or NetworkAdmin)
where they needed the operator role. An Operator is refused on an upgraded
host, with the grant that lets it:
`lv role grant NetworkAdmin <principal> --path / --propagate`. A host still on
the previous release checks the operator role only until it is upgraded. A
caller with no role binding of its own is unchanged: its legacy operator role
still passes.

### A hand-deleted NetBox address is re-created after the roll

A lease names its NetBox address object by id. When that object is deleted in
NetBox by hand, the inventory mirror can no longer give the NIC its address.
It skips that one address, runs the rest of the pass, and reports the pass
unconverged. Once the `netbox_ip_repoint_v1` capability token has latched, the
mirror also repairs it. It re-creates the address in NetBox at the lease's
address, under the NIC's identity and inside the bound prefix, then points the
lease at the new object and assigns it. The token latches on its own once every
host the cluster replicates to, including one parked in `maintenance`, runs
this release. A host on the previous release cannot decode the statement that
re-points the lease. The address is looked up first: if NetBox shows any object
at it, nothing is created, and the mirror keeps reporting the pass unconverged
until that object is removed in NetBox.

`netbox_ip_repoint_v1` is mandatory and replication-gated, with no flag. Its
stand-down is the inventory mirror's own: `netbox.mirror_inventory` off on
every node stops the only writer. A binary rolled back below the latched token
enters WAL quarantine, as below every latched token. Roll forward.

### A deleted account stays deleted after the roll

A password change made on a host that has not yet seen an account's
`lv user delete` used to bring the account back on every host, with that
password. Once the `user_incarnation_v1` capability token has latched, a
delete names the account it ends, and no later write to that account from a
lagging host revives it. `lv user create` of a deleted name makes a new
account, which replaces the deleted one everywhere. Nor does a lagging
host's password change, or its delete of the deleted account, reach the new
account: its password, second factors, recovery codes, role bindings,
enrollment code, directory bindings and session cut-offs stay its own. The
same holds for anything else a lagging host gives the deleted account: an API
token or login session minted there, a role binding, a directory binding, an
enrollment code, recovery codes, a second-factor change, or an enable or
expiry change. A host that learns of the re-create drops the deleted
account's tokens and sessions it holds. A write to an account that is deleted
or re-created while the write is being made fails and changes nothing; run it
again. A second factor, a disable or an earlier expiry that reaches a host
before the account it belongs to does is applied there at once, and taken
away again only if the host then learns of a newer account of the name. Two
things of the deleted account can still reach the new one from the lagging
host itself, and both only take access away: its session cut-offs, which log
the new account out once, and its clearing of a directory identity the new
account is bound to as well, which the new account binds again. A second
factor enrolled on a host that had not latched the token yet names no
account. A host that then learns of the re-create holds it: the factor is
kept, but never accepted, and the account cannot log in, even with its
password, until an admin removes it with
`lv 2fa disable --user <name> --method <method> --label <label>` (the
factor's own method, `totp` or `webauthn`) and then issues an enrollment
code with `lv 2fa enroll-code <name>`. `lv 2fa ls --user <name>` lists a
held factor with `(held)` after its label, and the `held_second_factor`
health condition names the account and the commands for each held factor. The
token latches on its own once every host the cluster replicates to, including
one parked in `maintenance`, runs this release. Until then hosts write and
merge users rows as the previous release does.

`user_incarnation_v1` is mandatory and replication-gated, with no flag and no
stand-down. A binary rolled back below the latched token enters WAL
quarantine, as below every latched token. Roll forward.

### A re-created project starts without the old one's grants after the roll

A role binding a host granted on a project before it heard that the project
was deleted and created again elsewhere used to reach the new project and
grant there. Once the `project_incarnation_v1` capability token has latched,
each `lv project create` of a name gives the project a new identity, and a
role binding grants only on the project it was granted for. One granted on an
earlier project of the name is kept and grants nothing: `lv role ls` lists it
with `(held)` after its role, it keeps its principal bound, and
`lv role revoke <binding-id>` removes it. The same holds for a binding granted
before the upgrade on a project that is re-created after it; bindings on
projects that are not re-created keep granting as before. A quota set with
`lv project quota` is bound to its project the same way: a re-created project
never enforces the old one's quota. A host's orphaned
admission authority for a deleted project is retired only on hosts that still
hold that deleted project, never on one that has the new project. A grant or
`lv project quota` made while its project is deleted or re-created fails and
changes nothing; run it again. The token latches on its own once every host
the cluster replicates to, including one parked in `maintenance`, runs this
release. Until then hosts write projects and bindings as the previous release
does.

`project_incarnation_v1` is mandatory and replication-gated, with no flag and
no stand-down. A binary rolled back below the latched token enters WAL
quarantine, as below every latched token. Roll forward.

### Console passwords start after the roll

This release gives each VM's VNC and SPICE consoles a per-VM password
([ui.md](ui.md#console-passwords)). The daemon on the VM's host presents it. A
host on the previous release relays the console stream raw, so a passworded
guest that reached it by a live migration would have a console nobody could
open. So no host sets a password until the `console_password_v1` capability
token has latched. It latches on its own once every host the cluster
replicates to, including one parked in `maintenance`, runs this release.
Nothing changes mid-roll. A console opened through a previous-release host
that only relays it keeps working, because the VM's own host does the
authentication.

After the latch, each VM gets its passwords at its next define or start; a VM
already running keeps an open console until then. `enforcement.console_password`
(default on) is a per-host choice. The token is advertised whatever the flag
says, because presenting a password does not depend on it, so a host with the
flag off still opens every passworded console and only stops setting new
passwords. A binary rolled back below the latched token enters WAL quarantine,
as below every latched token. It also cannot present a password, so every
passworded guest on that host has a console nobody can open (the guests
themselves keep running). Roll forward; if you must run the older build, set
`enforcement.console_password: false` on every host first and restart each
guest, so their next start has no password.

A FIPS-mode host (whose QEMU has no DES for VNC authentication) sets no VNC
passwords, takes incoming live migrations without them, and reports
`console_password_v1` in `not_enforcing`; it never fails a start over one.

### Load balancer VRRP moves off the guest network after the roll

On earlier releases, each load balancer host multicasts its keepalived VRRP
adverts on the bridge its VIP is on, with a password derived from the LB's
name, so any guest on that bridge can read the password and answer with a
higher priority, which takes the VIP off its holder. This release sends them
as unicast between the LB hosts' recorded addresses, over the host network
([compose.md](compose.md#load-balancer)). A host on the old transport and a
host on the new one do not hear each other and would both hold the VIP, so
nothing switches until the `vrrp_unicast_v1` capability token has latched. It
latches once every host the cluster replicates to, including one parked in
`maintenance`, runs this release; a host with `enforcement.vrrp_unicast: false`
withholds it, so it holds the switch off. The first host whose latch is durable
records it cluster-wide, once `failover_scope_v1` has latched there too (the
record lives in `cluster_policies`), and until then every host stays multicast.
Every LB host then re-applies its LBs within 2 seconds of that record reaching
it, whatever its own flag says: an LB is held by both its hosts for about the
replication delay between them plus 2 seconds. A host that cannot render unicast
(its recorded address is on no up, non-loopback local device) raises
`lb.vrrp.transport_refused`, stops its keepalived for each LB another host serves
on unicast, and runs on multicast each LB no other host serves.
Hosts must pass IP protocol 112 between their recorded addresses.

The stand-down is cluster-wide: `lv cluster vrrp-transport multicast` (admin),
which every host renders within 2 seconds of receiving it, and
`lv cluster vrrp-transport unicast` undoes it. It can be set before the latch
too, to keep the old transport. A host on an earlier build that comes back
after the latch renders multicast while its LB peers render unicast; they raise
`lb.vrrp.transport_split` naming it. A binary rolled back below the latched
token enters WAL quarantine, as below every latched token, and renders the
multicast transport its peers have left: roll forward, or set
`lv cluster vrrp-transport multicast` first.

### SPICE through the daemon

`lv spice --launch` and `--listen` now carry the SPICE console through the
daemon (`ProxySpice`), because the VM's SPICE listener is on its host's
`127.0.0.1` and a client never reached it at the host's address. Both the
host you enter on and the VM's host must run this release; through an older
one, each connection is refused and `lv spice` says the daemon predates
`ProxySpice`. Mid-roll, use an SSH tunnel to the VM's host instead
([ui.md](ui.md#spice-console)). No capability token gates it: an older host
simply lacks the RPC, and nothing is written.

### Console sessions in the audit log

Every VNC, SPICE and serial console session is now an open and a close row in
the audit log, and every refused open a row
([audit-log.md](audit-log.md#console-sessions)). There is no schema change and
no capability token: the rows go through the ordinary audit writer, and an
older host simply writes none. Mid-roll, a console entering on an older host
for a VM on an upgraded one is recorded only on the VM's host, under
`peer:<entry host>` rather than the user, and two users' concurrent SPICE
consoles relayed by that older host are one session there. Through an older
VM host, the upgraded entry host records a relayed session from the VM host's
first byte rather than its explicit accept, so a serial console that never
printed anything reads as a refusal (`aborted by the client`) or a session of
near-zero duration.

### Firewall: per-NIC rules move to the bridge, observed until enforced

This release enforces per-NIC policy — security groups, the cluster and host
tiers applied to each NIC, the default policy, the VLAN rule and the new NIC
guards — in a `bridge litevirt-nic` table on every bridge port, instead of in
the `inet` forward hook, where traffic between two guests on one bridge (and
between a guest and its host) was never filtered at all (docs/firewall.md,
"Where the rules are enforced").

An upgraded cluster starts in **observe** mode: the rules are installed with
would-drop counters and drop nothing, so nothing that worked before the roll
stops working, and every host with guest NICs raises `firewall.nic.observe`.
After the roll, read `lv firewall enforce status` — per host, per workload, NIC
and rule, what the rules would have dropped since the time it shows, totalled
across reloads and restarts — fix rules or guests as needed, then
`lv firewall enforce on`. A cluster founded on this release (`lv host init`)
enforces from the start; no host that joins or rejoins ever changes the mode,
which only `lv firewall enforce` does. A routed neighbour-discovery message (one
a router forwarded) is dropped in either mode; bridged ones are not touched,
with `br_netfilter` loaded or not. A NIC on the `trunk:` feature keeps carrying
its VLANs in either mode. Each host switches tables when it restarts on the new binary; the
per-NIC table loads first, in its own transaction. The daemon loads
`nf_conntrack_bridge`; a host that cannot load it enforces only the guards and
raises `firewall.nic.unavailable`.

New NICs are guarded against spoofing by default (in either mode) once every
host runs this release — a guard is the release feature `nic_guards`, so a NIC
created during the roll is created unguarded, as before; NICs that exist before
the roll are not, and stay unguarded through their VMs' rebuilds
and rolling updates (docs/firewall.md, "NIC guards"). NICs this release defines
name their taps after their MACs (`lvt<mac>`), so their guards are in force
before their domains run; a guarded NIC an older release defined is started,
or handed over by a live move, paused until its guard is in force — held
paused on its target, with the critical condition `firewall.nic.held`, until
the target can put it in force (`lv firewall nic-guard resume <vm>`;
docs/firewall.md, "Held paused"). A trunk NIC's VLANs in use at the upgrade
are recorded into its network's `allowed-vlans`, every 30 seconds until every
host runs this release (so a trunk an older host creates during the roll keeps
its VLANs too), each VLAN once; a new trunk's VLANs, and VLANs a re-create
adds to a trunk, need `lv network set <net> --allowed-vlans` — on a flat
bridge (a network name with no network row) too, with `network.update` at the
cluster root. The VLANs recorded for a flat bridge go with its trunks: into a
network row later created under its name, and onto `<name>` when a re-deploy
moves a legacy stack's NIC off the flat `<stack>_<name>`. Until every
host runs this release, a guarded VM is placed and moved only onto hosts that
enforce NIC guards: hosts whose daemon set the `litevirt.nic-guards` label to
the version they still report, which it does after every firewall pass that
put the per-NIC table in force and clears after one that did not.
Guards and the mode are recorded in `cluster_policies`, so a NIC created before
`failover_scope_v1` has latched is created unguarded, and the mode stays
observe until then.

IPv6 firewall rules and ip-set elements are the release feature
`firewall_ipv6`: refused until `release_2026_11_v1` has latched, which it does
once every host the cluster replicates to runs this release — an older
renderer refuses its whole plan on an IPv6 rule.

**Rolling a host back below this release.** The release installs a systemd
`ExecStartPre` that asks the binary about to start whether it owns the
`bridge litevirt-nic` table (a hidden command only this release and later
answer) and deletes the table when it does not. A rollback swaps the binary and
keeps the unit, so the rolled-back daemon starts without the stale table:
libvirt reuses `vnetN` names, and stale chains would hold the next VM to get a
name to another VM's policy. An upgrade writes the units of the binary doing
the upgrading — the older one — so this release, when its daemon starts on a
host whose unit lacks the step, installs it as the drop-in
`/etc/systemd/system/litevirt.service.d/10-nic-table-cleanup.conf` (and reloads
systemd), leaving the main unit and any local edits to it as they are: a host
upgraded from an older release has the step from its first start on this one. Only a host not run under the systemd unit at
`/etc/systemd/system/litevirt.service` lacks it; delete the table by hand there
(`nft delete table bridge litevirt-nic`). A rolled-back host keeps its
`litevirt.nic-guards` label, which its older binary does not know, but reports
its older version at start, so the label no longer counts: no guarded VM is
placed or recovered onto it. Rolling back below this release follows the
release token's rule (above): it quarantines once `nic_guards` or
`firewall_ipv6` has been used. A lab cluster that ran a pre-release build of
this branch may hold a marker for its own token `firewall_ipv6_v1`; that token
is retired, so this release recognises the marker and ignores it.

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

### Account lifecycle and the second-factor policy latch after the roll

Schema v64 adds `user_lifecycle`, one row per (account, attribute) holding an
account's `disabled` flag and `expires_at`. Nothing writes it, and nothing
writes the `login_2fa_required` second-factor policy row, until the release
feature `login_policy` opens (the release token `release_2026_11_v1` has
latched; see "Rolling back after a release token latched") — so `lv user
disable`, `lv user enable`, `lv user expire`, `lv user unbind`, `lv 2fa
enroll-code` and setting `lv 2fa policy` are refused with `FailedPrecondition`
(`the cluster upgrade must finish first (login_policy needs
release_2026_11_v1)`) until every host (every host in `maintenance` included)
runs this release. A previous-release host would neither decode the rows nor
enforce them; it has no statement that touches the table, so it cannot undo a
disable either. Delegated administration (`perm.modify`) needs no token: it
writes the existing `role_bindings` shape, and its rules are enforced where a
grant is created. It needs an **explicit** `perm.modify` (or `perm.*`) grant:
an existing `Admin` (`*`) binding on a project does **not** gain the right to
grant or revoke roles there. To see who holds delegation:
`lv role ls --role PermissionAdmin`.

**LDAP logins this release refuses.** The typed name must now literally be
the login value of the one entry the search finds (docs/auth.md,
`user_login_attr`). Check the realm config before the roll; these setups that
logged in before are refused after it:
- a `user_filter` with `%s` inside a longer value, such as
  `(userPrincipalName=%s@corp.example)`, and no `user_login_attr`: no
  attribute value equals the typed name. Set `user_login_attr` (for example
  `sAMAccountName`) or match a whole attribute (`(uid=%s)`);
- a `user_filter` with no `%s` at all (`(objectClass=person)`): every login is
  refused. Use `(&(objectClass=person)(uid=%s))`;
- a service account that cannot read the matched attribute (or
  `user_login_attr`): grant it read access;
- a typed name that differs from the stored one by more than ASCII case and
  surrounding spaces (non-ASCII case, NFD, width or accent variants): users
  type their name as stored.
A search that finds two entries for one name is refused too. Each LDAP or
OIDC account is bound to its directory entry at its first login after the
`login_policy` feature opens.

v64 also adds `session_factors` (what each session's login presented) and
`user_enrollment_codes` (hashed first-enrollment codes), written under the
same feature. A host below the release does not enforce any of it: it
accepts a disabled account's sessions and API tokens and does not confine
password-only sessions. Keep such a host out of the client path until it is
upgraded (docs/auth.md, "Rolling upgrade, and hosts below the latch"). From
this release on, a host in WAL quarantine refuses every user credential and
serves only local-root and peer mTLS.

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

### Lease-term claims latch after the roll

A node with an adopted voter generation that has members records a new
leader-lease term only after a majority of that generation has decided it for
the node. Before that, two nodes that took a lease over at the same moment
could both record the next term and both act as its holder. See
[Operating model](operating-model.md) → "Two nodes taking a lease over at once
record one term". There is no schema change: voters keep these decisions in
`local_recovery_claims`.

During the roll, a host on the previous build refuses a lease-term claim as an
unknown claim type and records terms without claiming them. An upgraded host
claims anyway, and records a term from the quorum read alone only when so many
voters give that refusal that the rest cannot form a majority. A voter that
does not answer counts as one that could still accept, so an older-build
minority plus one dead upgraded voter leaves a lease with no takeover until
the roll finishes. Once the mandatory, replication-gated `lease_term_claim_v1`
token has latched on a host, it always claims while a voter generation with
members is adopted. The token cannot latch while any host the cluster replicates to runs
the previous build, one parked in `maintenance` included.

A takeover now needs a majority of voters that can vote, not only a majority
that answers a read. `ha.lease.claim_no_majority` and
`litevirt_lease_term_claim_no_majority_total` show a lease that cannot get one.
There is no flag. Voter changes are decided by the same majority, so repair a
voter while `ha.voter.unavailable` names it (`lv cluster voter rm <host>` then
`lv cluster voter add <host>`). Once the claim itself has no majority, the
exits are restoring the lost voter, or fencing proof-grade every member that
cannot vote, abstaining ones included, and naming each in
`lv cluster voter force-reconfigure --lost <host>[,<host>...]`. `lv cluster voter reset`
returns hosts, as each adopts the reset generation, to recording terms from
the quorum read alone — the two-holder race — and also ends recovery-claim
protection. A binary rolled back below the
token after it has latched enters WAL quarantine, as below every latched token.

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
swapped, so you can fix it and re-run.

An upgrade of some hosts (`lv host upgrade host-b`) pre-stages **every other
member** too, and leaves their binaries alone: a member left on the old
schema refuses every push from an upgraded host. A member is skipped only
when it already runs the version `lv` probed from `--binary`, and that
version names one build: a `dev` build or a `-dirty` tree never matches, and
neither is treated as up to date by `lv host upgrade` with no host names.
"The same build" means the identical version string (`git describe` at build
time). Two builds that share one defeat it: a `VERSION=` override reused for
different code, or a tree whose only change is an untracked file, which
`--dirty` does not see. Build those with a distinct `VERSION`. When the
binary cannot be probed (built for another architecture), every member is
pre-staged, and `lv host upgrade` with no host names refuses before it
changes anything, whatever versions the members run: check the path given
to `--binary`, or name the hosts to upgrade.

A pre-staged host advertises the new schema at once, so the upgrade first
checks that every member answers (the read-only `lv host preflight-upgrade`
call) and pre-stages nothing until all do. A member that does not answer
(down, unreachable, or a daemon without the upgrade RPCs) refuses the
upgrade, naming it, with nothing changed on any host. Then bring it back and
re-run, upgrade it with the rest, remove it with `lv host rm <host>`, or name
it with `--skip-prestage <host>[,<host>]`. `--skip-prestage` pre-stages a
named member anyway if it answers, and otherwise leaves it on its old schema
with a warning; the targets' preflight blocks still apply. A skipped member
refuses replication from every upgraded host once it is back, until
`lv host upgrade <host>` reaches it, and while it does so `lv health` reports
[`replication_peer_schema_behind`](diagnostics.md#a-peer-refuses-replication-its-schema-is-behind-replication_peer_schema_behind)
on every node running this release or later. `--force` only skips preflight
blocks; it does not pass a member that cannot be pre-staged.

Every member is probed in parallel, a few at a time, and a member that does
not answer within 30 seconds counts as one that does not answer.

If a pre-stage fails after every member answered (a full disk, or a binary
built for another architecture), the hosts already pre-staged stay at the new
schema (it cannot be undone), the rest are still pre-staged, and the refusal
names them and the host that failed. That host refuses their pushes until it
is pre-staged: fix it and re-run, re-run with a binary built for that host,
or, for a member outside the upgrade, proceed without it with
`--skip-prestage <host>` and pre-stage it later. While it refuses, `lv health`
reports `replication_peer_schema_behind` only on nodes running this release
or later: on the rollout into this release every node still runs the old one,
so the refusal printed by `lv host upgrade` is the only sign.

A member pre-staged without its binary keeps running, and restarts safely,
on its old binary: that binary starts on the newer schema. Two things stay
until its own upgrade:

- The staged binary is left at `<daemon binary>.new` (for example
  `/usr/local/bin/litevirt.new`). Nothing starts it; the member's own upgrade
  overwrites it.
- A previous-release daemon on the new schema cannot record a tie
  acknowledgement: `lv cluster acknowledge-lease-term` on that host fails
  with `persist acknowledgement`. Upgrade the host first, then acknowledge.

A **target** whose daemon is too old to support the pre-stage RPC reports
`Unimplemented` and is skipped (it migrates itself on restart; a
single-version skew self-heals) — so the very upgrade that introduces this
feature still works as a plain rolling restart. Pass
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

## Email notification targets during a rolling upgrade

Email notification targets (see [notifications.md](notifications.md)) are new in
this release. Two effects while the fleet is mixed:

- **No email from older hosts.** A host on the previous build does not know the
  `email` target type: it logs `notify: bad target config` and sends no email
  for the events it handles. Create email targets after the last host has
  upgraded, or accept gaps in email coverage until then.
- **SMTP password creation is held back.** Storing an SMTP password is the
  `email_target_secret` feature of the release token `release_2026_11_v1` (see
  "Rolling back after a release token latched"). Until the token has latched,
  creating an email target that carries a password is refused with `the cluster
  upgrade must finish first (email_target_secret needs release_2026_11_v1)`; an
  email target without a password is allowed at any time. The first such create
  after the latch marks the feature used, after which a rollback below this
  release quarantines the host.

### Container exec, recreate and OCI pulls during the roll

Until every host runs this release:

- `lv ct exec` entered on a host still on the previous release reaches a
  privileged or legacy-confined container with Operator rights, as before.
  Run exec through an upgraded host.
- A compose recreate entered on a previous-release host deletes a container
  member before its new image is fetched, and does not hold a privileged
  member to the image it was built from. Run `lv compose up` through an
  upgraded host, and only once the member's own host is upgraded.
- An `lv ct pull` entered on a previous-release host may still let an
  Operator pull from a local source (`dir:`, `oci-archive:`,
  `docker-archive:`). Do not rely on local sources being the Admin's until
  every host is upgraded.
- An `lv ct pull --local` of the previous release that is still running does
  not re-check its item's lock file, which this release removes once the item
  is gone. Let such pulls finish before upgrading the host.
- A pull over an existing OCI library item is refused on a previous-release
  host. An Admin's claim (`lv ct pull --project`) replaces an item only on an
  upgraded host, entered through an upgraded host.
- A delegated `PermissionAdmin` on a previous-release host may grant the
  `ContainerRoot` role through a custom `*.exec` role.
- A container whose name is not valid today (anything but letters, digits,
  `_`, `.` and `-`, or exactly `.` or `..`) cannot be started, stopped,
  deleted, cloned or recreated by this release. Before the roll, on the
  previous release, clone it under a valid name (`lv ct clone <source>
  <new-name>`) and remove the original.

Once every host is upgraded, review the `ContainerRoot` bindings and revoke
any that were not intended:

```bash
lv role ls --role ContainerRoot
lv role revoke <binding-id>
```

### Re-created project names during the roll

During the roll, a host on the previous build can still retire a re-created
project's admission authority, and anti-entropy spreads that to upgraded hosts.
It recovers when the next admission claims a fresh authority epoch, and it
heals once every host runs this release.

### Migration-TLS credentials checked on every host

A host of this build checks its migration-TLS credentials before it reports
itself ready for an encrypted storage copy: a CA file that is not a set of
certificates (or not a file), a host certificate none of them issued, a key
that is not the certificate's, or a certificate outside its validity is
unusable. Such a host installs nothing for QEMU and is not ready.

During the roll a source on an older build reads only "ready" or "not
ready". With `migration.allow_unencrypted_storage: true` it would send a
storage copy in plaintext to a host that is not ready. So a host of this
build whose own credentials are unusable refuses a storage copy that asks for
TLS, naming the fix (`lv host install-migration-tls --reissue`): the older
source fails closed instead. A host that simply has no credentials answers
"not ready" as before, and the older source's opt-in applies, as it always
did.

The migration CA a host reports is a fingerprint of its CA file's
certificates as a set. For a single CA it is the value every build computes.
For a rotation bundle (two CAs) a host of this build and one of an older build
compute different values, so a storage copy between them is refused as
holding different migration CAs until both run this build. A memory-only move
between them is not refused: it stays in libvirt's tunnel instead of using
QEMU's TLS stream, and so does not use the migration network. Finishing the
upgrade restores both.

Peer connections of this build send gRPC keepalive pings while a call is
open, every 6 minutes. That is longer than any daemon permits by default (5
minutes), so a daemon on an older build never rejects them.
