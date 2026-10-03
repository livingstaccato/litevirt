# Design: pause on losing the majority, settle on return

| | |
|---|---|
| Status | **Proposed.** Written before the code; §10 records where the code departs. |
| Issues | colonelpanik/litevirt#250, colonelpanik/litevirt#253 |
| Base | `fix/gossip-remerge-after-partition` at `0145e64c` |
| Builds on | [recovery-claims.md](recovery-claims.md) (single-winner claims, the voter set) |

Recovery claims (recovery-claims.md) make the majority decide **one** new
owner. They say nothing about the **old** one. A best-effort fence that cannot
reach its target records `assumed` and recovery proceeds, so a partitioned
host keeps running the copy the majority has just replaced. This document adds
two layers that close that gap:

- **Layer 2, pause.** A host that cannot see a majority of the voter set pauses
  its recoverable workloads after a fixed time. The majority waits until that
  time has certainly passed before it starts a replacement.
- **Layer 3, settle.** A host that comes back holding a copy that a certified
  claim gave to another host stops its own copy, keeping the definition and
  the disks.

## 1. Problem

Lab drill 1 on the kvm003-f3 5-node lab, build `84ee1603`
(`kvm003:~/drill-evidence/d1-partition-84ee1603/FINDING.txt`):

| UTC | Event |
|---|---|
| 13:10:31 | nftables drops all traffic between {node-1, node-2} and {node-3, node-4, node-5}. |
| 13:10:54 | node-4 holds the failover lease and reaches quorum for node-1 (3 observers, quorum 3). The best-effort SSH fence fails (exit 255), so the fence records `assumed`. |
| 13:11:04 | Claim `vm/d1a@1#0` is decided for node-5 at round 5, and d1a starts on node-5. |
| 13:16:11 | After the heal, `vm_dual_run` is CRITICAL: d1a is active on node-1 and on node-5. |
| after | node-1's reconciler logs "NOT destroying a local domain whose DB row points elsewhere — not a clearly-dead leftover" every pass, forever. |

The claim protocol did its job: one decision, one recovery start. The copy
that ran twice was the ORIGINAL, which nothing stopped. Two things are missing:

1. Nothing stops the original while the partition lasts. An `assumed` fence
   means the power-off request is not even known to have arrived.
2. Nothing stops it after the heal. The reconciler's non-destruction guard
   (`internal/health/reconciler.go`, `selfFence`) refuses to act on a DB
   `host_name` alone. That is correct: a converged-wrong `host_name` must not
   be able to kill a live VM. But it has no positive proof to act on instead.

**The end state the user chose:** no dual run, even briefly. After any dual run
that does happen, settle to exactly the certified copy, with no data destroyed
and no operator action.

## 2. Goals and non-goals

**Goals.**

- G1. While a host is cut off from the majority, its recoverable workloads stop
  executing before the majority starts their replacements.
- G2. Layer 2 changes nothing when its capability token has not latched. The
  majority behaves exactly as today, and so does recovery.
- G3. A host that comes back resumes what it paused only on positive evidence
  that nothing moved it.
- G4. A host that comes back holding a copy that a decided, verified claim gave
  to another host stops that copy, on that proof and nothing weaker.
- G5. No disk, definition or memory image is deleted by either layer.
- G6. A blip shorter than `T_pause` pauses nothing, when it starts from a
  healed state (`T_pause` of unbroken Yes, §3.1). Loss left in the window by
  an earlier blip less than a heal ago still counts, by design: that is what
  pauses a host on a lossy link (§4.1). A fleet-wide blip pauses
  everything and resumes everything, with a condition raised while it lasts.

**Non-goals.**

- Hosts whose daemon is dead. A dead daemon cannot pause anything. That is the
  case a hardware watchdog covers (§7, F1).
- One-way partitions, where A reaches B but B does not reach A (§7, F4).
- Replacing fencing. An IPMI fence that verifies a power-off needs no pause and
  no wait (§4.4).

## 3. Layer 2: the minority pauses

### 3.1 The trigger

The trigger is the **execution quorum**. That is the quorum `ExecutionGate`
requires: `QuorumProof` over `corrosion.VoterSet`, or the host's own region's
voters when failover is region-scoped (`Checker.executionQuorum`). It is the
majority that may fence this host and recover its workloads, which is the one
that matters. It is computed from this daemon's own probe results, never from
replicated `host_health` rows, which freeze and look fresh during a partition.

A `PartitionPauser` runs on every node and ticks every `partitionPauseTick`
(1 s). It keeps the quorum readings of the last `2·T_pause` on the local
monotonic clock, and accumulates loss rather than timing it continuously:

- **It pauses** once the readings that are not Yes (No, or Unknown) cover at
  least `T_pause` of that window (§3.3). Each interval between two readings
  counts as the EARLIER reading's state, so a loss starts at the first reading
  that saw it. Charging it to the later reading counted up to a tick before
  that reading, while the last reading was still Yes, and paused a blip a tick
  short of `T_pause`. §4.1 already allows one tick (`Δ`) for the first lost
  reading to come.
- **Only an unbroken run of Yes readings lasting `T_pause` (`F·P` = 10 s)
  counts as the majority being back.** It clears the window and runs the
  resume path (§3.5). A single Yes on a lossy link is not a heal, and neither
  is a short run of them (§4.1).

A continuous clock, reset by any single Yes, would never pause a host on a link
that drops two probes in three, while the voters, which need only five
consecutive failures each, can still fence it. Accumulating closes that.
It never pauses later than a continuous clock would: continuous loss covers
`T_pause` of the window after exactly `T_pause`, so §4.1's bound is
unchanged.

Unknown counts as loss, unlike in the VIP demoter, which clears its clock on
Unknown. The demoter can afford to lose time, because its majority reclaims on
proof, not on a timer. This majority relies on a deadline (§4), so a stretch of
Unknown in the middle of a real partition must not push the pause past it.
Unknown means one of two things:

- **Startup warmup.** It ends with the first full probe cycle, about 2–3 s
  after start. That is far inside `T_pause`, so an ordinary restart pauses
  nothing. Once the first Yes arrives, warmup's readings are dropped, unless a
  No came with them: they were never a loss, and with a heal now taking
  `T_pause` of Yes they would otherwise shorten a partition that begins soon
  after start. A restart inside a partition reads No and never Yes, so it
  keeps them.
- **An unreadable voter set.** A host that cannot read its own voter set cannot
  claim a majority.

The pauser never pauses anything in these cases:

- **A single-node cluster**, meaning a voter set of size 1 that includes this
  host. Nothing could recover its workloads anywhere else.
- **A host in maintenance.** The coordinator never fences one (`run` skips it),
  so nothing would recover its workloads.
- **A witness.** It runs no workloads. Its pauser finds nothing to pause.
- **The flag is off** (`enforcement.partition_pause: false`, §5).

The maintenance exemption reads this host's own replica (L1). A host an
operator put into maintenance on the majority side during the partition, which
the minority never heard about, still pauses; the reverse — a host the minority
believes is in maintenance while the majority does not — does not pause, and
the majority may fence and recover it. Maintenance is an operator act; doing it
across a partition is the residual.

### 3.2 What is paused

Only a workload that **the majority would recover elsewhere**. The rule is the
coordinator's own, moved to `corrosion` so that both sides read one definition:

- **VM.** `vmNeedsFailover`: `on_host_failure` is set and not `none`, or the VM
  is enrolled in auto-promote replication, and it has no host-local firmware
  state.
- **Container.** `containerNeedsFailover`.

A workload with policy `none` keeps running. Nothing would replace it, so
pausing it would only cost availability.

It also has to be:

- **Running on this host now.** For a VM, libvirt state `running`. For a
  container, the LXC runtime says running. A domain that is already paused
  belongs to whoever paused it, and the pauser leaves it alone.
- **Owned by this host in this host's replica.** That means `host_name` is this
  host and the row is live.
- **Not being live-migrated.** The migration's target takes over, and a
  suspend would stall the migration itself.

**A workload the pass cannot account for is a failed pause** (§3.4): a domain
or container whose state cannot be read, or whose row cannot be read, is not
known to be stopped. Every libvirt and LXC call is bounded
(`partitionPauseCallTimeout`, 2 s); the pauses run **concurrently**, one
goroutine each, so the pass ends within one call timeout of its last read,
however many workloads there are. The reads themselves are bounded as a whole:
VMs and containers are read at once under one pass budget, every read ends by
`E − partitionPauseCallTimeout` after the pass starts (its timeout is cut to
what is left), and a workload left unread when the budget runs out is a failed
pause. So the pass stays inside `E` (§4.1) against a libvirtd or LXC that is
merely slow, too. A call that times out is abandoned, not cancelled. A pause
call blocks any second call for the same workload until it returns, so a
wedged suspend is never issued twice; a read blocks any second read of the
same kind (list, state, XML), so a wedged libvirtd holds at most one
abandoned goroutine per kind rather than one per tick per domain.

**How it pauses.**

- **VM.** `virDomainSuspend` (`libvirt.Client.SuspendDomain`). The vCPUs stop
  and RAM stays resident, so a resume continues where the guest stopped.
- **Container.** `lxc-freeze` (`lxc.Runtime.Freeze`).

### 3.3 The durable record

Before it pauses a workload, the pauser writes a record to a host-local file:

```
<data_dir>/partition-pause/<kind>-<name>.json
  {kind, name, owner_epoch, incarnation, domain_uuid, host, paused_at, reason}
```

The file is written through a temp file, `fsync`, `rename` and a directory
`fsync`. It is a file and not a table, for these reasons:

- It is a statement about what THIS host did to its own runtime. It must
  survive a restart, and it must never be replicated, repaired or merged. The
  owner-epoch marker files (`internal/health/owner_marker.go`) are the
  precedent.
- It costs no schema version, no new statement shape and no ledger entry.

**Write first, then pause.**

- A crash between the write and the pause leaves a record for a running
  workload. That is harmless: resuming a running domain is a no-op.
- Pausing first would leave the opposite after a crash: a paused workload
  with no record. The pauser would treat that domain as paused by an operator
  and never resume it.

`owner_epoch` and `incarnation` come from the row at the moment of the pause.
They are what the resume check (§3.5) and Layer 3 (§6) compare against.

**Resume only what self-fencing paused.** The pauser resumes a workload only
when a record exists for it. A workload an operator paused (with `virsh
suspend`, or `lxc-freeze` by hand) has no record, so the pauser never resumes
it. A container someone else froze is told apart with `lxc-info`'s raw state
(`IsFrozen`), since `lxc.Runtime.State` folds frozen into running.

**A record is true only while it describes the domain.** It carries the paused
domain's UUID. When the majority is back, a VM record whose domain is gone, is
no longer paused, or is another domain of the name is dropped: it would
otherwise hold `partition_paused` open forever and offer Layer 3 a stale epoch.
A memory snapshot, which resumes the guest when it finishes, is refused for a VM
a record holds, and `CreateLiveSnapshot` refuses any paused domain.

### 3.4 Pause failure

If a suspend or a freeze fails, the pauser does three things:

- It raises `partition_pause_failed` (evaluator `partition_pause`, subject
  `host/<name>`, severity critical), with the workload and the error. The row
  replicates whenever this host can replicate at all, which may be never
  during the partition.
- It retries every tick while the loss lasts.
- If a VERIFIED hardware watchdog is armed (`watchdog.Controller.Armed`), it
  self-fences, exactly as the VIP demoter does when a demotion cannot be
  confirmed. The host reboots, the VMs stop, and the disks are untouched.

**The majority does not count a host as paused when it holds an open
`partition_pause_failed` for that host** (§4.3). The majority sees this only
for a failure it has heard about: one from before the partition (a fleet-wide
blip whose pause failed, with the condition still open), or one that reached
it through a partial partition. A failure that happens inside a full partition
cannot reach the majority. That is F2 in §7.

### 3.5 Resume

The pauser resumes a paused workload only when **all** of these hold, checked
in this order:

1. **QuorumYes.** The execution quorum is back, from this host's own probes.
2. **The local row still names this host** at the recorded `owner_epoch` and
   incarnation (`created_at`).
3. **A majority of the voter set confirms it.** The pauser asks every other
   voter it can reach, with one peer-only, read-only RPC,
   `ConfirmPartitionResume`, answered from that voter's OWN replica and claim
   tables. It needs answers from enough of them that, counting itself, they
   are a majority. Every answer must say:
   - this host's state, in that voter's replica, is not `fenced`, `offline` or
     absent;
   - the voter's own **row** for the workload names this host, at the recorded
     owner epoch and incarnation. This is the check that holds with recovery
     claims off (the default), after `lv host undrain` has cleared the fenced
     state while the replacement runs, and when the majority moved the
     workload to an epoch the minority never saw;
   - that voter has accepted no recovery-claim value for this workload at the
     recorded epoch and incarnation, attempt 0, under either the
     incarnation-scoped key or the legacy one.

   One objection holds the workload. An unreachable voter, or one on a build
   without the RPC, is not an answer: during a rolling upgrade a paused
   workload on an upgraded host resumes once a majority of voters run this
   build.

**Why a majority of answers, and not this host's own replica.** A healed host's
replica is stale. In a 2|3 split its first anti-entropy exchange can complete
with the OTHER minority host, which missed everything too. That would mark it
"caught up" (`ReplicaCaughtUp`) without delivering the majority's writes.
Asking a majority directly removes the dependency on which peer it happened to
sync with:

- **Claims.** A decided claim needs accepts from a majority of voters. This
  host never accepts its own eviction (recovery-claims.md §3.5:
  `v.source_host == me` refuses). So any `q - 1` other voters intersect every
  accepting majority in at least one voter, and that voter reports the accept.
  The same arithmetic holds for any two majorities of one set:
  `(q-1) + q - (n-1) = 2q - n ≥ 1`.
- **No claims** (`recovery_claim` off). Every recovery is preceded by a fence
  that writes this host `fenced` or `offline` (`RecordFenceWithState`,
  `markHostState`). It is written on the coordinator at decision time, at least
  `W` (§4) before any replacement can start, and it replicates within the
  majority side during that wait. Any `q - 1` other voters intersect the fence
  quorum.

**Why it cannot race a new decision.** After step 1 this host sees a majority.
Under symmetric reachability those voters reach it too. A voter that can reach
the recorded owner refuses to accept its eviction (recovery-claims.md §3.5.1),
so at most a minority of voters could still accept, and no new claim can be
decided. Without claims, the coordinator's deadline check refuses a host that
observers have seen answer since the fence (§4.2).

**If any check fails, the workload stays paused.** The pauser logs why, once per
cause per workload. If a certified claim moved the workload, Layer 3 stops the
copy (§6). If the host was fenced and nothing moved, `recoverHosts` returns it
to `active` once a fresh healthy quorum agrees, but only when the coordinator
that fenced it also drove the recovery and moved nothing. Otherwise an operator
runs `lv host undrain`. Either way the next resume check passes. An answer that
does not come back (unreachable, or `Unimplemented` from an older build) is not
a yes. The pauser retries every tick.

**A fleet-wide blip.** No host has a majority, so nothing fences anyone. Every
host pauses. When the network heals, every check passes and everything resumes.

**Restart.** A restarted daemon reads its records at start. It does not re-pause
anything and it does not resume early. It resumes only through the same
checks, so a paused workload stays paused across a daemon restart.

### 3.6 Conditions and logs

While this host holds any self-paused workload, it holds a
`partition_paused` condition (evaluator `partition_pause`, subject
`host/<name>`, severity warning). It lists the paused workloads and the reason,
and it is resolved when the last record goes. A fleet-wide blip therefore
leaves one resolved condition per host in the history.

The daemon logs every pause, resume and hold with the workload's kind and name
and a reason. The lab check greps these lines:

```
partition-pause: paused workload       kind=vm name=d1a reason="lost the voter majority for 10s (2 of 5 live, 3 needed)"
partition-pause: resumed workload      kind=vm name=d1a reason="majority regained; 3 of 5 voters confirm owner node-1 at epoch 1"
partition-pause: workload stays paused kind=vm name=d1a reason="voter node-4 has node-1 fenced"
```

## 4. Layer 2: the majority waits

### 4.1 The timing argument

**Existing constants.**

| Symbol | Value | Source |
|---|---|---|
| `P` | 2 s | probe interval (`health.checkInterval`) |
| `τ` | 3 s | probe timeout (`health.checkTimeout`) |
| `C` | `max(P, τ)` = 3 s | probe cycle (the batch waits for its slowest probe) |
| `k` | 3 | consecutive failures for "suspect" (`suspectThreshold`) |
| `F` | 5 | consecutive failures for a fence vote (`FailuresToFence`) |
| `Δ` | 1 s | pauser tick |
| `E` | 5 s | bound on executing the pauses (per-call timeout, all workloads) |

**Minority detection, `D_M`.** Let `b` be the moment the link from the
minority host M to a majority voter V breaks. M's first probe of V that starts
after `b` starts within one cycle, and each later cycle starts within one
cycle of the last. The third consecutive failure therefore completes by the end
of its own cycle: at most `(k+1)·C` after `b`, which here is `4·3 = 12 s`. At
that point V is no longer `healthy` in M's view.

`C` grows with the number of peers M probes. A cycle waits for its slowest
probe, with at most `probeConcurrency` (16) in flight, so with `n` probe
targets a cycle lasts at most `C(n) = max(P, ⌈n/16⌉·τ)`. A voter probes every
non-maintenance host (`probePlan`), so `n` is the number of non-maintenance
hosts minus one, not just the voters minus one. §4.1's numbers are for
`n ≤ 16`. §4.4 scales them.

A stall of M's checker does not lengthen `D_M`. `quorumOver` refuses to count a
peer last seen healthy before the stall (stall.go), so a stall makes the quorum
read **No** sooner, not later.

**What the majority knows at its decision.** At decision instant `t_d`, measured
on the coordinator's monotonic clock, the coordinator holds `q` fresh
`host_health` rows about M. Each comes from a different voter V, with
`consecutive_failures ≥ F`.

- Each row was written before the coordinator read it, so its real-time
  write time is `≤ t_d`. That is causality, not clocks, so clock skew does not
  enter.
- V's `F` failures are consecutive probe completions at least `P` apart, so
  V's first failure was at least `(F-1)·P = 8 s` before that write.
- Under symmetric reachability, the link M↔V broke before V's first failure. So
  `b_V ≤ t_d − 8 s` for every V in the quorum.

**M has lost its majority at that point.** With `q` voters other than M unable
to reach it, M reaches at most `n − 1 − q` peers. Its live count is then at
most `n − q`, and `n − q < q` because `q = ⌊n/2⌋ + 1`. Region scope gives the
same arithmetic over the region's voters.

**So M pauses by:**

```
max_V b_V + D_M + Δ + T_pause + Δ + E
  ≤ t_d − 8 + 12 + 1 + T_pause + 1 + 5
  = t_d + T_pause + 11 s
```

**Choices.**

- **`T_pause` = `F·P` = 10 s.** That is the time the majority needs to build its
  own verdict. A loss shorter than that would never have been fenced, so
  pausing for it buys nothing. A blip that is shorter than `D_M + T_pause`
  (12–22 s, depending on where the probe cycles fall) pauses nothing.
- **Margin** = `max(0, D_M − (F−1)·P) + 2Δ + E + slack`, which is
  `4 + 2 + 5 + 2 = 13 s`. The 2 s of slack covers scheduling and the monotonic
  clocks' rate error (well under 0.1% over 30 s).
- **`W` = `T_pause` + margin = 23 s**, measured from `t_d`.

**Accumulated loss changes nothing here** (§3.1). From the moment M's links to
the quorum observers are continuously broken, M's readings are continuously
not-Yes after `D_M`, and they cover `T_pause` of the window after exactly
`T_pause`; earlier lossy readings can only add to that. What accumulation adds
is a lossy link that never breaks continuously: there the guarantee is
probabilistic — M pauses once it has lost the majority for half of `2·T_pause`
— while the observers' five-consecutive-failure rule makes a fence on such a
link equally a matter of chance.

**What a heal must last.** On a lossy link M can read an intermittent Yes
while the voters build a verdict against it. M's Yes needs only SOME majority
to answer its own probes, and each voter's failure run is its own, so a
majority of voters can each count `F` consecutive failures across a stretch in
which M's readings alternate. A heal that clears the window must therefore not
fit inside a verdict's build time. A run of three Yes readings did: on a link
that loses seven seconds in ten, every three-second Yes run cleared the
window, the loss never reached `T_pause`, and M never paused while the voters
fenced it. A heal is now an unbroken `T_pause` = `F·P` of Yes readings: as
long as any voter's `F`-failure run, so no clear can land inside the stretch a
verdict is built from without M having held a majority for that whole
stretch. `TestPartitionPause_ALossyLinkStillPauses` pins both the two-in-three
and the seven-in-ten patterns; `TestPartitionPause_AHealIsASustainedYesOfTPause`
pins the length. The cost is resume latency: a healed host resumes `T_pause`
after its first Yes instead of 3 s.

**Why `t_d` and not the coordinator's own last contact.** The coordinator's own
last successful probe of M is a LOWER bound on M's last contact with the
majority. Another voter may have heard from M later, and M keeps its majority
until enough of those links are gone. The decision instant is an UPPER bound on
every quorum observer's last contact, plus `8 s` of slack. The coordinator
therefore measures `W` from
`anchor = max(t_d, lastContact_C(M))`. The second term only matters if the
coordinator probed M healthy after the quorum formed, and taking the max keeps
that case safe too. "Measured from the last successful contact" therefore
means: from the latest instant the majority can prove M was still in contact.

**What it costs.** On the lab, quorum came 23 s after the partition
(`t_d` ≈ +23 s) and d1a started 10 s after that, at about +33 s. With Layer 2
latched it starts no earlier than `t_d + W` = `t_d + 23 s`, so at about +46 s
after the partition instead of +33 s.

All of these values are constants in `internal/health/partition_pause.go`.
`TestPartitionPauseWaitCoversTheMinority` pins the inequality
`W(n) ≥ max(0, D_M(n) − (F−1)·P) + 2Δ + E + T_pause + slack` against the live
constants, for 5, 17, 18 and 40 hosts, so retuning a probe constant cannot
silently break it. None of them is a config key. The majority computes `W` from
the same constants the minority runs on, and a per-node knob would break that
contract on the first node set differently.

### 4.2 Where the wait sits

All of this is in the failover coordinator (`internal/failover`).

1. `failover()` fences as today. If the fence's assurance would be `assumed`
   (best-effort SSH failed and proceeded), and the pause applies (§4.3), it
   keeps the method `best-effort-ssh` and prefixes the detail with
   `corrosion.FencePauseReliance`. A coordinator on an OLDER build reads the
   row exactly as it always has — an assumed best-effort fence, gated by
   `safe_fence_default` — where a new method value would have read to it as a
   proved power-off it could resume from at once. This build waits on the
   prefix, and operator surfaces (`lv doctor fence`, the coordinator's log)
   show assurance `self_paused` through `FenceAssuranceDetail`. It is not
   proof-grade. `litevirt_fences_total` classifies by method and result, so it
   counts these rows as `assumed`.
2. `recoverFenced` runs the safe-fence and confirmation checks unchanged. For a
   fence carrying the reliance prefix it then checks the deadline. If the deadline has not
   passed, it records `pauseWait[host] = anchor + W` in memory and returns
   without recovering anything.
3. On every later cycle, `run()` revisits a host in `pauseWait` through the
   handled-host branch, as it already does for `claimRetry`. Once the deadline
   has passed, it re-checks two things before it recovers:
   - the host is still `fenced` or `offline`;
   - **`fenceStillStands`**: no observer has seen the host answer since the
     fence.

   If either check fails, the wait is dropped and nothing is recovered. The
   host came back, it will resume itself (§3.5), and `recoverHosts` reactivates
   it.
4. A successor coordinator, or a restarted one, has no `pauseWait` entry. It
   resumes from the relied-on fence record through `resumeActionFor` →
   `recoverFenced`, and starts a fresh wait anchored at its own first sight of
   the record. That is later than the original `t_d`, so it is safe.

The recovery itself (claim, proof, destination start) is unchanged. It merely
starts after the deadline. A verified fence (IPMI) or an operator confirmation
never waits.

### 4.3 When the majority relies on the pause

All three of these must hold:

- `partition_pause_v1` is latched (`Gate.Enforced`), and this coordinator's
  own flag is on. This is §5.
- The TARGET host's own last cached Ping advertised `partition_pause_v1`
  (`Checker.PeerAdvertisedLast`, which makes no RPC: the host has just been
  found unreachable). The latch alone is not enough: a host whose flag went off
  after the latch stops advertising.
- The target host holds no open `partition_pause_failed` condition in the
  coordinator's replica.
- The fence's assurance would otherwise be `assumed`.

Otherwise the coordinator does exactly what it does today, and records
`assumed`.

### 4.4 More than 17 hosts

The coordinator computes `W` for the cluster it is deciding about, not for a
fixed size (`health.PartitionPauseWaitFor(n)`):

```
C(n)   = max(P, ⌈n/16⌉·τ)
D_M(n) = (k+1)·C(n)
W(n)   = T_pause + max(0, D_M(n) − (F−1)·P) + 2Δ + E + slack
```

| Hosts | Probe targets `n` | `C(n)` | `D_M(n)` | `W(n)` |
|---|---|---|---|---|
| 5 | 4 | 3 s | 12 s | 23 s |
| 17 | 16 | 3 s | 12 s | 23 s |
| 18 | 17 | 6 s | 24 s | 35 s |
| 40 | 39 | 9 s | 36 s | 47 s |

**Which `n`.** The minority's probe count is what matters, and the coordinator
cannot read it. It takes the largest count either side could be running with,
`n = max(G_adopted, G_latest, H) − 1`:

- `G_adopted` is the adopted voter generation's size, which is identical on
  every node that adopted it.
- `G_latest` is the newest generation in `voter_configs`, adopted or not, so a
  generation mid-change counts at whichever size is larger.
- `H` is the number of non-maintenance hosts in the coordinator's replica,
  because a voter probes all of them.

A host that was added inside the minority during the partition is not in the
coordinator's replica and is not counted. That is the one gap. Adding a host
is an operator act, and doing it inside a partition is a second fault.

## 5. Capability: `partition_pause_v1`

**Where the guarantee is enforced.** On the MINORITY, which pauses. The
MAJORITY relies on it: its whole wait-then-recover rule is sound only if the
host it fenced is running a pauser. This is the `recovery_claim_v1` and
`operation_protocol_v1` shape, not the `shared_storage_fence_v1` shape. So:

- **Withheld while the flag is off.** `advertisedCapabilities` drops
  `partition_pause_v1` when `enforcement.partition_pause` is false. A latched
  token therefore means every voting member has the flag on: config uniformity,
  not merely a uniform build. `TestAdvertise_PartitionPauseWithheldWhileOff`
  pins it.
- **Not mandatory.** It states a policy (availability against duplicate
  execution), and a policy needs a flag to turn off in an incident.
- **Not replication-gated.** It emits no new replicated statement shape:
  - the record is a host-local file;
  - the conditions use `UpsertHealthCondition`'s existing shape;
  - the fence row uses `InsertFenceLog`'s existing shape and the method every
    build already knows (`best-effort-ssh`), with the reliance as a prefix of
    its `detail` (§4.2), so an older coordinator reads the row as it always has;
  - the resume check is an RPC (`ConfirmPartitionResume`), not a replicated
    statement; a voter on a build without it answers `Unimplemented`, which is
    not an answer (§3.5).

  `ReplicationGated` is for latches that claim what a peer can DECODE. This one
  claims what a peer will DO, which is exactly what the voting-member latch
  measures.

**Acting does not wait for the latch.** The pauser runs whenever this node's
flag is on. It does not wait for the latch.

- The latch is the majority's reliance, and each node forms it on its own
  schedule (one unlatched token per HA-monitor cycle). Node A can latch while
  M has not.
- If M paused only once M had latched, A could rely on a pause M would not
  perform.
- So **a node advertises the token only while it already acts on it**, and the
  latch on any node implies every voter acts.

Pausing before the latch forms is still strictly safer than today: the
minority stops its copy, and the majority recovers as it always has.

**Default ON.** `LoadConfig` presets `enforcement.partition_pause: true`, the
`audit_signature` pattern. An explicit `false` wins, and is the kill switch:

- **On one host**, it withdraws that host's advertisement, so a latch that has
  not yet formed cannot form.
- **Once latched**, a host with the flag off reports the token in
  `PingResponse.not_enforcing` (`withheldStandDowns`, beside
  `recovery_claim_v1`), and its peers raise `ha_degraded`
  (unsupported_member). A coordinator also stops relying on that host's pause
  the moment its Ping stops advertising the token (§4.3).
- **Standing down in an incident** is `false` on every host and a restart.
  The coordinator relies on the pause only when its own flag is on AND the
  token is latched (`flag && Enforced`, the family rule) AND the target host
  advertised it, so a coordinator
  whose flag is off records `assumed` and recovers at once, exactly as today,
  and a host whose flag is off pauses nothing.

**The premise about watchdogs, corrected.** The brief said that a host with an
armed hardware watchdog is "already covered by it". It is not, for a
partition. `watchdog.Heartbeat` keeps petting the device as long as the daemon
runs. It self-fences only when the daemon dies, or when the VIP demoter cannot
confirm a demotion (`watchdog.go`, `vip_demote.go`). A partitioned host with
a live daemon and an armed watchdog keeps running its VMs indefinitely.

So the pauser runs on every host with the flag on, watchdog or not. The two
are complementary:

- the watchdog covers a dead daemon, which cannot pause (F1);
- the pause covers a live daemon on the wrong side of a partition, which the
  watchdog never fires for.

A watchdog host also uses its watchdog as the backstop when a pause fails
(§3.4).

## 6. Layer 3: settle on return

**Where.** `Reconciler.selfFence`, at the non-destruction guard. Today the
guard skips any local domain whose row names another host and that is not a
clearly-dead leftover. Layer 3 adds one way past it: **positive proof**.

**The proof.** A runtime-action proof row in this host's replica (it arrives
with the heal) for which all of these hold:

1. it targets this workload (`vm`, `<name>`), and its `dest_host` is the host
   the row now names, which is not this host;
1a. it **completed**, executed by its own destination (`status = completed`,
   `executor_host = dest_host`). A decided claim whose destination has not yet
   started the workload, or failed to, is not a running replacement, and
   settling on it would stop the only running copy;
2. it carries a claim certificate, and `corrosion.VerifyClaimCertificate`
   accepts it. That means:
   - the certificate decides exactly this proof's value;
   - its voter generation is adopted here, and no forced generation replaced
     it;
   - a majority of distinct members signed one ballot;
   - every signature chains to the cluster CA and is unrevoked;
   - the live row is the certificate's incarnation.
3. the certificate's key is for the **same incarnation as the local copy**, at an
   owner epoch **≥ the local copy's**;
4. the destination's OWN runtime reports the workload running now (the peer
   runtime inventory, `CheckPeerVMRuntime`). An unreachable destination, or no
   runtime check wired, is no proof.

Proofs `ReapSpentProofs` has tombstoned are still read: a host that comes back
more than a day later still needs the certificate.

A legacy-key certificate (one minted before `claim_incarnation_v1` latched)
names no incarnation. It is accepted only together with clauses 1a and 4 and
with the current row being the local copy's incarnation, so a legacy
certificate of an earlier incarnation could settle a copy only if its proof
completed on a host that now runs a later same-named workload whose row carries
the local copy's incarnation. That is the bound (L6); the legacy bridge
(`claims.Spec.AdoptLegacy`) does not record an incarnation attribution to check
against.

**The local copy's identity** comes from evidence on THIS host, never from the
row:

- **The pause record (§3.3)**, only while it still describes the domain: the
  domain is paused, with the recorded UUID.
- **The domain's own metadata.** The managed stamp, extended to carry
  `incarnation="<created_at>"` (`SetDomainManagedIncarnation`), gives the
  incarnation. The reconciler stamps it from a live row that names this host
  (`adoptManagedDomains`). An older binary's `<managed/>` element without the
  attribute still parses, as "incarnation unknown". A record and a stamp that
  disagree about the incarnation are no answer.
- **The epoch is the HIGHEST** of the record's, the owner-epoch element's
  (`GetDomainOwnerEpoch`) and the host-local owner-epoch marker file's, so a
  stale source can never make the local copy look older than it is.

A host WITHOUT the token settles from domain metadata alone, which needs both
the managed stamp's incarnation and an owner-epoch element or marker. The
owner-epoch element is written only when a VM with a real generation is
published running, so a VM still at the pre-epoch 0 (`enforcement.owner_epoch`
off, rows never graduated) has no epoch evidence and is not settled; it stays
behind the non-destruction guard as before.

If either the epoch or the incarnation is unknown, there is no proof, and the
guard skips the domain as it does today. That is why the brief says never to
act on `host_name` alone. A converged-wrong `host_name` is not a certificate,
and it cannot make one.

**The action.**

- **VM.** `DestroyDomain`. This stops the qemu process and keeps the definition,
  every disk and the NVRAM. A paused domain is destroyed the same way: its RAM
  belongs to a superseded copy.
- **Container.** `Stop`.
- Write an audit row: `partition.settle`, the target, `superseded by proof <id>
  for <dest> at epoch <e>`.
- Raise `vm_settled` or `ct_settled` (evaluator `partition_pause`, subject
  `<name>@<host>`, severity warning). The evidence holds the proof ID, the
  certificate's key and the destination.
- Drop the pause record.

The domain is now shut off with reason `destroyed`. On the next pass the
existing leftover cleanup handles it exactly as it handles any shut-off domain
whose row moved (`cleanableLeftover` → `UndefineDomain(name, false)`, which
keeps the storage). Layer 3 deletes nothing itself.

**Why a certificate is enough where `host_name` is not.** `host_name` is an LWW
column, and an equal-`updated_at` tie can converge it to the wrong host. A
certificate is a majority of signed accepts for one value. It can name another
host only if a majority of voters, each unable to reach this host when it
accepted, agreed to move exactly this incarnation at exactly this epoch.

**Hosts without the token.** Layer 3 does not depend on Layer 2. A host that
never paused (flag off, a pre-latch cluster, or a pause that failed) and comes
back running a superseded copy settles the same way. It needs only the domain
metadata.

**Containers.** Container rows are keyed `(host_name, name)`, and a relocation
tombstones the source row and writes a row at the target. "The row points
elsewhere" is therefore "my row is gone, and a live row at another host
carries a certified relocation proof". The ContainerChecker's runtime re-key
must not race this. It already refuses a re-key when the other host runs the
container (`split_brain`), so a certified relocation can only lead to a stop.

## 7. Failure modes

| # | Case | What happens | Residual |
|---|---|---|---|
| F1 | The minority's daemon is dead (crash, OOM, hung) | Nothing pauses. The majority still waits `W` and then recovers. | A dual run, as today. A hardware watchdog closes it, because daemon death trips it. Layer 3 settles it when the daemon returns. |
| F2 | A suspend fails inside a full partition | The minority raises `partition_pause_failed`, retries every tick, and self-fences if a verified watchdog is armed. | Without a watchdog, the majority cannot learn of the failure until the heal, so it counts a pause that did not happen. Layer 3 settles it on return. |
| F3 | The daemon restarts during the partition | Its loss clock starts at its own start, so it pauses at most `T_pause` + warmup after the restart. | If the restart lands after the majority's decision, the pause can miss the deadline by up to the restart's length. Layer 3 settles it. |
| F4 | One-way partition (A→M works, M→A does not) | M can count a majority that cannot count it, so it may not pause while the majority fences it. The coordinator raises `partition_one_way` (evaluator `partition_pause`, subject `host/<M>`, critical) when it sees both views at once: a quorum of voters with at least `F` consecutive failures of M, and M's own rows marking enough voters healthy for a majority, each written AFTER that voter's failure streak against M began, with that voter still failing M after M saw it healthy. The last clause is what a heal lacks: there the host's new healthy rows are newer than the voters' last failures. It does not recover any differently. | Still open. The fix is mutual reachability: a probe answer that states the responder's own view of the caller. Detection is partial, because the checker does not re-stamp a steadily healthy edge. M's "healthy" rows are fresh only after a transition (a restart, or a flap), so a one-way split that starts with every edge already healthy is not seen. |
| F5 | More than 17 hosts | `D_M` grows by one probe batch per 16 peers. | Closed: `W` is computed from the cluster's size (§4.4). The one gap is a host added inside the minority during the partition. |
| F6 | A host comes back before the deadline | The deadline check sees fresh healthy observers (`fenceStillStands` fails), and recovers nothing. The host's resume check passes once `recoverHosts` reactivates it. | If the lease moved in between, `recoverHosts` leaves the host `fenced` until `lv host undrain`, and its workloads stay paused until then, with `partition_paused` saying why. |
| F7 | A fleet-wide blip | Everything pauses, then everything resumes. `partition_paused` is raised on every host and resolved. After the heal, every coordinator holds failure rows its peers wrote during the blip, about every host, and replication delivers them before the observers' first successful probes overwrite them. A coordinator therefore decides no new fence while the quorum its fence rests on is lost, or within `QuorumRegainGrace` (`StallGrace`, 10 s) of that quorum's own No→Yes transition (`error_class=quorum_regain`), as after a stall of its own. The scope is the quorum the decision rests on — the cluster-wide one, or under region scope the target's region's — never the cluster-wide quorum for a regional decision: a region majority cut off from the rest of the cluster lacks the cluster-wide quorum for as long as the cut lasts, and is exactly the side that must fence. "Lost" is read fresh inside the grace check, never taken from the last recorded reading: a remote region's quorum is read only by a fence decision about one of its hosts, which the grace runs ahead of, so a recorded No would otherwise defer that region's fences for as long as nothing re-read it. A fresh Yes is the No→Yes transition and opens the grace from that moment. | Workloads lose execution time for the blip plus about one probe cycle. Accepted by the user. A fence decided anyway (a grace too short for a slow re-probe) waits out the pause and is then refused by `fenceStillStands`, and the host stays paused until `recoverHosts` reactivates it (F6). |
| F8 | A resume answer is missing | The workload stays paused and is retried every tick. | An unreachable minority of voters delays the resume. It never makes the pauser resume wrongly. |
| F9 | Recovery claims off | Resume relies on the fence-state check alone (§3.5). | Without claims, two coordinators can still each recover (recovery-claims.md §1). Layer 3 needs a certificate, so it does nothing without claims. |

## 8. Testing

Every assertion is mutation-verified: break the property, see the test go red,
restore it.

**Unit (`internal/health`, `internal/failover`, `internal/capabilities`,
`internal/grpcapi`).**

- **Pauser decisions:** the loss clock; a blip shorter than `T_pause`; Unknown
  counts as loss; warmup; a single node, a witness, maintenance, the flag off;
  policy `none`; an operator-paused domain left alone; a suspend failure raises
  the condition and self-fences only when armed.
- **Record:** the write-then-pause order; the record survives a new pauser on
  the same data dir (restart); resume needs a record.
- **Resume verdict:** every check in §3.5, in order; a missing answer is not a
  yes; too few answers hold.
- **The timing inequality** (§4.1) against the live constants.
- **Coordinator:** the reliance prefix only when latched, advertised by the target and assumed; the
  wait, scaled by cluster size; the deadline re-check; a host that came back;
  an open `partition_pause_failed` falls back to `assumed`; unlatched
  behaviour is unchanged; `partition_one_way` raised on both views and not
  on a symmetric split.
- **Capability:** withheld while off; not mandatory; not replication-gated;
  `tokenEnabled`.
- **Settle decision:** certificate present and verified; same incarnation;
  epoch ≥; unknown identity means no proof; never on `host_name` alone.

**Fleet (`tests/fleet/`, `RealGossip` + `libvirtfake`).**

- **Layer 2.** Split 2|3. The minority pauses within `T_pause` of losing its
  quorum, and the majority starts the replacement only after the deadline. A
  sampler asserts that no instant has two running copies. After the heal,
  nothing resumes on the minority.
- **Layer 3.** A dual run with a running copy on the old host (a host without
  the token) settles to one running copy.
- **Blip.** Every node partitioned from every other: everything pauses, and
  after the heal everything resumes, with the condition raised and resolved.

**Lab (after merge, not in this branch).** nftables drops all traffic on all 5
nodes at once, then heals. Grep for `partition-pause: paused` and
`partition-pause: resumed`. Repeat drill 1 and expect no `vm_dual_run`.

## 9. Alternatives considered

- **Self-fence (reboot) on losing the majority.** It needs a watchdog, it loses
  RAM, and a fleet-wide blip reboots the fleet. Pausing keeps RAM and costs
  only execution time.
- **Destroy on losing the majority.** Same objections, without even the
  watchdog's guarantee.
- **Wait for a minority heartbeat to stop.** A partitioned minority's
  heartbeat stops at the partition, not at its pause. Nothing the majority
  observes distinguishes "paused" from "running".
- **A replicated pause record.** It would cost a new statement shape and a
  replication-gated token, and it cannot cross a partition anyway, which is
  the one time it would matter.

## 10. Where the implementation departs from the text above

1. **`QuorumRegainGrace` (§7 F7) was not in the first draft.** Writing the
   fleet-wide blip scenario showed that a coordinator coming back from the
   blip can fence a host on the failure rows the blip left behind, which
   would leave that host paused behind a fence instead of resuming. The first
   cut stamped the cluster-wide quorum's every No, which stopped
   region-scoped failover outright (safety review H1); the grace is now per
   quorum scope and runs from that scope's No→Yes transition.
2. **CLAUDE.md** names `enforcement.partition_pause` beside
   `enforcement.audit_signature` as a default-on flag; the user applied that
   change at `7e690187`. `internal/daemon/config.go` and
   `docs/configuration.md` carry the default and its kill switch.
3. **The watchdog premise.** §5 explains why the pauser runs whether or not a
   hardware watchdog is armed. The brief said that an armed watchdog already
   covers a host; it covers only a dead daemon.
4. **`DecideResume` stops at the first objection.** One voter that has this
   host fenced, or that accepted a claim to move the workload, is enough to
   hold it. Waiting for a majority of objections would let a resume race a
   recovery that only one voter has heard of yet.
5. **Containers settle only when this host paused them.** A container has no
   managed-stamp incarnation and its owner-epoch marker is written only on a
   relocation, so the only evidence of a container copy's incarnation and
   epoch is the pause record. Layer 3 for containers therefore runs in the
   pauser's resume pass (`PartitionPauser.settleContainer`), not in the
   ContainerChecker: when a self-paused container's own row is gone and its
   one live row on another host carries a relocate proof whose certificate
   verifies for the recorded incarnation at an epoch at least the recorded
   one, the frozen copy is stopped (`ct_settled`, a `partition.settle` audit
   row). A container running on a host without the token is not settled; that
   remains open.
7. **Safety review, applied.** Settle requires a completed proof executed by
   its destination and the destination's runtime reporting the workload
   running (H2); the resume check reads the voters' own rows over
   `ConfirmPartitionResume` (M1); records carry the domain UUID and the local
   epoch is the highest evidence (M2); a relied-on fence keeps method
   `best-effort-ssh` (M3); the target must have advertised the token (M4);
   loss is accumulated with hysteresis, and a heal is an unbroken `T_pause`
   of Yes (M5); every skip is a failed pause and
   every call is bounded, with pauses run concurrently (M6).
6. **Stale-replica resume, tested.** The 2|3 scenario holds replication into
   the healed minority for 12 s while every other RPC flows, so the minority's
   own row still says the workload is its own and only the voters' direct
   answers can stop the resume.
