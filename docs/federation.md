# Federation: regions and anycast

litevirt's federation model labels every host with a **region** name
and exposes regions as a first-class operator concept: `lv region` for
discovery and cross-region migration, plus anycast service endpoints
that the embedded DNS server publishes with weighted round-robin
records.

The CRDT replicator (Crescent) is already WAN-native — no 5 ms-LAN
constraint — so federation is built on top of normal cluster state
rather than a separate "PDM" layer. A litevirt cluster IS the federation
unit.

## Regions

A region is a string tag on `hosts.region`. Single-region clusters
keep working unchanged — every host defaults to region `default`.

Set (or change) the region on a host:

```bash
lv host config eu-west-1 --region eu-west
```

List + inspect:

```bash
lv region ls
# REGION    HOSTS  HEALTHY  VMS
# eu-west   3      3        42
# us-east   3      3        37
# default   1      1        2

lv region status --region eu-west
# REGION   HOSTS  ACTIVE  VMS  LAST UPDATED
# eu-west  3      3       42   2026-06-06T12:00:00Z
```

(Omit `--region` to show a rollup for every region.)

### Region is a label, not a placement constraint

A region is a host label (`hosts.region`) plus the anycast-DNS
concept below. The placement engine does **not** filter on region when it
places a new workload: there is no `--region` flag on `lv run` and no
`placement.region:` compose key. To pin a VM to hosts in a region, use
the existing placement controls keyed off labels — `placement.host`,
`placement.require`/`prefer` against host labels you set with
`lv host label set`. See `docs/placement.md`.

The one place region is a hard constraint is recovery under region-scoped
failover (below): a workload fenced off a host is recovered onto a host in
the same region.

## Regions and failure

How a multi-region cluster fails over is a cluster-wide policy, the
**failover scope**:

```bash
lv cluster failover-scope            # show the scope and each region's quorum
lv cluster failover-scope region     # scope fencing and recovery to regions
lv cluster failover-scope cluster    # one cluster-wide quorum (the default)
```

- **`cluster`** (the default, and what every cluster did before it existed):
  one failure domain that spans the WAN. Described next.
- **`region`**: each region is its own failure domain for automated HA. See
  "Region-scoped failover" below.

The scope is a replicated row, not per-host configuration, so every host reads
the same answer. The design is in
[design/region-scoped-failover.md](design/region-scoped-failover.md).

### Cluster scope: one cluster, one failure domain

Under the default scope a multi-region cluster is **one failure domain that
spans the WAN**, not one HA domain per region. The region label is read by
`lv region`, by cross-region migration and by anycast endpoints. Nothing that
decides whether a host is dead, or where its workloads go next, reads it:

- **Quorum is one cluster-wide count.** The voter set is every host whose
  state is not `offline`, `maintenance` or `fenced`, in any region, witnesses
  included. Fencing a host needs `floor(N/2)+1` of those voters to report it
  unreachable. No region has a quorum of its own.
- **Membership and health probes span the WAN.** Gossip runs memberlist's LAN
  profile on every host whatever its region, and every host probes every
  peer not in `maintenance`.
- **Failover targets are cluster-wide.** When a host is fenced, every other
  `active` host is a candidate for its VMs, and neither the failover
  coordinator nor the placement engine reads region. A VM fenced in `eu-west`
  can be restarted in `us-east`.

### What a site partition does under cluster scope

Say the WAN link between two sites fails. Each site now sees every host in
the other site as unreachable, and what happens next depends on which side
holds a majority of the voters.

**The majority side acts.** It reaches quorum on every host in the other
site, fences them, and reschedules their workloads onto its own hosts, across
the link that just failed. It cannot tell a partitioned site from a
powered-off one, because both look the same to a health probe. Whether the
reschedule actually happens depends on the host's `fence_strategy`, and a
site partition is where the strategies differ most:

| Strategy | On a host behind the failed link |
|---|---|
| `ipmi` | The power-off goes to the BMC. If the BMC sits behind the same failed link, the fence fails and nothing is rescheduled: the host is marked down and its workloads stay put until an operator acts. If the BMC is reachable some other way, the power-off lands and the reschedule is safe. |
| `ssh` | The fence reports failure on an unreachable host, so nothing is rescheduled. |
| `manual` | Nothing is rescheduled until `lv host fence-confirm`. |
| `best-effort`, which is also what an unset or unrecognised `fence_strategy` becomes | The fence reports success whether or not the power-off landed. Unless `enforcement.safe_fence_default` is on and latched, the majority reschedules the minority site's VMs **while they are still running there**, so two copies of each VM run at once. Do not use best-effort across sites. |

**The minority side stalls.** It cannot reach quorum, so it fences nothing
and reschedules nothing. Its runtime-ownership actions refuse: a start
another node placed there, a restart-policy restart, a replica promotion, an
owner-assert. They all sit behind `ExecutionGate`/`DecisionGate`, which
requires a majority this daemon probed itself. Workloads already running
there **keep running**, because nothing stops them when quorum is lost.
Once `vip_demote_v1` is enforced cluster-wide, the minority's hosts stand
their own VIPs down after `quorum_loss_demote_after_sec` of quorum loss.
A host self-fences only if that demotion cannot be confirmed and it has a
verified hardware watchdog.

**When the sides are equal, neither acts.** Split 2/2, each side counts
2 of 4 voters against a quorum of 3. Nothing is fenced and nothing moves on
either side. That includes a host that really dies while the partition
lasts: its workloads are not recovered until the link returns.

**The size of each site decides the winner in advance.** With 3 hosts in one
site and 2 in the other, a partition always resolves for the site with 3,
and the site with 2 is always the one the majority fences. If you lose the site with 3
outright, the site with 2 cannot reach quorum and recovers nothing
automatically.

### Region-scoped failover

With `lv cluster failover-scope region`, a host in region R is fenced, and
its workloads recovered, only by a decision whose quorum is R's own voters.

- **Fencing.** A host is fenced when a majority of its region's voters
  (`floor(V_R/2)+1`, counting voters other than the host itself) report it
  down. Reports from other regions' voters do not count, however many there
  are.
- **Re-admission.** An `offline` host returns to `active` on a majority of its
  own region's voters, the same population that may fence it.
- **Recovery decisions.** With `split_brain_gate_v1` latched, each reschedule,
  promotion and relocation re-checks that the deciding host probed a live
  majority of the failed host's region itself.
- **Execution.** A host starts, restarts or promotes a workload on itself only
  while it can reach a majority of its own region's voters. A cluster-wide
  majority is neither needed nor enough.
- **Recovery targets stay in the region.** A VM is rescheduled only onto a host
  in the failed host's region, a container relocated only there, and a
  replica auto-promoted only if the host holding it is there. If nothing in
  the region fits, the workload stays on the fenced host and
  `litevirt_failover_stranded_workloads` counts it.

**What a site partition does now.** Neither site can see a majority of the
other site's voters, so neither fences the other. The minority site's
workloads keep running and are not restarted anywhere else. Each site still
recovers its own dead hosts, if it has the voters to (next point).

**A region needs three voters to fence one of its own.** A fence needs a
majority of the region's voters other than the target, which exists only when
the region has at least three. A region with one or two voters has **no
automatic failover** for its hosts while the policy is on; it is never
widened to a cluster-wide count. `lv cluster failover-scope` marks such a
region `cannot fence its own hosts`,
`litevirt_failover_regions_without_quorum` counts the ones holding workloads,
and the coordinator logs each host it declines to fence and counts
`litevirt_failover_attempts_total{phase="quorum",result="refused",error_class="region_too_small"}`.
A witness counts as a voter of its own region, so two workers and a witness is
enough. The same counter's `error_class="region_scoped"` is a host in a large
enough region reported down only by other regions' voters: a site partition.

**A single-region cluster is unaffected.** The region is the cluster, so every
count and candidate set is the same under either scope.

**Changing the scope.** Needs the `admin` role. It refuses until every host,
including any in `maintenance`, runs a release carrying `failover_scope_v1`
(see [upgrades.md](upgrades.md#region-scoped-failover-needs-every-host-upgraded)),
and while any voter is unreachable from the host you run it against: each host
acts on the value it holds, and a change made from one side of a partition
reaches only that side. Under region scope, `lv host config --region` refuses
for the same reason, because a host's region decides who may fence it.

**What stays cluster-wide.** VIP self-demotion (`quorum_loss_demote_after_sec`)
and, with `enforcement.lease_term` on, the lease-term barrier still count every
voter. A minority site therefore still stands its VIPs down during a
partition, and with `enforcement.lease_term` on only the side holding a
cluster majority can recover a dead host while the partition lasts.

**Replication relays.** A host that is not a replication relay pushes only to
relays. If every relay is in one site, then during a partition the other
site's hosts reach each other only through the leaf fallback, which starts no
sooner than 15 seconds after the relays stop answering. Until it does, their
reports about each other do not meet, and their own region's fence waits.

**Cross-region DR.** Losing a whole site recovers nothing automatically: no
quorum of that region exists to fence its hosts, and from outside a lost site
looks exactly like a partitioned one. Recover by hand once you know the site is
down: fence it (`lv host fence-confirm <host>`), then `lv replication promote
<vm>` for replicated VMs. To let one VM be recovered into another region when
its own region fences its host but has no room, give it the label
`litevirt.failover_any_region=true` in its spec's `labels`; its home region
still decides the fence. Containers have no equivalent.

### Operator guidance

- **Under region scope, give each site three voters.** A site with two hosts
  and no witness has no automatic failover (see above).
- **Under cluster scope, put a tie-breaker in a third site.** Use either an odd number of sites
  that hold voters, or a witness host (`lv host config <host> --role
  witness`) in a site of its own. A witness votes but holds no workloads. With
  2 + 2 + a witness, a partition resolves for whichever site can still reach
  the witness. A witness placed *inside* one of the two sites makes that site
  the permanent winner, the same as the 3/2 layout above.
- **Fence with something that reaches across the partition, or refuses.**
  `ipmi` over an out-of-band management path is the only strategy that lets
  the majority reschedule safely. `ssh` and `manual` fail closed. See the table
  above for `best-effort`.
- **Pin workloads that must not cross.** Give each site's hosts a label, for
  example `lv host label set eu-west-1 site=eu-west`, and require it with
  `placement.require` (in compose, `require: {site: eu-west}`). Failover
  honours `require`. If no surviving host in that site fits, the VM stays on
  the fenced host, because there is no fallback to an unconstrained pick.
  `placement.host` does **not** pin through failover: a pin that names the
  failed host is dropped. A VM with `on-host-failure: none` is not
  rescheduled at all. Auto-promotion of a replica is the one exception: it
  takes precedence over that policy and promotes on whichever host holds the
  replica.
- **Containers ignore labels on failover.** A container's relocation target is
  chosen on capacity alone, so a container with an `on_host_failure` policy
  can land in any site. Leave that policy at `none` for containers that must
  stay put.

## Cross-region migration

```bash
lv region migrate <vm> <target-host>            # storage assumed shared
lv region migrate <vm> <target-host> \
    --with-storage --target-pool <pool>         # replicate disks first
```

The second positional argument is the **target host** (the destination
region is inferred from that host's `region` label). The handler drives
`ReplicateVolume` per disk into `--target-pool` before invoking
`MigrateVM(WithStorage=false)` against that host. The replication uses the storage driver's
native primitive when available — `zfs send | zfs recv`,
`rbd export-diff | rbd import-diff`, `btrfs send | btrfs receive` —
falling back to `qemu-img convert` otherwise.

Constraint today: `target-pool` MUST be reachable from the source
host (typical for shared Ceph RBD or NFS, or anywhere a replication
peer is preconfigured). Truly source-local storage requires in-band
streaming across regions, which is a planned follow-up
(truly-local cross-region disk transport).

## Anycast service endpoints

A *service endpoint* is a named (service, region) → IP mapping with
a weight. The embedded DNS server (`internal/dns/`) reads
`service_endpoints` on every query and returns rows in a
weight-respecting round-robin so a multi-region service surfaces
under one DNS record.

Each call registers (or replaces) one endpoint:

```bash
lv region anycast add --name api --ip 10.10.0.5 --region eu-west
lv region anycast add --name api --ip 10.20.0.5 --region us-east

lv region anycast ls
# SERVICE  IP           REGION    WEIGHT
# api      10.10.0.5    eu-west   1
# api      10.20.0.5    us-east   1

# Bias traffic 4:1 toward eu-west (re-add the same endpoint with a weight)
lv region anycast add --name api --ip 10.10.0.5 --region eu-west --weight 4

lv region anycast rm --name api --ip 10.10.0.5
```

The DNS server resolves `<service>.<dns_domain>` (default
`litevirt.local`) to one of the configured IPs. Internal callers
must use the cluster's DNS resolver — `dns_port` in daemon config,
typically delegated from the host's primary resolver.

Note: anycast at the *network fabric layer* (FRR/BGP/ECMP) is out of
scope for this slice — what ships is DNS-weighted round-robin, which
covers most internal-service use cases without router cooperation.

## gRPC surface

```
ListRegions          → list regions and their host counts/health
RegionStatus(name)   → per-host detail
CrossRegionMigrate   → drive ReplicateVolume + MigrateVM
GetFailoverScope     → the failover scope and every region's quorum
SetFailoverScope     → change it (admin; refused mid-roll or with a voter unreachable)
UpsertServiceEndpoint, ListServiceEndpoints, DeleteServiceEndpoint
```

REST surface (see `docs/rest-api.md`):

- `GET /api/v1/regions` (`?region=`) → `RegionStatus`
- `GET /api/v1/regions/list` → `ListRegions`
- `POST /api/v1/regions/migrate` → `CrossRegionMigrate` (SSE for progress)
- `GET|POST|DELETE /api/v1/services` → the service-endpoint RPCs
  (DELETE takes a `{service_name, ip}` JSON body)

## When NOT to use multiple regions

- The CRDT replicator works fine across regions, but understand what the
  latency buys and what it does not. A write does NOT wait for a remote
  region — it commits locally and returns, and the cross-region latency
  is how long the state stays divergent, not how long your call blocks.
  So a chatty, consistency-sensitive workload does not get slower across
  regions; it gets a wider window in which two regions disagree, and
  last-writer-wins settles it. A single region with a high-availability
  layout is simpler. See [Operating model](operating-model.md) → "Three
  different guarantees, one vocabulary".
- Under the default failover scope, HA quorum is cluster-wide, not
  region-local. On a site partition the majority site fences the minority
  site's hosts and may reschedule their workloads across the WAN, and an even
  split stalls both sides. `lv cluster failover-scope region` changes that. See
  "Regions and failure" above before splitting a cluster across sites.
- Cross-region migrate copies the entire disk for source-local
  storage today; for VMs with many TB on local NVMe, plan for the
  copy time. Shared Ceph or NFS sidesteps the bandwidth question
  entirely.
