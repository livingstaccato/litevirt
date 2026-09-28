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

A region is purely a host label (`hosts.region`) plus the anycast-DNS
concept below. The placement engine does **not** filter on region:
there is no `--region` flag on `lv run` and no
`placement.region:` compose key. To pin a VM to hosts in a region, use
the existing placement controls keyed off labels — `placement.host`,
`placement.require`/`prefer` against host labels you set with
`lv host label set`. See `docs/placement.md`.

## Regions and failure: one cluster, one failure domain

A multi-region cluster is **one failure domain that spans the WAN**, not one
HA domain per region. The region label is read by `lv region`, by
cross-region migration and by anycast endpoints. Nothing that decides
whether a host is dead, or where its workloads go next, reads it:

- **Quorum is one cluster-wide count.** The voter set is every host whose
  state is not `offline`, `maintenance` or `fenced`, in any region, witnesses
  included. Fencing a host needs `floor(N/2)+1` of those voters to report it
  unreachable. No region has a quorum of its own.
- **Membership and health probes span the WAN.** Gossip runs memberlist's LAN
  profile on every host whatever its region, and every voter probes every
  peer not in `maintenance` (a non-voter probes every voter and a sample of
  the other non-voters; see docs/migration-failover.md).
- **Failover targets are cluster-wide.** When a host is fenced, every other
  `active` host is a candidate for its VMs, and neither the failover
  coordinator nor the placement engine reads region. A VM fenced in `eu-west`
  can be restarted in `us-east`.

Quorum, fencing and failover scoped to a region are not available.

### What a site partition does

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

### Operator guidance

- **Put a tie-breaker in a third site.** Use either an odd number of sites
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
- HA quorum is cluster-wide, not region-local. On a site partition the
  majority site fences the minority site's hosts and may reschedule their
  workloads across the WAN, and an even split stalls both sides. See
  "Regions and failure" above before splitting a cluster across sites.
- Cross-region migrate copies the entire disk for source-local
  storage today; for VMs with many TB on local NVMe, plan for the
  copy time. Shared Ceph or NFS sidesteps the bandwidth question
  entirely.
