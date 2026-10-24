# Configuration

The daemon reads its config from `/etc/litevirt/config.yaml` (override with `LITEVIRT_CONFIG` env var).

## Full reference

```yaml
# Required: unique name for this host in the cluster.
host_name: "host-a"

# gRPC API port (mTLS). CLI and inter-host communication.
grpc_port: 7443

# Prometheus metrics endpoint (HTTP, no auth).
metrics_port: 7444

# Address the /metrics endpoint listens on. Empty (default) binds ALL
# interfaces, and that endpoint has NO auth and NO TLS — set "127.0.0.1" or a
# management-network address. See "Metrics endpoint exposure" below for what is
# readable without a credential; the daemon warns at startup while this is
# world-readable.
metrics_bind: ""

# Web UI port (HTTP).
ui_port: 7445

# Address the web UI listens on. Defaults to 127.0.0.1 (localhost only)
# so the UI is unreachable from off-host without a reverse proxy or
# SSH tunnel. Set to 0.0.0.0 to expose directly — only with TLS: either a
# reverse proxy that terminates it, or ui_tls / a custom certificate / acme
# below. The daemon warns at startup when it serves plain HTTP on a
# non-loopback address.
ui_bind: "127.0.0.1"

# Whether the web UI speaks TLS itself (docs/ui.md, "TLS"). `lv host init` /
# `lv host add` write `on` for a NEW node; a config without the key (an older
# node) means auto, and re-initialising a node keeps the value it has.
#   auto (the default when unset): TLS while a custom certificate is installed
#        (`lv host ui-cert set`) or acme: is configured; plain HTTP otherwise.
#        Re-decided while running — installing or clearing a certificate
#        switches the listener within seconds, no restart.
#   on:  always TLS. Serves the custom certificate, else ACME's, else this
#        host's cluster certificate (issued by the cluster CA; import ca.crt
#        into browsers that should trust it).
ui_tls: on

# WebSocket Origin allowlist for the UI (host patterns). Empty (default)
# enforces strict same-origin checks on the console WebSocket; add entries
# when the UI is fronted by a proxy on a different host/port.
ui_allowed_origins: []

# Reverse proxies in front of the UI and the REST gateway (CIDRs or
# addresses). From one of them, the client's address is the right-most
# X-Forwarded-For hop that is not itself a listed proxy; from anyone else,
# the TCP peer. Used for the per-address bound on in-progress OIDC sign-ins,
# the address a UI or REST login records on its session, and the login
# throttle. List only your proxies: a range that covers the clients lets them
# write their own X-Forwarded-For and choose their address.
# Empty (default): no forwarding header is believed. See docs/auth.md,
# "OIDC sign-in".
trusted_proxies: []

# REST API gateway port. Set to 0 to disable.
rest_port: 7446

# How often anti-entropy compares state digests with peers and full-syncs on
# drift. 0 = default (60s). Lower it (e.g. 10) on backup-critical clusters where
# faster drift detection is worth the extra digest traffic.
anti_entropy_interval_sec: 0

# Stand-down for incremental anti-entropy. A pass normally takes unchanged
# tables' digests from a cache and, for a table that disagrees with a peer, asks
# the peer which of its 256 buckets differ and pulls only those, a bounded page
# at a time (docs/design/ae-incremental.md). true makes this node pull whole
# tables as one blob and scan every digest, as older releases did; it still
# answers its peers' bucket and paged requests. Leave false unless you suspect the incremental path.
anti_entropy_legacy_repair: false

# Cluster membership port (used for peer discovery).
gossip_port: 7946

# Address peers reach this host on. Sets BOTH the gossip advertise address and
# the host record this daemon self-registers — they must agree, or peers dial an
# address the host certificate does not cover and every replication push fails
# the TLS hostname check. It is also this host's VXLAN tunnel endpoint (VTEP)
# once every host runs a release that knows it (docs/networking.md, VXLAN).
#
# Empty (default) auto-detects, which is only safe on an unambiguously
# single-homed host: the host record takes the source IP toward the DEFAULT
# ROUTE, while gossip takes the first private IP by INTERFACE ENUMERATION ORDER.
# Those are different heuristics and can pick different interfaces.
#
# SET THIS on any host with more than one network — a separate management NIC, a
# NAT'd or container fabric, a storage network. The failure is quiet and
# confusing when the auto-detected address is identical on every node (e.g. a
# NAT'd 10.0.2.15): gossip membership looks healthy and every node lists its
# peers by name, but each one dials ITSELF, so the cluster never converges and
# the logs show "certificate is valid for <real ip>, not <wrong ip>".
#
# MUST be a bare IPv4 literal — no port, no brackets, no hostname. The daemon
# refuses to start otherwise. IPv6 is rejected because cluster transport is
# IPv4-only today: gossip and gRPC both bind 0.0.0.0. Nothing downstream would
# catch a v6 value — memberlist accepts it and gossips it over the v4-only mesh,
# so the node boots looking healthy, no peer can reach it, and the failure
# detector marks it suspect and fences a host that was never down.
advertise_address: ""

# Path to TLS certificates (CA, host cert/key).
pki_dir: "/etc/litevirt/pki"

# Data directory for images, disks, and SQLite state.
data_dir: "/var/lib/litevirt"

# DNS server port (UDP). Serves <vm>.<stack>.<domain> records.
dns_port: 5354

# DNS domain suffix for VM name resolution.
dns_domain: "litevirt.local"

# Kernel watchdog device for self-fencing. Empty string disables.
# When set, the daemon validates the device exists (and is a character device)
# at startup and REFUSES TO START if it's missing — otherwise a broken watchdog
# would only be discovered at fence time, when the node can no longer self-fence
# (split-brain risk). Override with LITEVIRT_UNSAFE_SKIP_WATCHDOG_CHECK=1.
watchdog_dev: ""

# Bounds on petting, during startup, a watchdog timer that a previous daemon
# left running (a crash, or a stop while it owned workloads). Each startup
# pets for at most boot_keeper_max_sec; startups that never reach the
# heartbeat stop being petted after boot_keeper_max_boots, or once the first
# of them is boot_keeper_streak_window_sec old. A host whose daemon cannot
# come back then reboots at the watchdog timeout. 0 in any turns startup
# petting off (the timer is then first petted when the heartbeat starts).
#
# liveness_stale_sec: with watchdog_dev set and the device verified as a
# counting hardware watchdog, the daemon stops petting it, and self-fences,
# once neither a state-store round trip nor the partition pauser has made any
# progress for this long, so a wedged daemon cannot keep its workloads behind
# a petted watchdog. Progress is timed on the monotonic clock, so a wall-clock
# step is not a wedge. 0 turns this off; otherwise it must be at least 120
# (twice the hardware watchdog timeout). It does nothing in auto mode
# (watchdog_dev empty) or on an unverified device.
watchdog:
  boot_keeper_streak_window_sec: 300
  boot_keeper_max_boots: 5
  boot_keeper_max_sec: 120
  liveness_stale_sec: 120

# Load-balancer VIP split-brain safety (see migration-failover.md).
# quorum_loss_demote_after_sec: sustained local quorum loss before an isolated
#   LB host stands its own VIPs down (must be > 0). Default 12.
# keepalived_stop_timeout_sec: how long the stand-down waits for keepalived to
#   confirm stopped before escalating (must be > 0). Default 3.
# no_quorum_vip_policy: how the majority reclaims a VIP whose holder can't be
#   reached or proven released. Only "safe" is accepted (empty → safe): reclaim
#   ONLY on a release proof, else leave the VIP down + alert (never a blind
#   takeover). A weaker takeover-without-proof tier is intentionally not
#   implemented; recover a dead unreachable holder with `lv host fence-confirm`.
quorum_loss_demote_after_sec: 12
keepalived_stop_timeout_sec: 3
no_quorum_vip_policy: safe

# How often this host checks the managed fence SSH path to every peer: the
# pin, the key, the source address and the forced command, without arming a
# fence (`lv doctor fence`, litevirt_fence_ssh_probe_ok). Default 900 (15
# minutes); 0 disables the probe. See migration-failover.md "Managed fence SSH".
fence_ssh_probe_interval_sec: 900

# Peers to join on startup. At least one existing host.
join_peers:
  - "10.0.50.10:7946"

# PCI device management.
pci:
  # How often to rescan PCI devices. "0" disables periodic rescan.
  rescan_interval: "5m"

  # DEPRECATED: installs no udev rule. Real-time PCI events are covered by
  # rescan_interval. Setting it true only logs a warning; remove any leftover
  # /etc/udev/rules.d/99-litevirt-pci.rules (an upgrade cleans up the litevirt one).
  udev_hook: false

  # Free pcie-root-port controllers a NEWLY-DEFINED q35 domain is left with —
  # ports none of its own disks/NICs/hostdevs sit on — so a later hot-plug
  # (disk, NIC, or PCI) has somewhere to land. They are added right after the
  # define, from the addresses libvirt assigned. With none free, a live attach
  # fails with libvirt's "No more available PCI slots" (FailedPrecondition, not
  # a generic internal error). Default 4; an explicit 0 adds none, leaving the
  # one spare libvirt adds on its own. See docs/pci-passthrough.md "Spare PCIe
  # root ports" for what existing VMs get (no backfill) and why this is a
  # non-issue for live or cold migration.
  #
  # The value counts spares only: they are added on top of the root ports the
  # VM's own devices use (five for one disk and one NIC), so the maximum, 16,
  # can mean more than 20 root ports in total. Guest firmware reserves I/O and
  # memory windows for every root port and may fail to enumerate devices
  # beyond roughly 15 root ports in total; keep the value small on VMs with
  # many disks, NICs or PCI devices.
  spare_pcie_root_ports: 4

  # SR-IOV configuration.
  sriov:
    # false: operators provision VFs (litevirt reuses free VFs on any PF, but never
    # writes sriov_numvfs). true: litevirt may CREATE the VF pool on an adopted PF.
    managed: false
    # VF pool size litevirt creates on a managed, EMPTY, adopted PF (default 8),
    # clamped to the PF's hardware sriov_totalvfs. litevirt creates the pool ONCE; it
    # never grows, shrinks, or destroys a pool.
    max_vfs_per_pf: 8
    # Allowlist of PF PCI addresses litevirt may create VFs on when managed: true.
    # Entries are canonicalized (a malformed BDF is warned about + ignored). An empty
    # list with managed: true adopts no PF (reuse-only). A PF NOT in this list is
    # never written to — VFs there can still be reused if the operator created them.
    managed_pfs: ["0000:41:00.0"]

# Host-level storage pools (created as libvirt pools on startup).
# See storage.md for driver details. Operators may also add pools at
# runtime via `lv pool create` — those land in the cluster's
# storage_pools table without editing this file.
storage_pools:
  - name: default
    driver: local                         # local | nfs | ceph | iscsi | zfs | btrfs | lvm-thin | dir
    target: /var/lib/litevirt/disks

  - name: shared-nfs
    driver: nfs
    source: "10.0.10.1:/exports/vms"
    target: /var/lib/litevirt/mounts/shared-nfs

  - name: ceph-pool
    driver: ceph
    source: "litevirt"
    options:
      id: admin
      conf: /etc/ceph/ceph.conf

# Split-brain-family enforcement kill-switches. Each is a per-node on/off for a
# hardening feature whose capability token the build advertises but does NOT enforce
# until you opt in. Enforcement = this flag AND the token's cluster-wide latch, so the
# flag is BOTH the enable and the kill switch: set it false + restart to disable,
# regardless of any durable latch (never delete marker files). Every flag is false when
# absent, so an UPGRADE changes no behavior — the flip has to be deliberate.
#
# A NEW cluster is different, and `lv host init` treats it differently: with no cluster
# to preserve the behavior of, it writes safe_fence_default and shared_storage_fence as
# TRUE on the first node, in both its remote and `--local` forms (a target re-initialised
# with --force keeps the block it already has). Both protect against the same outcome — a
# best-effort fence that never landed reporting success, the coordinator rescheduling, and
# a writable shared disk being opened on a second host while the first still has it.
# Hosts JOINING a cluster inherit that cluster's block verbatim instead, so adding a node
# never flips a flag mid-roll. `lv host add` reads the block from this machine's config
# when it is a cluster node, and otherwise from an existing node's config over SSH (as
# the same user as the target); when it can read neither, it refuses before touching the
# target. To adopt them on an existing cluster, set both on every node and restart;
# `lv doctor fence` reports which nodes have not.
#
# Enable fleet-uniformly for lww_skew_guard (it changes merge behavior) and for vip_*
# enable the pair together.
#
# The values below are the ABSENT-key defaults, not what `lv host init` writes.
enforcement:
  safe_fence_default: false   # a best-effort (unconfirmable) fence must carry an operator
                              # proof (`lv host fence-confirm`) before reschedule/promote
  lww_skew_guard: false       # quarantine an incoming LWW row >5 min future-skewed (future-skew only)
  hlc_lww: false              # emit HLC conflict keys for updated_at (fixes the backward-clock
                              # lost-update: a wall-clock step-back can otherwise mint older-sorting
                              # keys that lose cluster-wide). The persisted monotonic clock
                              # (nowts.hwm) is ALWAYS on; this flips only the KEY FORMAT and is a
                              # real kill switch — per-node rollback is safe (the comparator orders
                              # HLC and RFC3339 by instant). Enable fleet-uniformly, AFTER every
                              # node is on the build.
  vip_self_demote: false      # a minority node releases its VIPs on sustained quorum loss
  vip_proof_reclaim: false    # majority refuses a VIP takeover without a release/fence proof
  shared_storage_fence: false # a cross-host transfer (auto-promote/reschedule) of a VM with a
                              # writable SHARED disk (nfs/ceph/rbd/iscsi) requires a proof-grade
                              # fence of the old owner (IPMI or `lv host fence-confirm`); a
                              # best-effort SSH fence is rejected. Local-disk transfers keep
                              # today's gate. Enable fleet-uniformly (changes failover behavior).
                              # See docs/migration-failover.md → "Shared-disk fence gating".
  operation_protocol: false   # rely on the operation journal, VM/container
                              # epoch/generation + active_operation_id barriers, durable
                              # device-lease recovery, and operation-backed capacity admission.
                              # Both operation_protocol_v1 and capacity_admission_v1 are advertised
                              # CONDITIONALLY on this flag, so their cluster-wide latches only form
                              # once EVERY node has opted in. capacity_admission_v1 deliberately has
                              # no standalone user flag. Enable fleet-uniformly; this flag is the
                              # reversible kill switch.
                              #
                              # REQUIRED FOR HOTPLUG. Device attach/detach — disk, NIC, and
                              # concrete-address PCI — refuse while this is off, because each
                              # is journaled and at-most-once and has no un-journaled path:
                              #   Error: attach disk: disk attach requires the
                              #   operation_protocol_v1 capability to be active
                              # A cluster left at the default therefore has no working
                              # `lv attach-disk` / `lv detach-disk` / `lv attach-nic` /
                              # `lv detach-nic`. That is deliberate, but the error names only
                              # the capability, so see this flag. Note the capability activates
                              # only once EVERY node has the flag on AND the token has latched
                              # cluster-wide: enabling it on one node changes nothing.
  live_resize: false          # allow TRUE live CPU hot-add + balloon-memory resize. Setting a VM's
                              # max_cpu vCPU-hotplug ceiling is refused until this latches cluster-wide
                              # (an old peer could drop max_cpu from a spec it rewrites), after which
                              # `lv update --cpu` grows a running VM's vCPUs live up to its ceiling.
                              # Enable fleet-uniformly; the flag is the reversible kill switch.
  digest_v2: true             # emit the order-invariant anti-entropy row digest (digest_v2), which
                              # pairs each value with its column NAME instead of hashing values in
                              # physical column order — so a fresh-CREATE vs ALTER-upgraded node stop
                              # showing a permanent column-order divergence. DEFAULT ON. Negotiated
                              # PAIRWISE by field presence (no latch): two peers compare v2 only when
                              # both emit it, else both compare v1, so a mixed fleet is always safe.
                              # Explicit false is the kill switch. See docs/diagnostics.md → "digest_v2".
  canonical_identity: false   # resolve the natural-key identity tables (snapshots,
                              # container_snapshots) by their UNIQUE natural key instead of the
                              # minted random id. Two nodes can independently create DIFFERENT ids
                              # for one logical object, whose rows then collide on the secondary
                              # UNIQUE and back-pressure; once this latches cluster-wide the
                              # receiver collapses each such pair to a single deterministic winner
                              # (newer updated_at; an exact-instant tie breaks to the smaller id
                              # ONLY when the rows' content is otherwise equal — a different-content
                              # tie stays a surfaced fault) by RE-KEYING the surviving row in place,
                              # so receiver-only columns are preserved. Unlike digest_v2 this is NOT
                              # pairwise — identity resolution mutates shared state, so (like
                              # operation_protocol) it is advertised only while this flag is on and
                              # activates only when the flag is set AND the token has latched
                              # fleet-wide. Enable fleet-uniformly; the flag is the reversible kill
                              # switch.
                              # (canonical_registry was removed on 2026-10-04: it only advertised a
                              # token for a writer that never shipped. A config that still sets it
                              # loads; the key is ignored and the daemon logs a WARN naming it at
                              # startup. See docs/design/canonical-registry-credentials.md.)
  vm_replace: false           # allow `lv cutover` to give a replacement VM the name a replaced VM
                              # still holds. The replaced VM is soft-deleted, so its tombstone still
                              # occupies that PRIMARY KEY, and no pre-existing replicated statement
                              # shape makes the handover safe on a RECEIVER — the batch needs ONE
                              # receiver decision over both VMs' incarnations and authority, which
                              # is a guard protocol only an upgraded peer understands. Advertised
                              # only while this flag is on, and `lv cutover` REFUSES until the flag
                              # is set AND vm_replace_v1 has latched fleet-wide — refusing before it
                              # stops a domain or writes to either VM, so a cluster that has not
                              # opted in gets a cutover that declines rather than one that
                              # half-applies. Requires enforcement.operation_protocol as well:
                              # the transition displaces the rows describing what the replaced
                              # VM owned, so the cleanup manifest is journaled as an operation
                              # and the step authorizing the destruction is committed with the
                              # transition. Enable fleet-uniformly; the flag is the reversible
                              # kill switch.
  project_authority: false    # route the PROJECT-QUOTA half of an admission to the project's
                              # admission-authority holder instead of deciding from this node's
                              # replica. Admission counts in-flight reservations, but two nodes
                              # that have not yet exchanged those rows each see only their own
                              # and can both admit — together exceeding the quota. One decider
                              # per project closes that window; HOST capacity is unaffected
                              # (only the target host's owner reserves against it, so it is
                              # already serialized). A holder that cannot be reached REFUSES the
                              # admission rather than falling back to the stale local view, so
                              # enabling this trades a little availability for the guarantee.
                              # Advertised only while on (like operation_protocol) and active
                              # only once the flag is set AND project_authority_v1 has latched
                              # fleet-wide — a peer still deciding locally would bypass the
                              # single decider entirely. Enable fleet-uniformly; the flag is the
                              # reversible kill switch.
  audit_signature: true       # DEFAULT ON — unset means on, as for digest_v2 above and
                              # recovery_claim, partition_pause, console_password and vrrp_unicast below. Sign every audit row this host writes with its cluster key
                              # (the same host.key that identifies it on the wire, under a
                              # separate signing domain). An unsigned chain is an UNKEYED
                              # hash: anyone who can write the database can edit a row,
                              # recompute the hashes after it, and `lv audit verify` comes
                              # back clean. A signature makes that require the host's private
                              # key instead of just the algorithm, and any OTHER node can
                              # check it — a compromised host cannot certify its own
                              # rewritten history. Signing follows this flag alone (signed
                              # rows are backward-compatible; old peers replicate the new
                              # columns untouched), and no node relies on a peer signing,
                              # so a mixed fleet is safe: a host on an older build or with
                              # the flag off is just a host that is not signing yet, which
                              # `lv audit verify` names under "not signing now". Builds
                              # before this default needed `audit_signature: true` set
                              # explicitly; see docs/audit-log.md "Turning signing on".
                              # The token is advertised only while the flag is on, and once
                              # it latches fleet-wide a write this node cannot sign is
                              # logged as an error and still RECORDED — dropping the row
                              # would lose the record of an operation that happened, which
                              # is the outcome an attacker would pick. It is caught instead
                              # by the verifier: while a host's published signing
                              # certificate stands, an unsigned row from it is reported as
                              # tampering on every node.
                              # Setting it to false is a real rollback, not a silent one: on
                              # the next start the daemon signs a retirement of its own key
                              # at the sequence its chain had reached, so rows after it are
                              # unsigned and expected. A host that cannot sign that
                              # retirement keeps its contract — that is the case it exists
                              # for — and `lv host retire-audit-key` closes it out from the
                              # machine holding the cluster CA.
  lease_term: false           # enforce leader-lease terms on this host (lease_term_v1).
                              # Enforcement is this flag AND the fleet-wide lease_term_v1
                              # latch, so clearing the flag stops enforcement on this host
                              # even after the latch has closed; the latch itself is
                              # one-way and durable. Config is read once at startup, so
                              # clearing it means editing the file and restarting the
                              # daemon on each affected node. See operating-model.md,
                              # "Leader-lease terms".
  owner_epoch: false          # activate the ownership-generation regime on this host
                              # (owner_epoch_v1). With the flag on, the health sweeps
                              # backfill every workload this host owns from the pre-epoch 0
                              # to a real generation, stamping its runtime marker (libvirt
                              # domain metadata / the container marker file) in the same
                              # pass. A new VM does not need that sweep: every create path
                              # assigns the first generation and stamps both markers before
                              # publishing it running, REGARDLESS of this flag, and the
                              # owner's reconciler finishes one whose create stopped short.
                              # Containers still land at epoch 0, so this sweep remains what
                              # graduates them.
                              # The token is advertised only once this node is READY —
                              # flag on and no owned workload left at epoch 0 — so the fleet
                              # can never latch across a node whose workloads are still
                              # ungraduated. Enforcement (refusing a stale rejoined replica's
                              # self-heal restarts on a marker/epoch mismatch) activates only
                              # after the fleet-wide latch. Enable fleet-uniformly; the flag
                              # is the reversible kill switch.
  isolation_epoch: false      # activate the isolation regime on this host
                              # (isolation_epoch_v1). A node whose local state was produced
                              # OUTSIDE the cluster's current compatibility regime — rolled
                              # back below a capability token it had already latched, or
                              # isolated by an operator — is recorded as isolated BY A
                              # HEALTHY PEER in cluster state (hosts.isolation_epoch), not
                              # by itself: a node that cannot be trusted to replicate cannot
                              # be trusted to record its own quarantine. With the flag on and
                              # the token latched, this node REFUSES that host's mutation
                              # pushes and will not merge from it via anti-entropy, until
                              # `lv host reseed` replaces its state and verifies convergence.
                              # Deliberately not a version check — mixed-version rolling
                              # upgrades keep working. Pre-latch clusters behave exactly as
                              # before. Enable fleet-uniformly; reversible kill switch.
  recovery_claim: true        # DEFAULT ON. Single-winner recovery claims (recovery_claim_v1,
                              # design/recovery-claims.md). The failover coordinator
                              # collects a majority certificate from the explicit voter set
                              # before it mints a reschedule, promote or container-relocate
                              # proof, and the destination verifies it before it executes
                              # (refusing with recovery_claim_unproven otherwise), so two
                              # coordinators that both think they lead can never both start
                              # one workload. Enforced only with this flag AND the latch AND
                              # an adopted voter generation (`lv cluster voter ls`).
                              # Advertised only while the flag is on and the node is ready
                              # (split_brain_gate_v1 latched, able to vote durably), so the
                              # latch means every host has it on. A missing key, an empty
                              # value or `~` means on; only an explicit `false` turns it
                              # off. An older build reads a missing key as false and
                              # advertises the token only with an explicit `true`, so the
                              # latch forms once every host runs a build that defaults it
                              # on (or has the explicit key) — nothing changes mid-roll.
                              # `false` is the kill switch: false everywhere + restart is
                              # the full stand-down, recovery is authorized as before, and
                              # voters keep their history. One host with false holds the
                              # latch off fleet-wide and keeps
                              # ha_degraded{reason="unsupported_member"} raised on every
                              # other host: opt out everywhere or nowhere. False on only
                              # some hosts AFTER the latch is the hazard, not a degraded
                              # mode — such a host reports recovery_claim_v1 in
                              # PingResponse.not_enforcing and its peers raise ha_degraded.
                              # WAL quarantine does NOT cover a host rolled back to an older
                              # build after the latch: that build knows the token and reads
                              # a missing key as false. Write `recovery_claim: true`
                              # explicitly before rolling a host back (`lv host init` on
                              # this build writes it for a new cluster); `lv doctor fence`
                              # warns about a latched cluster with a non-enforcing host.
  partition_pause: true       # DEFAULT ON. A host that cannot see a majority of the voter
                              # set for 10 s suspends every VM (RAM kept) and freezes every
                              # container that failover would recover elsewhere; a workload
                              # with on_host_failure: none keeps running. Each pause is
                              # recorded under <data_dir>/partition-pause, so only what this
                              # host paused is resumed, and only once a majority of voters
                              # confirms nothing moved it. Advertises partition_pause_v1
                              # only while on; once that latches, a coordinator whose
                              # best-effort fence cannot reach a host waits out that host's
                              # pause (26 s after its decision on up to 17 hosts, longer on
                              # larger clusters) before recovering, and records the fence as
                              # self_paused. Runs whether or not a hardware watchdog is armed
                              # (the watchdog fires only when the daemon dies); a verified
                              # watchdog is the backstop when a pause fails. A blip shorter
                              # than the pause time pauses nothing; a fleet-wide blip pauses
                              # everything and resumes everything on heal. An explicit false
                              # is the kill switch: that host pauses nothing and recovers an
                              # assumed fence at once, as before. See
                              # design/partition-pause.md.
  partition_pause_record_failure: pause
                              # What a partition pause does when its record under
                              # <data_dir>/partition-pause cannot be written (a full or
                              # failing disk). The majority relies on the pause, never on
                              # the record, which only decides what this host resumes.
                              # pause (default): pause anyway, keeping the record in the
                              # reserve (<data_dir>/partition-pause/reserve, 1 MiB made at
                              # the pauser's first pass while there is room) or, failing
                              # that, in memory, and write it to the directory once a write
                              # succeeds. A daemon that dies holding a record in memory only
                              # comes back to a paused VM with no record, which it never
                              # resumes itself. reserve: the record must be in the directory
                              # or the reserve before the pause; with neither writable the
                              # pause fails. self_fence: the directory only, and a write that
                              # fails is a failed pause (partition_pause_failed, and a
                              # self-fence), the behaviour before this key. reserve and
                              # self_fence need a verified watchdog: without one armed they
                              # pause as pause does, with the record in memory, and log
                              # fallback=no_verified_watchdog. A write that has not returned
                              # within 2 s (less when the pass is short of time) counts as
                              # failed. The reserve holds 1024 records; more at once are
                              # held in memory (warned once). It works where blocks are
                              # overwritten in place: ext4, xfs, and btrfs (made no-COW).
                              # On zfs it is best effort: give data_dir its own dataset with
                              # a refreservation, or rely on pause. Any other value fails the
                              # config load.
  console_password: true      # DEFAULT ON. Give the VNC and SPICE consoles of every domain
                              # this host defines a fresh per-VM password, so a local process
                              # or user on the host can no longer open a console on its
                              # 127.0.0.1 listener. Only the daemon on the VM's own host
                              # presents it: the web UI and `lv` reach VNC through it as
                              # before, and `lv spice` / the UI's .vv file carry the SPICE
                              # one. Applied at each define, and only once
                              # console_password_v1 has latched (an older build cannot
                              # present a password), so a VM running when it latches picks
                              # it up at its next define or start. The token is advertised
                              # on the build, not this flag: presenting is unconditional,
                              # so no host relies on a peer's flag. Before the latch nothing
                              # is set or removed. An explicit false is the kill switch:
                              # this host's next define (or revert/repair redefine) of each
                              # domain drops its passwords. A host whose QEMU cannot do VNC
                              # passwords (FIPS mode) sets none, keeps SPICE ones, never fails
                              # a start over them, and reports console_password_v1 in
                              # not_enforcing. See ui.md "Console passwords".
  vrrp_unicast: true          # DEFAULT ON. Whether this host advertises vrrp_unicast_v1 before
                              # it has latched. The token moves the load balancers' VRRP off the
                              # VIP's bridge, where any guest can read and answer it, to unicast
                              # between the LB hosts' recorded addresses; false holds that off for
                              # the whole cluster. Once latched it decides nothing: the transport
                              # is cluster-wide, and its stand-down is
                              # `lv cluster vrrp-transport multicast`. See upgrades.md.
  project_adoption: true      # DEFAULT ON. Run this host's project adoption pass: once
                              # release_2027_01_v1 has latched, give each project created
                              # before project_incarnation_v1 latched its stable identity
                              # (the release feature project_adoption). false holds this
                              # host's pass off and nothing else: the token is advertised
                              # regardless, and the host still applies its peers'
                              # adoptions. It keeps a rollback below release_2027_01_v1
                              # open only while it is false on every host. See upgrades.md
                              # "Projects created before the upgrade get a stable identity".
  gossip_encryption: false    # encrypt and authenticate gossip (memberlist, gossip_port)
                              # with the cluster key in <pki_dir>/gossip.key. false is
                              # plaintext; true is encrypted-only (anything unencrypted or
                              # under another key is dropped). An EXISTING cluster walks
                              # there in three rolling restarts, each finished on every host
                              # first: install (key loaded, still sends plaintext), staged
                              # (sends encrypted, still accepts plaintext), true. Nodes one
                              # stage apart interoperate; two apart cannot gossip. Every
                              # value but false refuses to start without a usable gossip.key.
                              # `lv host init` writes true for a new cluster. No capability
                              # token. See auth.md "Gossip encryption".
  fence_ssh: auto             # how this host's ssh and best-effort fences reach their
                              # target (migration-failover.md "Managed fence SSH").
                              # auto (the default, also when unset): the managed fence key
                              # toward a host whose sshd accepts it, else the legacy command
                              # with the host's published sshd keys pinned; toward a host
                              # that has published no row, the legacy command unpinned
                              # until release_2026_12_v1 latches, refused once it has.
                              # managed: the managed key only; a fence toward a host that
                              # does not accept it fails. Any other value refuses to start.
                              # No mode fences a host that has published a fence ssh row
                              # without its pinned host key. `lv host init` writes managed
                              # for a new cluster. No capability token.

# External NetBox IPAM integration. Disabled by default; when disabled no
# NetBox client is constructed and no behaviour changes (no HTTP, no goroutine).
netbox:
  enabled: false            # advertise netbox_ipam_v1 and allow prefix bindings
                            # (`lv network create --netbox-prefix-id`). Must be
                            # uniform cluster-wide for the latch to form — an older
                            # binary does not parse the prefix-binding field at all
                            # and would silently allocate from the builtin
                            # allocator across the whole prefix, so replicated
                            # state alone cannot make a bound prefix safe.
  url: ""                   # NetBox base URL, e.g. "https://netbox.corp".
  token_path: ""            # path to a file containing the API token. The token
                            # is read from this file at startup and is NEVER held
                            # inline in config.
  cluster_name: ""          # NetBox `virtualization.cluster` to mirror inventory
                            # into. Empty uses the local cluster name. NetBox
                            # allows one VM name per cluster, so two litevirt
                            # installations sharing one NetBox need a distinct
                            # name here or same-named VMs collide. Set it before
                            # the first sweep — changing it later strands
                            # everything written under the previous cluster.
                            # MUST BE UNIFORM CLUSTER-WIDE: identical on every
                            # node, or unset on every node. Unlike the
                            # enforcement.* flags there is no latch mediating
                            # this one, and the sweep runs on whichever node
                            # holds the `netbox` leader lease — so a value set
                            # on only some nodes duplicates the whole inventory
                            # into a second virtualization.cluster at the first
                            # leadership handover, and no sweep can then see the
                            # objects written under the other name. Nothing
                            # ENFORCED from the first bind onward: the bind
                            # PINS the name it resolved onto the
                            # netbox_bindings row, and any node whose own
                            # config resolves to a different one refuses to
                            # mirror and refuses `lv netbox rekey`, raising a
                            # netbox_cluster_name_mismatch health condition
                            # naming both values. Address allocation is
                            # unaffected. Unset on every node agrees (it
                            # resolves to the local cluster name); set on some
                            # nodes only does not. NOT enforced on a cluster
                            # with no bound network — there is no binding row
                            # to pin — so compare the mirror's startup log line
                            # across nodes there.
  site: ""                  # NetBox SITE NAME the cluster is scoped to, e.g.
                            # "DC-01". Every VM in a NetBox cluster inherits
                            # that cluster's site, and a VM with no site is
                            # invisible to anything that scopes by one — NetBox's
                            # own filters, and the DNS and inventory
                            # integrations built on them. litevirt cannot derive
                            # which site the hardware sits in, so like
                            # cluster_name it is operator-supplied.
                            # Empty leaves the cluster's scope UNMANAGED rather
                            # than clearing it: the scope is also settable by
                            # hand, outside this key, and writing an empty
                            # value through would strip the site off a working
                            # cluster and take every VM's inherited site with
                            # it. A name that does NOT exist in NetBox fails the
                            # sweep with the name it could not find, rather than
                            # being treated as unset — silently mirroring VMs
                            # with no site is the outcome this prevents, so a
                            # typo is loud. Applied on every sweep, so correcting
                            # it takes effect on the next pass with no restart.
  mirror_inventory: false   # opt into the INVENTORY MIRROR — the half that
                            # creates NetBox virtual_machine / vminterface
                            # objects and assigns addresses to them. Default
                            # false: NetBox is pure IPAM, holding ip_address
                            # objects that carry this cluster's identity and
                            # nothing else. That is a complete configuration,
                            # not a degraded one — the identity is what makes an
                            # address litevirt's, and the orphan sweeper proves
                            # an address unclaimed by a per-host negative
                            # fan-out that never reads what it is assigned to,
                            # so bind, claim, revalidate and reclaim all behave
                            # identically. Advertises netbox_mirror_v1 only
                            # while set, so the cluster-wide latch requires
                            # config uniformity: enabling on one node changes
                            # nothing, which matters because the sweep runs on
                            # whichever node holds the `netbox` leader lease and
                            # a non-uniform flag would make the inventory appear
                            # and disappear with leadership. Mirroring also
                            # still needs netbox_ipam_v1 (its tables are v51).
                            # The flag stays the reversible kill switch — a
                            # latch is monotone and durable.
  timeout_sec: 10           # per-request timeout.
  sweep_interval_sec: 900   # how often each configured node runs one maintenance
                            # pass: re-validate every binding, then reclaim
                            # NetBox addresses nothing claims. Unset (or <= 0)
                            # means 15 minutes. The sweep's leader lease is
                            # derived from this value, so exactly one node
                            # reclaims however many run the loop. Reclamation
                            # needs a complete whole-cluster proof, so a longer
                            # interval only delays it — it never weakens it.
                            # See docs/networking.md, "Maintenance and
                            # reclamation".
  # Binding a network to a NetBox prefix requires the netbox_ipam_v1 latch, and the
  # prefix must belong to a VRF with enforce_unique set. Global-table prefixes are
  # refused, because NetBox does not expose the global uniqueness setting through a
  # supported API.

# Authentication realms. The "local" realm is always present (bcrypt
# passwords in the cluster DB) and need not be listed here. OIDC and
# LDAP realms are loaded into a Registry at startup; `Login` dispatches
# by realm name. See docs/auth.md for the realm model.
auth:
  # Session lifetimes as Go duration strings. Empty = built-in defaults
  # (idle 8h / hard 7d). session_idle_timeout is the inactivity window
  # (refreshed on each request); session_hard_expiry is the absolute cap.
  session_idle_timeout: ""                # e.g. "8h"
  session_hard_expiry: ""                 # e.g. "168h" (7 days); at most "720h" (30 days),
                                          # a larger value is clamped to 720h with a startup warning
  # Strict mTLS identity: when true (and the strict_mtls_identity_v1 capability
  # is active cluster-wide), a bearerless "client" certificate (the distributable
  # CLI client cert, or any cert whose CN is not a live cluster host) is not
  # treated as admin — it must present a session bearer (`lv login`). Host/peer
  # certs and on-node loopback are unaffected. Default false. This flag is the
  # enforcement + kill switch. See docs/auth.md.
  strict_mtls_identity: false
  # Trust rotated peer certs — RECOVERY switch, not a steady-state setting.
  #
  # Peer trust binds a live host row to the certificate serial recorded in it. A
  # node re-records its own serial at startup, so an ordinary certificate rotation
  # converges by replication and needs nothing here. That re-record is
  # conditional (docs/diagnostics.md, own_row_held):
  #   - a certificate that renewed the recorded one (lv host renew-cert) is
  #     re-recorded at once;
  #   - otherwise, over a row at incarnation 0, the node first holds its own-row
  #     writes for ten minutes (reason at_start) and re-records when that hold
  #     times out;
  #   - otherwise, over a row at incarnation 1 or higher (a host re-added since
  #     host_incarnation latched), it re-records only when the row is the
  #     admission recorded in <pki_dir>/own-admission.json. A host without that
  #     record, or with another admission's, is held and never re-records: it
  #     needs `lv host rm` then `lv host add`;
  #   - a certificate swapped while the daemon runs, not by a renewal, is held
  #     until the daemon restarts, and then as above.
  # But if those recorded serials have ALREADY gone stale fleet-wide, every
  # daemon refuses every peer ("replication RPC requires peer mTLS") and the
  # cluster cannot repair itself: the correction has to replicate, and
  # replication is what is being refused.
  #
  # Set true on EVERY node to break that deadlock — a mismatch is then logged and
  # admitted for CA-issued HOST certificates instead of refused — wait for the
  # fleet to replicate, then set it back to false — only once every host above
  # has re-recorded or been re-added. It never relaxes the removal
  # tombstone (a decommissioned host stays out) and never lets a distributable
  # client certificate act as a peer. While it is on it ALSO turns off the
  # recovery-claim serial pin (accepts signed with a renewal's replaced key
  # count again, in claim certificates and voter generations) and stops
  # refusing RPCs on, or closing, connections made with a superseded host
  # certificate. Because such a node does not pin, the cluster also HOLDS the
  # revocation of a renewal's replaced certificate while any node has it on
  # (each node reports it as a certificate/trust_rotated_peer_certs
  # condition). Turn it off as soon as the fleet has converged. It is NOT a way
  # out of a voter chain stuck after a renewal: it relaxes the pin, never
  # revocation, and a renewal revokes the replaced certificate — the renewed
  # voter's re-attestation is (docs/auth.md, "Renewing a voter"). Default false.
  trust_rotated_peer_certs: false
  # Forwarded identity: when true (and the forwarded_identity_v1 capability is
  # active cluster-wide), the owning node re-authenticates a forwarded user's
  # bearer and runs RBAC + audit as the real user instead of the peer=admin
  # trusted-forward. Default false.
  forwarded_identity: false
  # Realm-aware role bindings: when true (and the rbac_realm_v1 capability is
  # active cluster-wide), a bare `user:<name>` grant is rejected pre-latch and
  # resolved to `user:<name>@<realm>` once latched, so this node stops minting
  # inert legacy bare bindings. Default false; the flag is the reversible kill
  # switch. See docs/auth.md.
  rbac_realm: false
  realms:
    - name: corp                          # realm name oidc:corp
      kind: oidc
      oidc:                               # the per-kind keys sit under oidc: / ldap:
        issuer_url: https://idp.corp/realms/main
        client_id: litevirt
        client_secret_file: /etc/litevirt/oidc-secret
        # THIS node's UI callback: a login finishes on the node that began it.
        redirect_url: https://node-1.corp:7445/oidc/callback
        # Loopback address `lv login --realm oidc:corp` listens on (optional;
        # unset = no CLI sign-in). http://127.0.0.1:<port>/<path> only.
        cli_redirect_url: http://127.0.0.1:18765/oidc/callback
        ca_file: /etc/litevirt/idp-ca.pem  # optional: CA the IdP must chain to
        groups_claim: groups               # JWT claim that lists group memberships
    - name: ad
      kind: ldap
      ldap:
        url: ldaps://dc.corp:636
        bind_dn: CN=svc-litevirt,OU=Service,DC=corp,DC=local
        bind_password_file: /etc/litevirt/ad-bind-password
        user_base_dn: OU=Users,DC=corp,DC=local
        group_base_dn: OU=Groups,DC=corp,DC=local

# WebAuthn second-factor enrolment. Empty rp_id disables WebAuthn —
# the gRPC RPCs return Unimplemented and the UI's /account/2fa page
# stays TOTP-only. See docs/auth.md.
webauthn:
  rp_id: litevirt.corp                    # bare host operators reach via the UI
  rp_display_name: "Litevirt Cluster"     # shown in the browser prompt
  rp_origins:
    - https://litevirt.corp

# Backup repositories. Maps a logical repo name (referenced from
# compose `backup.repo:` and `lv backup schedule --repo`) to an
# on-disk path. The snapshot scheduler opens these locally; daemons
# not hosting backup data leave this empty. The /backups UI page
# also reads this map to render the configured-repos overview.
backup_repos:
  main: /srv/backup/main
  offsite: /mnt/dr/offsite

# Backup bandwidth limits, per repo (by logical name), per second: "100MiB",
# "512K" or a byte count; at least 64KiB (0 = none). One limit is shared by every backup job THIS host
# runs into the repo (a scheduled fan-out moves at the repo's rate in total),
# and covers the disk read and, for a remote backup, the chunks sent to the
# repo's host. When this host is the repo's sink for a remote backup, it hands
# its limit to the host that reads the disk. A container replication run is
# paced by the entry on the OWNER (the host the container runs on) under the
# target's repo name, shared with that host's backups into a repo of that
# name; the target host's own entry does not apply to it. A job's own
# `--bwlimit` can only lower it. Absent or 0 = no limit; an invalid value refuses to start the
# daemon. See docs/backups.md#bandwidth-limits.
backup_bwlimits:
  offsite: 100MiB

# Firewall logging (docs/firewall.md, "Logging"). Records of logged rules are tenant flow
# metadata: kept in memory (the newest 10,000) and under <data_dir>/firewall-log/
# (directory 0700, files 0600), never in the journal.
firewall:
  log_group: 27          # the NFLOG group the daemon's log listener reads (0-65535); every
                         # rendered log line sends to it. Raises firewall.log.listener if taken.
  log_max_rate: 200      # records a second this host keeps (0-100000); the rest are counted
                         # (litevirt_firewall_log_records_total{outcome="rate_limited"}) and discarded
  log_retain_mib: 64     # cap on <data_dir>/firewall-log/; 0 keeps records in memory only
  log_retain_days: 7     # records older than this are removed, on disk and in memory, within about
                         # an hour of passing it; 0 = no age bound

# Single-file restore (lv backup file-ls / file-restore). The backup is read
# inside a throwaway restore VM booted from this host's own kernel; every key
# is optional. See docs/design/backup-file-restore.md.
file_restore:
  enabled: true              # false refuses file restore (full restore is unaffected)
  kernel: ""                 # default /boot/vmlinuz-<running release>
  modules_dir: ""            # default /lib/modules/<running release>
  qemu: ""                   # default qemu-system-x86_64 / -aarch64 on PATH, or /usr/libexec/qemu-kvm
  memory_mib: 512            # the restore VM's memory (at least 256)
  run_as: ""                 # restore account whose group reads the boot files; default litevirt-restore
                             # (created at daemon start). qemu runs as a per-session uid (uid_base), not as it.
                             # root, libvirt-qemu, qemu and nobody are refused unless allow_shared_run_as
  idle_timeout_sec: 300      # a browsing session's VM is killed after this long unused
  max_sessions: 2            # restore VMs at once on this host (browsing and extracting)
  max_extractions: 1         # extractions at once on this host; each runs on a VM of its own
  max_extract_bytes: 16G     # per extraction; a request can only lower it
  uid_base: 3800000000       # first of 64 uids reserved for restore VMs, one per session; must belong to no
                             # account (NSS, getent), lie outside /etc/subuid, /etc/subgid and the containers'
                             # idmap range (an explicit uid_base inside that range refuses to load)
  allow_shared_run_as: false # DANGEROUS. true permits run_as to be root or a shared qemu user (libvirt-qemu,
                             # qemu, nobody): the restore VM then shares an identity with production VMs.
  allow_unsandboxed: false   # DANGEROUS. A list of the barriers a restore VM may run without, e.g. [seccomp]:
                             #   seccomp - qemu's seccomp sandbox;
                             #   mac     - mandatory access control: the AppArmor profile (AppArmor on but
                             #             apparmor_parser missing) and Landlock (a host with neither);
                             #   root    - a root daemon (a non-root daemon runs qemu as itself, with its
                             #             data_dir and keys).
                             # true lifts all three. Each removes a barrier between a malicious backup and the
                             # host; while set, the host raises file_restore_unsandboxed. Install a qemu with
                             # seccomp and apparmor_parser, use a kernel with Landlock, run the daemon as root.

# Billing-event webhook. Empty disables (the default — events
# are dropped). When set, `internal/billing` POSTs JSON
# {kind, project, subject, vcpu, mem_mib, disk_gib, …, at} on every
# VM lifecycle transition. Fire-and-log: a slow webhook never blocks
# the caller; 5xx triggers exactly one retry. See docs/tenancy.md.
billing_webhook_url: ""

# Per-VM event store (vm_events) retention, enforced by a daily prune so the
# operational activity history (VM lifecycle + backup outcomes, surfaced on the
# VM detail page and via `lv events <vm>`) stays bounded. Each host prunes only
# its own rows. info/success events are kept retention_days; errors (rarer +
# higher-value, e.g. backup failures) are kept error_retention_days; each VM is
# capped at max_per_vm rows. 0 disables that sweep. Defaults shown.
vm_event_retention_days: 30
vm_event_error_retention_days: 90
vm_event_max_per_vm: 1000
vm_event_prune_hours: 24

# Disk copies a failover set aside (<disk path>.superseded-<time>, see
# migration-failover.md "VM failure policies") are kept while the VM they came
# from exists, whatever its state: only `lv host superseded-disks <host>
# --remove <copy>` removes one then. Once the VM is gone, its copies are
# removed by their host when older than this. 0 keeps every copy until removed
# with `lv host superseded-disks --purge` or `--remove`. The firmware state
# (NVRAM, vTPM) the reconciler moves aside from a leftover domain
# (<data_dir>/fwmig-quarantine/<vm>-reconciled-<unix>/) follows the same rule,
# and is also kept while a firmware move record or an open owed DISCARD names
# the VM.
superseded_disk_retention_days: 7

# Pending OS package updates (docs/upgrades.md, "Pending OS updates"). A
# read-only check of what apt (Debian, Ubuntu) or dnf/yum (RHEL family) says is
# upgradable from its CACHED index and installs nothing. The counts are
# published on the host record (`lv host ls`, `lv host inspect`), as
# litevirt_host_pending_updates{host,kind}, and as a host.updates /
# host.security_updates notification when they change.
host_updates:
  enabled: true            # false stops the check on this host
  interval_minutes: 360    # 0 -> 360; minimum 5
  refresh_index: false     # true runs `apt-get update` / `dnf makecache` first: a network call (and the apt lock), so opt-in

# Resource pressure: this host grades its data directory, its storage pools,
# and the daemon's file descriptors and memory, and reports the grade. It
# reports only. Every key is in "Resource pressure" below.
pressure:
  enabled: true

# Post-upgrade health watchdog. After a self-upgrade re-exec, verify the NEW
# binary's local gRPC becomes pingable within the deadline; if not, roll back to
# the previous binary (.old) and exit so systemd restarts it. Catches a binary
# that starts but is non-functional (the gap systemd's crash-loop rollback
# misses). See docs/upgrades.md.
upgrade_watchdog_enabled: true        # false to disable (also LITEVIRT_UNSAFE_NO_UPGRADE_WATCHDOG=1)
upgrade_health_deadline_sec: 120      # 0 → 120s; widen for very slow N-step schema migrates

# Container host-loss relocation. When a host is fenced, the failover coordinator
# relocates its containers (on_host_failure != none), preferring a faithful
# restore from the latest backup (networking + non-image state) before falling
# back to recreate-from-image. container_restore_timeout_sec bounds how long a
# relocate-restore is treated as in-flight before giving up and image-recreating.
container_restore_timeout_sec: 600    # 0 → 600s (10m)

# vTPM state durability. swtpm writes a vTPM's state without fsync, so a write
# made shortly before a power cut can be lost. On a host with swtpm, the daemon
# sets the sync attribute (chattr +S) on /var/lib/libvirt/swtpm and everything
# under it, at start (before it starts any VM; it waits up to 10 seconds for
# that pass) and every minute, and records that it did in
# <data_dir>/vtpm-state-sync. Files swtpm creates there inherit it. On ext4,
# and on xfs mounted with dirsync or wsync (a mount-time sync implies wsync; a
# remount to sync does not), a vTPM command then returns only once its state
# is on disk. Elsewhere (xfs without one of those,
# btrfs, ZFS, NFS, tmpfs) the
# host raises vtpm_state_not_durable (docs/diagnostics.md). The vTPM capability
# label stays false until a pass has completed. false clears the attribute
# where that record says litevirt set it (an attribute set by hand on a host
# litevirt never protected stays): vTPM commands that write state return
# sooner, and such a write can be lost.
vtpm_state_sync: true

# Container security and limit defaults (docs/containers.md, "Security").
containers:
  # pids.max (cgroup v2) for a container whose config sets none: a new
  # container gets it at create, an EXISTING container at its next start (a
  # running container is never changed under it). 0 sets none.
  default_pids_max: 4096
  # Unprivileged containers' id ranges: idmap_ranges ranges of 65536 host ids
  # starting at idmap_base. Ranges are allocated cluster-wide, so set BOTH the
  # same on every node. The daemon appends root:<base>:<span> to /etc/subuid and
  # /etc/subgid when no root range covers a container's (LXC requires it when
  # the host hands out subordinate ranges): once, under shadow's lock file, and
  # it never rewrites or removes a line (docs/containers.md, "Security").
  idmap_base: 1000000000
  idmap_ranges: 30000
  # How an unprivileged container's rootfs is mapped: auto (an idmapped mount
  # on Linux 5.19+, LXC 5+ and an ext4/xfs/btrfs container store, otherwise
  # its files are shifted into the range at create), on, or off.
  idmapped_rootfs: auto
  # Host paths an ADMIN may pass into a container on THIS host (lv ct create
  # --mount / --device; docs/passthrough.md). A mount's host path is resolved
  # here, symlinks followed, and must land under one of these prefixes; LXC's
  # start hook mounts it from an fd on every start, never by path. A prefix
  # whose path is, lies in or contains a protected tree (/, /etc, /run, the
  # LXC store, litevirt's data and PKI directories, ...) is refused at load;
  # one that reaches a protected tree only through another mount of the same
  # filesystem still loads, with a warning and the condition
  # container_mount_prefix_overlap, and sources in that tree are refused.
  # Devices are listed EXACTLY, one node each (never a directory such as /dev;
  # /dev/mem, /dev/kvm and /dev/vhost-* are refused). Mounts are read-only
  # unless --mount asks for :rw, and always nosuid,nodev. Empty (the default)
  # allows nothing. Allow only trees untrusted users cannot write.
  bind_mount_paths: []                # e.g. ["/srv/shared", "/mnt/media"]
  device_paths: []                    # exact nodes, e.g. ["/dev/ttyUSB0", "/dev/dri/renderD128"]

# ACME for the web UI cert (#13). When set, the daemon TERMINATES UI TLS itself
# (port 7445) using a cert from the configured ACME directory, with the cluster
# certificate as fallback during issuance and for names outside `domains`. A
# custom certificate (`lv host ui-cert set`) takes precedence over both. Unset
# (default) = see ui_tls. directory_url points at internal step-ca or Let's
# Encrypt.
acme:
  directory_url: ""                 # e.g. https://ca.internal/acme/acme/directory  (empty = disabled)
  email: "ops@example.com"
  domains: ["litevirt.example.com"] # SANs to request; must resolve to this host (dns-01: "*.x" allowed)
  cache_dir: ""                     # default {data_dir}/acme
  # http-01 (default): autocert; needs inbound :80 reachable from the CA.
  # dns-01: publishes _acme-challenge TXT records through dns.provider; needs no
  #         inbound port and can issue wildcards. Renewed 30 days before expiry.
  challenge: http-01
  dns:
    provider: rfc2136               # TSIG-signed DNS UPDATE (BIND, Knot, PowerDNS, Windows DNS, ...)
    propagation_timeout_sec: 120    # wait for the record to be visible on the nameserver
    propagation_delay_sec: 0        # extra wait for secondaries that serve the zone too
    rfc2136:
      nameserver: "10.0.0.53"       # primary that accepts updates; host[:port], port default 53
      zone: "example.com"           # every acme.domains entry must be inside it
      tsig_key_name: "litevirt-acme"
      tsig_algorithm: hmac-sha256   # hmac-sha256 | hmac-sha384 | hmac-sha512 | hmac-sha224 | hmac-sha1
      # The TSIG secret (base64, or a BIND key file). A SECRET: it is never put
      # in this file, the daemon tightens the file to 0600 and never logs it.
      # Grant the key update rights for _acme-challenge names only.
      tsig_secret_path: /etc/litevirt/acme-tsig.key
      ttl: 60
      transport: udp                # udp (default) | tcp

# Notifications (#5). Optional shortcut: seed a catch-all webhook target+route
# (min-severity warn) from config without using `lv notify` / the UI. Manage
# additional targets/routes (webhook, Slack, email) via `lv notify` or the /notifications
# page; they are CRDT-replicated cluster-wide.
notifications:
  default_webhook: ""               # e.g. https://hooks.slack.com/services/…  (empty = none)

# Disk SMART health check (smartctl): litevirt_disk_smart_* gauges plus
# disk.smart.* notifications (see notifications.md). Informational only.
smart:
  interval: "1h"                    # Go duration (floor 10m); "0" or "off" disables

# Telemetry: structured logging + distributed tracing over OTLP (see
# telemetry.md). Metrics stay on Prometheus (metrics_port) — this block does NOT
# touch them. Export is OFF until otlp_endpoint is set; with no endpoint the
# daemon logs locally and attaches no otel handler to any gRPC path (zero cost).
# The auth secret for the collector belongs in LITEVIRT_OTEL_HEADERS (env), not
# here. LITEVIRT_* env overrides win over these fields — including for DISABLING:
# clearing otlp_endpoint here does not turn export off while LITEVIRT_OTEL_ENDPOINT
# (or OTEL_EXPORTER_OTLP_ENDPOINT) is still set in the daemon's environment.
telemetry:
  otlp_endpoint: ""                 # OTLP HTTP endpoint URL, e.g. http://otel-collector:4318 (http://|https:// required; empty = export disabled)
  environment: ""                   # service.env label, e.g. "prod"/"homelab"
  # sample_rate: 1.0                # trace sampling 0.0–1.0; unset = library default (100%), 0 = disabled
  log_level: "INFO"                 # TRACE|DEBUG|INFO|WARNING|ERROR|CRITICAL
  log_format: "console"             # json|console|pretty (default console; set json for structured export)

# Peer self-upgrade (auto-catch-up). A lagging daemon pulls a newer *released*
# binary from a healthy peer and re-execs, so a host that was down during a
# cluster upgrade converges on its own. Forward-only + release-only: it never
# downgrades, and never chases a dev / git-describe (`vX.Y.Z-N-gHASH`) build.
# See docs/self-upgrade-from-peer.md.
auto_upgrade:
  from_peer: true                   # default true (unset = on). Set false to PIN this
                                    # node's binary (e.g. hold a test build in place) —
                                    # it then upgrades only via `lv host upgrade`.
  interval_minutes: 5               # how often to check peers for a newer build; 0 → 5

# Image-pull bounds for URL pulls (`lv image pull <url>`). The block_* / blocked_cidrs
# deny policy is an OPT-IN SSRF guard (all default off). See "Image-pull controls".
max_image_bytes: 0                  # hard ceiling per pull/import, bytes; 0 → 64 GiB default
image_pull_timeout_sec: 0           # total wall-clock timeout for a pull; 0 → 30 min default
image_pull_block_metadata: false    # block link-local / cloud-metadata (169.254.0.0/16, IMDS)
image_pull_block_private: false     # block RFC1918 + loopback + CGNAT + ULA + link-local
image_pull_blocked_cidrs: []        # extra explicit CIDRs to block; an invalid CIDR fails startup

# Superseded-row garbage collection — an hourly, local, deterministic sweep that
# hard-deletes provably-inert rows past a retention floor. See "Garbage collection".
tombstone_gc_retention_hours: 0         # provably-inert rows (superseded set / stale LB gen); 0 → 24h
tombstone_gc_orphan_retention_hours: 0  # rows whose owning pointer/config is absent; 0 → 168h (7d)
```

## Minimal config

For a single-host setup, only `host_name` is required:

```yaml
host_name: "host-a"
```

All other fields use sensible defaults.

## Joining a cluster

Every host after the first needs `join_peers` pointing to at least one existing host:

```yaml
host_name: "host-b"
join_peers:
  - "10.0.50.10:7946"
```

Multiple peers can be listed for redundancy. The membership protocol discovers the remaining cluster members automatically, and state replication streams mutations to all peers via gRPC.

## Image-pull controls

URL-based image pulls (`lv image pull <url>`) are bounded by `max_image_bytes`
and `image_pull_timeout_sec`, plus an OPT-IN SSRF network deny policy
(`image_pull_block_metadata` / `image_pull_block_private` / `image_pull_blocked_cidrs`)
— all in the reference above. A pull's RESOLVED destination IP is rejected at
connect time if it falls in a blocked range, checked on every connection, so it is
DNS-rebinding- and redirect-safe. Notes:

- **Opt-in.** With no policy set (the default) pulls are unrestricted and honor
  `HTTP(S)_PROXY`. Recommended on cloud hosts: set `image_pull_block_metadata: true`
  so a hostile image URL can't reach the instance-metadata endpoint.
- **Direct-only when a policy is set.** Enabling any deny policy disables proxy use
  for pulls (a proxied request can't be validated against the post-proxy target);
  connections go direct so the resolved IP is always inspectable.
- **Scope.** The deny policy applies to **URL pulls only**. `lv image import` /
  `push` are streamed over gRPC (no outbound fetch) and are bounded only by
  `max_image_bytes`.
- An invalid CIDR in `image_pull_blocked_cidrs` **fails daemon startup** (a
  configured security policy is never silently dropped).

## Garbage collection

Re-enrolling 2FA recovery codes and recreating load balancers leave behind rows
that can never validate or render again (superseded recovery-code sets, stale LB
backend generations). An hourly per-node sweep hard-deletes them once they age
past a retention floor (`tombstone_gc_retention_hours` /
`tombstone_gc_orphan_retention_hours` in the reference above); the count is exported
as `litevirt_gc_rows_deleted_total` (labeled by `table`).

The same hourly sweep retires admission authority still held by projects that no
longer exist, and expires capacity leases abandoned by a crash between reserve and
release. Both are reported in the journal when they find anything.

The sweep is local-only and deterministic (each node prunes its own copy; it
never touches a current-active-set or current-generation row), so it is safe on a
live cluster.

### Signals the daemon ignores

The daemon deliberately does not terminate on `SIGHUP` or `SIGPIPE`, and does not
treat `SIGHUP` as a config reload. systemd counts death by either as a *clean*
exit, so a `SIGHUP` from `needrestart` or `unattended-upgrades` would leave the
node down with the unit reporting success. Each ignored signal is logged and
counted as `litevirt_signal_ignored_total` (labeled by `signal`) — a rising count
means something on the host keeps trying to bounce the orchestrator, which is
worth chasing even though the daemon survives it.

## VM defaults

Cluster-wide defaults stamped onto a VM at **create** time. They shape new specs
only — nothing here reinterprets a spec that is already stored, so changing one
can never move a running guest's hardware underneath it.

```yaml
vm:
  default_cpu_mode: host-model     # default host-model
```

`default_cpu_mode` is the `cpu_mode` a create writes into a spec that named none:
`host-model` or `host-passthrough`. It is the setting that decides what CPU your
guests actually see.

**Why this has a default at all.** With no CPU mode, litevirt emits no `<cpu>`
element, libvirt passes no `-cpu` to QEMU, and the guest lands on QEMU's x86_64
default: `qemu64`. That model reports no `sse4.1`, no `sse4.2` and no `xsave`, so
it has neither AVX nor AVX2 — on a host that has all three. Guest software built
against a modern baseline then refuses to start, and the failure looks like a
broken binary rather than a hypervisor setting. There is deliberately **no value
here that restores that behavior**.

**Why `host-model` and not `host-passthrough`.** `host-model` resolves, at domain
start, to the closest named model the host supports plus its extra feature flags:
the guest gets the host's modern ISA while staying migratable to any host with an
equal-or-richer CPU. `host-passthrough` exposes the host CPU verbatim — marginally
faster, and the only mode that carries nested virtualization (`vmx`/`svm`) and
every last feature flag — but it pins live migration to effectively identical
hardware, which is at odds with migration, failover and rebalancing. Set it only
on a uniform fleet.

For a deliberately heterogeneous fleet, hold one baseline per VM instead:
`lv run --cpu-mode custom --cpu-model x86-64-v3`. `custom` is not accepted here,
because a cluster-wide default cannot supply the per-VM model it requires.

A VM with an empty `cpu_mode` (one created before this default existed) keeps
it, and the default does not change how it renders. List them with `lv doctor cpu-mode` and move one
forward, while it is stopped, with `lv update <vm> --cpu-mode host-model`.

## Migration

```yaml
migration:
  allow_unencrypted_storage: false   # default false
  network: 10.20.0.0/24              # default empty: the cluster address
  address: 10.20.0.7                 # optional: this host's own address in that network
  allow_any_network: false           # default false: refuse a non-private network, or one holding the cluster address
  live_firmware: true                # default true
```

`allow_unencrypted_storage` decides whether this node may **send** a migration
that copies disks in **plaintext**. That covers `lv migrate --with-storage` and
compose VMs with `migrate.with-storage`. Such a copy is encrypted when both hosts
hold migration-TLS credentials, which `lv host init`, `lv host add` and
`lv host install-migration-tls` issue (see
[migration](migration-failover.md#migration-with-local-disks)). When either host
lacks them, QEMU would send the guest's memory and every copied disk block over
plain TCP, readable by anyone on the network path between the two hosts.

With the default, `false`, that plaintext copy is refused, and the error names
the host without credentials and this setting. Set it to `true` only where the
network between hosts is trusted, for example a dedicated, isolated migration
VLAN. It is read on the source host, and only at daemon start.

`network` is a dedicated migration network, an IPv4 CIDR, like Proxmox's
`migration: network=`. A migration this node sends then moves its data (guest
memory, and the disk blocks of a storage copy) to the target's address inside
that network instead of the address the host is dialed on. Nothing needs setting
on the target: the source asks it, in the request that already prepares the
move, for the address of its own in the network, or `address` if you set one
there (use it where a host holds several addresses in the network). The daemon
refuses to start with a `network` that is not inside a private range or that
contains the host's cluster or default-route address, unless `allow_any_network`
is `true`. The network carries live moves and the disk stream of cold moves and
clone copies, and an unencrypted storage copy stays on the cluster address. See
[migration](migration-failover.md#a-dedicated-migration-network).

Migrations of VMs on shared storage copy no disks, and only their memory moves.
When both hosts hold migration-TLS credentials, that memory stream goes to the
target's address in the network over TLS. When either host has none, it stays
in libvirt's TLS tunnel on the cluster address. A migration that cannot use the
network (this host or the target has no address in it) also stays on the
cluster address, with a `vm.migrate.network_fallback` event on the VM.

`live_firmware` lets this node take part in live moves of vTPM and Secure Boot
VMs. The daemon publishes the host label `litevirt.fw_live_migrate=true` only
when it is on, the host has vTPM and Secure Boot support (`litevirt.tpm` and
`litevirt.secureboot` are `true`), the installed libvirt is at least 10.0.0,
QEMU 8.2.2, swtpm 0.7.3 and libtpms 0.9.3, and `libvirt-guests` does not save or
restore guests (the unit enabled or active with `ON_SHUTDOWN=suspend` or
`ON_BOOT=start`; read from `/etc/default/libvirt-guests`, else `/etc/sysconfig/libvirt-guests`; keys the file does not set, and values that cannot be read as a plain shell assignment, count as unsafe). A version
that cannot be read counts as below the floor. The label is advisory: each
condition is checked again when a move starts. A live move of a vTPM or Secure
Boot VM does not use `network`: its data goes to the target's cluster address
(its memory in libvirt's tunnel), with a `vm.migrate.network_fallback` event
on the VM when `network` is set.

## Memory snapshots

```yaml
memory_snapshot:
  pause_budget: 1s      # default 1s [measure]
  live_deadline: 2m     # default 2m [measure]
```

A memory snapshot (`lv snapshot create --memory`) is captured inside the VM's
running QEMU process with libvirt's external memory snapshot. QEMU is not
restarted: the guest keeps its process, its disk locks and its devices, and is
not paused for a read of its RAM back. Earlier releases saved the guest and
restored it, pausing it for a full write and a full read of its RAM.

A VM with Secure Boot or a vTPM (and any VM whose definition carries UEFI
NVRAM or a TPM) is captured with its vCPUs stopped: litevirt pauses it,
libvirt writes its RAM and switches its disks to their overlays, the firmware
state is captured at that instant, and the guest resumes. The pause is one
write of its RAM.

Any other VM is captured live when it can be. litevirt first measures the
guest's dirty rate, then predicts the precopy QEMU would run: RAM is written
while the guest runs, then what it dirtied meanwhile, until the remainder fits
QEMU's downtime limit. If the predicted final pause is longer than
`pause_budget`, the VM is captured stopped instead, because a precopy that
cannot converge only adds work before the same pause. A live capture that
runs longer than `live_deadline` (the guest got busier than measured) is
finished with the guest suspended, and it resumes when the capture ends.
A guest whose predicted final set fits `pause_budget` but never shrinks below
QEMU's downtime limit is captured live and runs the whole `live_deadline`
before that suspend. When the dirty rate cannot be measured, the daemon logs a
warning and captures live with the deadline capped at twice the predicted
write of the guest's RAM, and at least a second.

A partition pause wins over a capture in flight: the capture is aborted, the
guest is paused, and litevirt never resumes it. If libvirt's job outlives the
pauser's wait, libvirt can resume the guest when the job ends; the capture
re-suspends it and the pause counts as failed (see
[partition pause](design/partition-pause.md#33-the-durable-record)). A pause
made outside litevirt during a capture (`virsh suspend`) is not protected: the
capture, or libvirt, resumes the guest.

Both values are Go durations and must be positive, and `live_deadline` is at
most an hour. The daemon refuses to start with one that is not. They are read
on the host that captures the snapshot, at daemon start, so set them the same
on every host. The defaults are design
targets until they are measured on hardware [measure].

## Capacity and overcommit

How much of a host litevirt is willing to hand to workloads. Cluster-wide
defaults live here; per-host overrides (`lv host config --cpu-overcommit …`) win
where set.

```yaml
capacity:
  cpu_overcommit_ratio: 4.0        # default 4.0
  mem_overcommit_ratio: 1.0        # default 1.0
  host_cpu_reserve: 1              # default 1
  host_memory_reserve_mib: 1024    # default 1024
  host_memory_reserve_pct: 5       # default 5
  vm_memory_overhead_mib: 128      # default 128
  disk_overcommit_ratio: 3.0       # default 3.0
  pool_reserve_pct: 5              # default 5
```

**CPU and memory are deliberately different.** vCPU is time-sliced: running more
vCPUs than cores is normal and the guests simply share, so the default
oversubscribes 4×. Memory is not — without ballooning, KSM or swap a guest's RAM
is either backed or the kernel starts reclaiming — so `mem_overcommit_ratio`
defaults to exactly `1.0`. Raise it only where something makes the promise real.

**The reserve matters more than either ratio.** At ratio 1.0 with no reserve,
guests are offered 100% of RAM and nothing is left for the kernel, page cache,
qemu's per-VM overhead or litevirtd itself — the host thrashes and, in the case
that prompted this, stops answering SSH. The effective memory reserve is the
**larger** of `host_memory_reserve_mib` and `host_memory_reserve_pct`, so the
fixed floor protects small nodes while the percentage scales with large ones.

`vm_memory_overhead_mib` is charged per running VM on top of its configured
memory, covering qemu's own footprint (device models, video, page tables).
Ignoring it under-counts usage, and by more the denser the host.

**Disk is admitted per POOL, not per host.** `hosts.disk_total` is the wrong
denominator for anything shared — a Ceph or NFS pool's capacity has nothing to do
with the host's local disk — while every managed pool carries its own
statfs-sampled total and used. A new disk is charged against its pool's **actual**
free space, less `pool_reserve_pct`, after dividing the declared size by
`disk_overcommit_ratio`.

That ratio defaults above 1 for the opposite reason memory's defaults to exactly
1: thin provisioning is the norm, so a declared 100 GiB qcow2 may occupy 2 GiB,
and charging it in full against real free space would refuse ordinary practice.
Both knobs count what is really taken.

A pool with **no capacity sample** (total 0 — never sampled, or a driver that
reports nothing) is treated as UNKNOWN and skipped, never as full. Refusing on
missing telemetry would break every cluster whose pools have not been sampled yet.

**Containers count too, for memory.** A running container's memory cap is
subtracted from host capacity exactly like a VM's, and `lv ct create` / `lv ct
start` are admitted against it. Container CPU is *not* counted: `--cpu` on a
container is a **cap** in cores — a ceiling the cgroup enforces, not a vCPU
reservation — so it is not added to the host's vCPU total. An **uncapped** container
(`--memory 0`) is not accounted at all: litevirt knows the cap, not the
footprint. Cap your containers if you want them to count.

These apply to **both** placement and admission — VM create (including a pinned
`--host`) and live resize all consult the same numbers, so the scheduler and the
admission check cannot disagree.

Admission runs wherever a host's usage can GROW: VM **create**, **start**, live
**resize**, and a `--restart-if-needed` **reconfigure** that grows the VM. Usage
counts running VMs and those in `starting`, so a stopped VM consumes nothing until it starts — checking
only at create time would be sidestepped by creating VMs that each fit and then
starting them all. A shrink never consumes anything and is never refused.
Automated recovery is deliberately exempt: the failover/reconciler restart paths
are not admitted, because after a host reboot every VM starts at once and
refusing there would strand the ones that lost the race.

To exceed the policy deliberately for one VM, pass `--allow-overcommit` to
`lv run` or `lv start`; the host check is skipped (project quota still applies)
and the bypass is audited.

## Resource pressure

Each host samples its own resources every `sample_interval_sec` and grades each
one `ok`, `warn`, `degrade` or `critical`. The host's level is the worst of
them. The thresholds are per host, because each host reads its own
`config.yaml`, and per pool through `pool_overrides`.

| Resource | Graded by |
|---|---|
| `data_dir.space`, `pool.<name>.space` | Bytes free to the daemon (`f_bavail`), as a percentage and against a MiB floor. A level is entered when either one is crossed. |
| `data_dir.inodes`, `pool.<name>.inodes` | Free inodes, as a percentage. Skipped on a filesystem without an inode count (btrfs). |
| `fds.daemon` | Open descriptors as a percentage of the soft `RLIMIT_NOFILE`. |
| `memory.daemon` | The Go runtime's mapped memory, less what it returned to the kernel, as a percentage of `daemon_limit_mib`. |

Pools are the file-based pools of this host (`local`, `dir`, `nfs`, `btrfs`),
from config and from pools made with `lv pool create`. A pool on the data directory's
filesystem is graded under both names. A statfs that gets no answer (a hung
NFS mount), or a descriptor or memory count that cannot be read, is recorded
as the resource's error, and the resource keeps its last level. The pool list
is read off the sampling path: a read that does not return within 2 seconds is
abandoned, and the last list is graded.

A report is **stale** when the pool list read is overdue, or when no sample
has completed for more than three sample intervals. Its levels are then the
last ones known.

```yaml
pressure:
  enabled: true              # false: sample and report nothing; peers see this host's pressure as unknown
  sample_interval_sec: 5
  enter_samples: 2           # consecutive samples past a threshold to enter its level
  clear_margin_pct: 2        # points better than a threshold to count toward leaving it (a MiB floor: 25 % of the floor)
  clear_after_sec: 120       # every sample past the margin for this long before a level is left
  trend_window_sec: 900      # window of the time-to-full projection (minimum 60)
  data_dir:                  # 0 turns a threshold off
    warn_free_pct: 15
    degrade_free_pct: 8
    critical_free_pct: 3
    warn_free_mib: 4096
    degrade_free_mib: 2048
    critical_free_mib: 512
    warn_free_inodes_pct: 10
    degrade_free_inodes_pct: 5
    critical_free_inodes_pct: 1
  pools:                     # the same keys and defaults as data_dir, for every pool
    warn_free_pct: 15
  pool_overrides:            # per pool name; a key left out keeps the pools: value
    fast-nvme:
      warn_free_pct: 25
      degrade_free_pct: 15
  memory:
    daemon_limit_mib: 0      # 0 = auto: 10 % of RAM, at least 1 GiB and at most 4 GiB
    warn_pct: 60             # percentage IN USE
    degrade_pct: 75
    critical_pct: 90
  fds:
    warn_pct: 70             # percentage of the descriptor limit IN USE
    degrade_pct: 85
    critical_pct: 95
```

The daemon refuses to start if a worse level's threshold is looser than a
milder one's, for example `degrade_free_pct` above `warn_free_pct`. A
threshold that is off (0) is not checked against the others.

**Where it shows.**

- The readiness probe. `Ready` carries the level, the pressured resources
  and the time to full. Each peer keeps the latest answer from every host.
  Pressure never makes a host unready, so a pressured host keeps its vote. A
  host on an older build, or with `enabled: false`, answers without the field,
  and its pressure is unknown, never ok.
- The `host.pressure` condition in `lv health`. The failover lease holder
  writes it for every host from that host's latest probe answer, so a host
  that cannot write is still described. It is a warning, or critical at
  `critical`, and it resolves when the host is back to `ok`. See
  [diagnostics](diagnostics.md#resource-pressure-hostpressure).
- `lv host inspect <host>`. `pressure` holds the level, the pressured resources,
  `since`, `time_to_full_sec`, `sampled_at`, `stale` and each resource's free
  and total.
  `pressure_observed_at` is when the probe that carried it was sent.
- Metrics: `litevirt_host_pressure_level`, `litevirt_host_free_bytes`,
  `litevirt_host_time_to_full_seconds`,
  `litevirt_host_pressure_last_sample_timestamp_seconds` and
  `litevirt_host_pressure_stale` ([telemetry](telemetry.md#resource-pressure-metrics)).

This release only reports pressure. Nothing is refused, paused or shed
because of it.

## Metrics endpoint exposure

`/metrics` on `metrics_port` has **no TLS and no authentication**, and
`metrics_bind` defaults to **all interfaces**. Anyone who can reach the port
reads, without a credential:

- every VM and container name on this host, with CPU and memory allocations,
  and for VMs live disk and network I/O counters (per-VM traffic volume)
- host names, capacity and `litevirt_host_pressure{host,dim}` for **every host
  in the cluster**, not only this one, plus every peer name via
  `litevirt_peer_healthy`, `litevirt_cluster_clock_skew_seconds` and
  `litevirt_replication_peer_pending_entries`
- `litevirt_vm_snapshot_chain_depth{vm}`, which carries VM names from other hosts
- `litevirt_enforcement_config_enabled{feature}` and
  `litevirt_enforcement_latched{feature}` — which hardening kill-switches are
  set on this node and which capability tokens have latched
- `litevirt_auth_bearerless_client_admin_total`, whose own help text describes
  it as the population strict mTLS would deny, plus
  `litevirt_audit_chain_findings{kind}` and `litevirt_ha_degraded{reason}`
- `go_info{version}` and `process_*` from the default registry — the exact Go
  toolchain version, i.e. which runtime CVEs apply

The enforcement gauges are worth naming separately: read together they say which
hardening features are **not** in force here, which is what an attacker choosing
an approach would want. No API path hands that out without a credential — today
the gRPC API carries no enforcement posture on any RPC. So this endpoint is a
weaker gate than the API for **posture**, not only for the inventory described
below: it is the only place the kill-switch readout is published at all, and it
is published to anyone who can reach the port.

The inventory is a different gate, and how much weaker this endpoint is depends
on one flag:

- with `auth.strict_mtls_identity` **off** (the default), a bearerless
  CA-signed client certificate is treated as admin, so the API inventory is
  gated by a credential distributed to every operator — roughly what
  `/metrics` gives away for free
- with the flag **on** *and* `strict_mtls_identity_v1` latched cluster-wide —
  enforcement is `flag && latch`, like the rest of the family, so setting the
  flag alone changes nothing until the token latches — that same certificate is
  refused without a session (`run lv login`). The API inventory then needs a
  real identity while `/metrics` still needs nothing. **Enforcing strict mTLS
  widens this gap rather than closing it** — the metrics endpoint becomes the
  weakest path to the inventory, and `metrics_bind` is the only thing narrowing
  it. During the flag-on-but-not-yet-latched window the first case still
  applies, and `litevirt_auth_bearerless_client_admin_total` counts the
  requests that would be denied once it latches

`/api/v1/status` is served on the same port and is also unauthenticated (and
method-unrestricted). The same path on `rest_port` requires a bearer token.
Fronting only `/metrics` with a proxy or a path ACL leaves it open.

That default is reasonable on a trusted management network and poor anywhere
else, and the daemon cannot tell which it is on — so it logs a warning at
startup when the bind reaches every interface, and a differently-worded one when
it is a **public** address, which is almost never deliberate for an endpoint
with no authentication. It is left as the default because changing it would
silently break every deployment scraping from a remote Prometheus, the way any
listener change does.

**Silence is not a safety claim.** No warning means the bind is neither a
wildcard nor obviously public — a loopback, RFC1918, CGNAT/tailnet or link-local
address, or a hostname, which is deliberately not resolved (resolution at startup
can block and can disagree with what the listener does). Whether the networks
that can reach it are trusted is not something the daemon can know.

Restrict it by binding one interface — pick **one** of these:

```yaml
metrics_bind: "127.0.0.1"
```

```yaml
metrics_bind: "10.13.200.5"
```

The first scrapes via a local exporter or an SSH tunnel; the second exposes it on
a management network only. Both IPv6 wildcard spellings also work — `"::"` and
`"[::]"`.

`metrics_port: 0` disables the endpoint entirely.

A host firewall achieves the same thing without a config change, but litevirt
ships no host-firewall guidance and `metrics_bind` is the supported route. Note
that [firewall.md](firewall.md) is about the **guest** firewall — per-NIC
security groups for VM traffic — and does nothing to the daemon's own listeners.

`ui_port` already defaults to localhost and this does not, which is a historical
difference rather than a judgement that this endpoint carries less.

## Ports summary

| Setting | Default | Protocol | Purpose |
|---------|---------|----------|---------|
| Setting | Default | Protocol | Authenticated? | Default bind | Purpose |
|---------|---------|----------|----------------|--------------|---------|
| `grpc_port` | 7443 | gRPC/mTLS | yes — mTLS, client cert required | all | API (CLI, inter-host) |
| `metrics_port` | 7444 | HTTP | **no** | **all** | Prometheus `/metrics` — see above |
| `ui_port` | 7445 | HTTP, or HTTPS per `ui_tls` | session cookie | `127.0.0.1` | Web dashboard |
| `rest_port` | 7446 | HTTP | bearer token | `127.0.0.1` | REST API gateway |
| `gossip_port` | 7946 | TCP+UDP | only with `enforcement.gossip_encryption: true` — AES-256-GCM under `gossip.key` ([details](auth.md#gossip-encryption)); members are also admitted only if they are in the `hosts` table ([details](operating-model.md#gossip-admits-only-known-hosts-and-is-authenticated-only-when-encrypted)) | **all** | Cluster membership |
| `dns_port` | 5354 | UDP | **no** | **all** | VM name DNS |

Three of these are unauthenticated, not one (two once `enforcement.gossip_encryption` is `true` on every host). `rest_port` and `ui_port` are
protected by *binding to loopback* rather than by their credential, which is the
same mechanism `metrics_bind` offers and the reason the bind column is here.
Restricting `gossip_port` and `dns_port` is out of scope for this setting — they
are listed so this table is not read as a claim that only `/metrics` is open.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `LITEVIRT_CONFIG` | Override config file path |
| `LV_CONFIG_DIR` | CLI: override the per-user config directory (default `~/.config/litevirt`; holds the CLI cert and stored login credential) |
| `LV_HOST` | CLI: default remote gRPC/mTLS target (`host` or `host:port`; a legacy `user@host` prefix is ignored) |
| `LV_TOKEN` | CLI: bearer token to authenticate gRPC calls. Overrides the credential stored by `lv login`. |
| `LITEVIRT_UNSAFE_NO_KILLMODE_CHECK` | Skip startup `KillMode=process` self-check (development / non-systemd hosts only). Default check protects against unit-file regressions that would kill child QEMU processes on daemon stop. |
| `LITEVIRT_UNSAFE_SKIP_ROLLBACK_CHECK` | Skip the startup capability-rollback self-check. That check looks for durable activation markers naming tokens this binary has never heard of — proof a newer binary ran here — and puts the node under WAL quarantine: it stays up and reachable but emits no replicated writes and advertises no capabilities, so peers see it degraded and nothing new latches across it. Since `release_2026_11_v1`, a release token's marker carries `rollback: safe_if_unused`, and the check does not quarantine on it while none of its features is recorded as used; the node starts in release probation instead, on every boot below that marker, emitting and applying no replicated state until a voter majority confirms no use (see upgrades.md, *Rolling back after a release token latched*). Set this only after reseeding the node's state, or to start a rolled-back binary deliberately. |
| `LITEVIRT_OTEL_ENDPOINT` | Telemetry: OTLP endpoint; turns logs+traces export on. Overrides `telemetry.otlp_endpoint`. |
| `LITEVIRT_OTEL_HEADERS` | Telemetry: OTLP headers, e.g. `Authorization=Basic <b64>` (collector auth — keep in env, not the config file). |
| `LITEVIRT_LOG_LEVEL` | Telemetry: log level `TRACE`\|`DEBUG`\|`INFO`\|`WARNING`\|`ERROR`\|`CRITICAL`. |
| `LITEVIRT_LOG_FORMAT` | Telemetry: log format `json`\|`console`\|`pretty`. |
| `LITEVIRT_TELEMETRY_ENV` / `LITEVIRT_TELEMETRY_SERVICE` / `LITEVIRT_TELEMETRY_VERSION` | Telemetry: `service.env` / `service.name` / `service.version` labels. |
| `LITEVIRT_TRACES_SAMPLE_RATE` | Telemetry: trace sample rate `0.0`–`1.0`. |
| `LITEVIRT_OTEL_TIMEOUT` / `LITEVIRT_OTEL_RETRIES` / `LITEVIRT_OTEL_BACKOFF` | Telemetry exporter resilience (seconds / count / seconds): bound the OTLP export calls so a slow collector can't stall the daemon. Fan out to logs + traces. Off by default. |
| `LITEVIRT_OTEL_FAIL_OPEN` | Telemetry: drop on export failure instead of blocking (`true`/`false`). Fans out to logs + traces. |
| `LITEVIRT_OTEL_SHUTDOWN_TIMEOUT` | Telemetry: drain cap (seconds) on daemon stop; logs signal only. |

See [telemetry.md](telemetry.md) for the full telemetry setup and an OpenObserve quick start.
