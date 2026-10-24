# Notifications

litevirt emits operator notifications for noteworthy cluster events to
configurable targets. It mirrors `internal/billing` in spirit — fire-and-log
delivery that never blocks or fails the operation that triggered it — but fans
out to multiple typed targets selected by **routes** (event-pattern + minimum
severity). The implementation is `internal/notify`; targets/routes are stored in
the `notification_targets` / `notification_routes` tables and replicated to
peers. Because their config can carry webhook tokens/URLs, they are excluded
from the operator-readable `GetStateDump` path, but daemon
peers repair missed pushes through a peer-mTLS-only sensitive anti-entropy lane.

## Model

- **Target** — a delivery destination. Types today: `webhook` (generic JSON
  POST of the notification) and `slack` (Slack incoming-webhook message with a
  severity emoji). Config is `{"url": "…"}`. `email` sends a plain-text email
  over SMTP (see *Email targets* below).
- **Route** — sends events whose **kind** matches an event-pattern glob and whose
  **severity** is at least `min_severity` to a target. A target receives nothing
  until a route points at it.

A notification has a `kind` (verb.noun), `severity` (`info` | `warn` | `error`),
`subject` (the resource), and `detail`.

## Events emitted

| Kind | Severity | When |
|---|---|---|
| `backup.failed` | error | a `lv backup snapshot` / scheduled backup fails |
| `host.fenced` | error / warn | the failover coordinator fences a host (warn = partial/manual) |
| `host.recovery.stalled` | error | a `fenced`/`offline` host's recoverable workloads are still on it 60 s after its fence record, or a host the quorum reports down has been held unfenced for 60 s by an HA hold (disarmed, a live voter's veto, too few voters counted live, or an unreadable policy), the reason naming which; names the host, the leader coordinator and why it is not proceeding. Repeats at most every 10 minutes per host |
| `watchdog.db_probe_failing` | warn | the watchdog liveness gate's state-store round trips have kept failing for a third of `watchdog.liveness_stale_sec`; the detail names the last error, how long probes have failed and how long until the host self-fences if they continue. Repeated at most every quarter of the threshold while it lasts. Delivery reads its routes from the same state store, so it may not arrive; the daemon log always carries it |
| `watchdog.db_probe_recovered` | info | a round trip succeeded again after `watchdog.db_probe_failing` |
| `replication.failed` | error (warn when the target host is down) | a scheduled replication run starts failing or fails differently; a continuing failure is repeated at most hourly |
| `replication.recovered` | info | a replication schedule that was failing replicates again |
| `replication.skipped` | warn | a host has skipped a VM's replication runs for 15 minutes because it may not act as the VM's owner (still fenced, warming up, not an active member, or its view is behind); repeated at most hourly while it lasts (docs/backups.md) |
| `replication.suspended` | warn | a replication schedule targets the host its workload now runs on, and the move's switch did not arrive within 15 minutes: it does not replicate there; or the VM is stopped on a witness, awaiting its move to a worker |
| `replication.replica_set_aside` | warn | a container replica was set aside, not removed: it is not proven to be contained in the data now replicated (`lv replication replicas`) |
| `replication.reversed` | info | a replicated VM or container moved onto its replica host and its schedule now replicates back to the host it left (docs/backups.md, "Reverse replication") |
| `replication.reverse_skipped` | warn | the same move, but the host it left could not be made the target; the workload is replicating onto its own host until the schedule is replaced |
| `host.security_updates` | warn | a host has pending OS security updates (docs/upgrades.md, "Pending OS updates"); sent when the counts change |
| `host.updates` | info | a host has pending OS package updates, none of them security |
| `auth.first_factor_enrolled` | warn | an account enrolled its first second factor from an enrollment-only session (mandatory second-factor policy); if it was not the account's owner, remove the factor and reset the password |
| `ha.vip.no_holder` | error | a configured VIP is served by nobody (VIP HA enabled) — a VIP outage |
| `ha.vip.demotion_unfenced` | error | a minority node's VIP self-demote failed with no verified self-fence; the majority holds in the safe gap (VIP outage until an operator provides a fence / intervenes) |
| `ha.dualrun.vm` | error | a VM is an active disk-holder on more than one host — a split-brain that can corrupt the disk |
| `ha.dualrun.ct` | error | a container is running on more than one host |
| `ha.dualrun.vip` | error | a VIP is kernel-assigned on more than one host — a dual VIP holder |
| `ha.owner.mismatch` | error | a VM's DB owner is not its sole runtime holder — the DB and runtime disagree (ownership drift) |
| `ha.owner.epoch_mismatch` | error | under a latched `owner_epoch_v1`, the DB owner's runtime carries an owner-epoch marker that is missing/corrupt/unreadable or unequal to the row's epoch — the runtime cannot prove it belongs to the current ownership generation |
| `ha.owner.epoch_suppressed` | error | under a latched `owner_epoch_v1`, a DB row is telling the owner-epoch check not to examine a VM while the runtime says that VM is running — a tombstoned row with a live disk-holder, a migration state parked well past its cutover window, or a `host_name` naming a host that is not in the cluster and so can never be probed |
| `ha.lww.unresolved` | warn | a node is tracking unresolved equal-timestamp LWW ties |
| `ha.dualrun.coverage` | warn | a workload-capable host could not be fully probed this pass — unreachable (segmented/down) OR returned a partial runtime (a local libvirt/container/ip probe errored, so its workload absence is unreliable); split-brain can't be ruled out there |
| `storage.lun_shared` | warn / error / info | more than one disk is one iSCSI LUN (an older build allowed it): warn when first observed, error once confirmed on a second scan, info when resolved. The detail names the VMs and disks — see `shared_lun` in [diagnostics.md](diagnostics.md#shared-iscsi-lun-shared_lun) |
| `quota.exceeded` | warn | a CreateVM is rejected by a project quota |
| `ct.rootfs.stranded` | warn | a container relocated off a failed host left its own rootfs there (nothing removes it); the detail names the container and the host |
| `vm.disk.stranded` | warn | a failover restarted a VM elsewhere and left its host-local disk on the failed host, a host set such a disk (or an old copy a failover found) aside, or failover held a `restart-same` VM with a host-local disk on its failed host to wait for it; the detail names the VM, the host and the path. See [migration-failover.md](migration-failover.md#the-real-disk-a-restart-leaves-behind) |
| `certificate.expiring` | warn / error | a certificate this node serves (`host`: its cluster mTLS identity; `ui`: a custom web UI certificate) expires within 30 days (error within 7); repeated daily. Subject is `<host>/<cert>`; the detail names the renew command. See [auth.md](auth.md#renewing-a-host-certificate-lv-host-renew-cert) |
| `certificate.expired` | error | that certificate is past its NotAfter |
| `certificate.revocation_owed` | warn | a renewal's replaced certificate is not revoked yet: a node that does not pin (an older build, or `auth.trust_rotated_peer_certs` on) still needs its signature in the newest voter generation; repeated daily until the cluster publishes the revocation itself. See [auth.md](auth.md#renewing-a-host-certificate-lv-host-renew-cert) |
| `certificate.revoked` | info | an owed revocation was published |
| `certificate.revocation_owed_tampered` | error | an owed revocation's row was marked done or its CRL replaced although the serial was never revoked; restored to owed where possible. See [auth.md](auth.md#renewing-a-host-certificate-lv-host-renew-cert) |
| `disk.smart.failing` | error | a disk on this host fails its SMART overall-health self-assessment (subject `host:/dev/sdX`) |
| `disk.smart.warning` | warn | a disk passes SMART but reports a non-failure warning (NVMe temperature above its threshold: check cooling) |
| `disk.smart.prefail` | warn | a disk still passes SMART but a prefailure attribute has tripped or the NVMe critical-warning flag is set |
| `disk.smart.recovered` | info | a disk that was prefail/failing reports healthy again |
| `image.versions_kept` | warn | a refresh's background prune kept unused versions of an image only because the image store is on a filesystem other hosts may share (nfs, cifs, ceph, fuse, ...), whose disks may be built on them; names the count and bytes. At most daily per image. Subject is `<host>:<image>`; `lv image prune <image> --version <file> --host <host>` removes one once no host uses it |
| `test.notification` | info | `lv notify test` / the UI "Test" button |

> **Route the `ha.vip.*` kinds if you enable VIP HA** (`enforcement.vip_self_demote` /
> `enforcement.vip_proof_reclaim`). VIP Phase-2 deliberately converts a partition
> overlap into a VIP *outage* rather than a dual-VIP — that is only a safe trade if the
> outage pages. Add a route matching `ha.vip.*` (or `ha.*`) at `error` severity, or a
> silent VIP gap can go unnoticed. Recovery is `lv host fence-confirm <host>`.

> **`ha.owner.epoch_suppressed` is the suppression itself, not the mismatch.** The
> owner-epoch check branches entirely on replicated LWW state, so any peer with SQL
> could once switch it off for a VM with a SINGLE write and nothing to renew — a
> tombstone (which `ListVMs` filters out), a migration state (which is exempted as
> cutover lag), or a `host_name` pointing at a host that is never probed (which defers
> to the coverage signal). Each is now corroborated against runtime evidence the leader
> gathered itself, and a row that says "do not look" while the workload is visibly
> running pages under this kind. A row saying the same thing with nothing running behind
> it is an ordinary stale row and stays silent. This narrows the trust boundary; it does
> not close it — the detector still judges replicated state using replicated state.

> **The `ha.dualrun.*` / `ha.owner.mismatch` / `ha.lww.unresolved` kinds are alert-only**
> and always on — the leader-gated dual-run detector never destroys or reconciles; it
> turns a silent split-brain (the same workload/VIP live on two hosts, or a DB owner that
> disagrees with the runtime) into a page so an operator can act. Findings are DURABLE
> health conditions (schema v50): the first positive scan emits the kind at `warn`
> (lifecycle *observed*), the second consecutive scan CONFIRMS and pages at the kind's
> listed severity, and the condition resolves — emitting the kind once at `info` — only
> after two consecutive clean scans with complete coverage of every host that could hold
> the condition's subject (a host that has been down since before a VM was created does
> not hold that VM's condition open — see *Cluster health* in docs/diagnostics.md). Conditions survive detector
> leadership changes and daemon restarts. A node that has lost the voter majority may not
> hold the detector's lease, so it scans what it can reach without it: such a scan records
> and confirms its own findings, but resolves nothing and raises no `ha.dualrun.coverage`
> (coverage is the leader's to report). The same rows drive admission refusals
> (`lv health` shows exactly what admission enforces). Route `ha.dualrun.*` at `error` (or
> `ha.*` broadly). Expect standing `ha.dualrun.coverage` alerts for any host that is
> genuinely down or network-segmented from the current leader — that is a real coverage
> gap, deduped to one page; do not mute the kind or a true split-brain on that host goes
> unseen. A host on an *older binary* (no `GetRuntimeInventory` handler) during a rolling
> upgrade is deliberately **not** paged as a coverage gap — it still appears in the
> `litevirt_dual_run_probe_failed{host}` gauge, but the transient version skew of an
> upgrade window does not raise a page. The gauges
> `litevirt_dual_run_detected{kind,target}` and `litevirt_dual_run_probe_failed{host}`
> carry the same signal for dashboards.

Event-pattern globs: `*` (all), `backup.*` (a prefix), or an exact kind like
`host.fenced`.

## Configure

CLI (`lv notify`):

```bash
lv notify target add --name ops-slack --type slack --url https://hooks.slack.com/services/…
lv notify target ls
lv notify route add --pattern "*" --target <target-id> --min-severity warn
lv notify route add --pattern "backup.*" --target <target-id> --min-severity error
lv notify test <target-id>
lv notify route ls
lv notify route rm <id>
lv notify target rm <id>
```

UI: the **Notifications** page (Observability nav) manages targets + routes and
has a per-target **Test** button.

Config shortcut: set `notifications.default_webhook` to seed a catch-all webhook
target + route (min-severity `warn`) without the CLI/UI — see
[configuration.md](configuration.md).

Slack: paste an [incoming-webhook](https://api.slack.com/messaging/webhooks) URL
as a `slack` target. Slack channels render the severity emoji + cluster +
kind/subject at a glance.

## Email targets

An `email` target delivers each notification as a plain-text email over SMTP.
Event routing is identical to the other types: a route (pattern + minimum
severity) points at the target.

```bash
printf '%s' "$SMTP_PASSWORD" > /root/smtp.pw && chmod 600 /root/smtp.pw
lv notify target add --name ops-mail --type email \
    --smtp-host smtp.example.com --smtp-user lv@example.com \
    --smtp-password-file /root/smtp.pw \
    --from litevirt@example.com --to ops@example.com --to oncall@example.com
lv notify route add --pattern "*" --target <target-id> --min-severity warn
lv notify test <target-id>        # sends a real test email, like Proxmox's "Test"
```

| Flag | Meaning |
|---|---|
| `--smtp-host` / `--smtp-port` | relay; port defaults to 587 (`starttls`), 465 (`implicit`) or 25 (`none`) |
| `--smtp-tls` | `starttls` (default: the relay MUST offer STARTTLS or nothing is sent), `implicit` (TLS from connect) or `none` |
| `--smtp-tls-skip-verify` | do not verify the relay's certificate. **Certificate verification is on by default**; this is for a self-signed lab relay |
| `--smtp-user` / `--smtp-password-file` | AUTH PLAIN credentials; the password comes from a file (or `-` for stdin), never a flag, so it stays out of shell history and `ps` |
| `--from` / `--to` | sender and recipients (`--to` repeats) |

Credentials are never sent before TLS is established, and a target with a
username and `--smtp-tls none` is refused unless the relay is loopback. The
SMTP password is stored in the target's config, in the same replicated,
sensitive `notification_targets` table that holds webhook URLs; every list
response (`lv notify target ls`, the API, the UI) masks it for every role, and
it is never logged, and `CreateNotificationTarget` masks it in its own response too.
An unknown key in the email config is refused by name. The config is stored canonically (re-encoded from the validated struct, lowercase keys
only) so a differently-cased `Password` key cannot dodge the masking. To change the
password, delete and re-add the target.

**Rolling upgrade.** Creating an email target *with a password* is the
`email_target_secret` feature of the release token `release_2026_11_v1`: it is refused
(`the cluster upgrade must finish first (email_target_secret needs release_2026_11_v1)`)
until every host runs a build that masks the password on read and the token has latched;
the first create after the latch is recorded as the feature's use. See `lv cluster
upgrade-status`. A passwordless email target (an open relay or IP-allowlisted relay) can
be created at any time. Hosts still on an older build do not know the `email` type: they
log `notify: bad target config` and send **no email** for events they handle, so email
coverage has gaps (and a warning per event in those hosts' logs) until the rollout
completes. Create email targets after the upgrade. Subjects are
`[cluster] severity: kind subject`, with newlines stripped so a hostile VM name
cannot inject headers. Each email also carries cluster, kind, severity, subject
and detail in the body.

A host on an older binary that receives an `email` target treats it as an
unknown type, logs a warning and skips it; the other targets keep working.

## Disk SMART alerts

Every host checks its own disks with `smartctl` (from smartmontools) on
`smart.interval` (default `1h`; `0` or `off` disables; values under `10m` are
clamped to `10m` with a warning, since smartctl runs once per disk per pass) and:

- exposes `litevirt_disk_smart_status{device,model,status}` (1 for the disk's
  current status: `ok`, `warning`, `prefail`, `failing` or `unknown`; the series set
  is swapped atomically each pass) and
  `litevirt_disk_smart_available` (0 when `smartctl` is not installed) on that
  host's Prometheus endpoint;
- notifies `disk.smart.failing` (error) or `disk.smart.prefail` (warn) when a
  disk enters or worsens into that state, and `disk.smart.recovered` (info) when
  it clears. A standing failure is paged once per daemon run, not every pass; a
  daemon restart pages it again.

smartctl runs with `-n standby`, so a spun-down disk is not woken (it reports
`unknown` for that pass and keeps its last state). Disk state is keyed by serial
number (WWN as a fallback, device name last), so a device renamed across a reboot
neither re-pages nor strands a standing failure; a disk that is physically removed
simply drops out. An NVMe critical warning of only the temperature bit is
`warning`; any other bit is `prefail`.

An `unknown` read (a smartctl hiccup, or a disk asleep under `-n standby`, whose
output carries no serial) keeps the disk's tracked identity and last state: a
standing failure neither re-pages nor is lost, and a disk that recovered while
unknown emits `disk.smart.recovered` when it next reads healthy. `recovered`
means the same physical disk: a disk that is removed stops being tracked and
never emits it, and a replacement at the same device name is a new disk (a bad
one pages; a healthy one is silent).

A host without `smartctl`, a virtual disk with no SMART support, or output that
cannot be parsed reports `unknown`: it neither pages nor clears a standing
failure. The check is informational only. It never fences a host, drains it or
blocks a workload.
