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
| `replication.failed` | error | a scheduled replication run fails |
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
| `quota.exceeded` | warn | a CreateVM is rejected by a project quota |
| `disk.smart.failing` | error | a disk on this host fails its SMART overall-health self-assessment (subject `host:/dev/sdX`) |
| `disk.smart.warning` | warn | a disk passes SMART but reports a non-failure warning (NVMe temperature above its threshold: check cooling) |
| `disk.smart.prefail` | warn | a disk still passes SMART but a prefailure attribute has tripped or the NVMe critical-warning flag is set |
| `disk.smart.recovered` | info | a disk that was prefail/failing reports healthy again |
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
> leadership changes and daemon restarts, and the same rows drive admission refusals
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

**Rolling upgrade.** Creating an email target *with a password* is refused until the
mandatory, replication-gated `email_target_secret_v1` token has latched, i.e. every
host runs a build that masks the password on read; the refusal says to finish the
upgrade first. A passwordless email target (an open relay or IP-allowlisted relay) can
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
