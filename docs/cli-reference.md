# CLI Reference

The CLI and daemon are one binary, `litevirt`. `lv` is a convenience symlink, so
`lv <cmd>` and `litevirt <cmd>` are identical — this reference uses `lv`. (The
server runs as `litevirt daemon`; see [Installation](installation.md).)

The `lv` CLI connects to any cluster host via SSH tunnel. Set the target with `LV_HOST`:

```bash
export LV_HOST=root@10.0.50.10
```

Every subcommand also accepts `lv <cmd> --help` for full flag detail; this
reference is a discovery map, not an exhaustive spec.

## Authentication

```bash
lv login                               # Log in with username and password
lv login --realm oidc:<name>           # Sign in through an OIDC realm (browser + loopback redirect; --no-browser prints the URL)
lv logout                              # Log out and remove stored credentials
lv whoami                              # Show current authenticated identity
lv session ls [--user <name>]          # List active sessions (admin: any user)
lv session revoke <session-id>         # Revoke a session immediately (the ID ls shows, or any unambiguous prefix of 8+ chars)
```

`lv session ls` shows a 12-character handle for each session (`*` marks your
current one); the full id is the session's bearer secret and the daemon never
returns it. `lv session revoke`
takes that short form: a prefix resolves only among the sessions you may revoke
(your own; an admin's, anyone's), and one that matches more than one is refused
with the matches listed.

## Two-factor authentication

```bash
lv 2fa enroll-totp --label <name>          # Enroll TOTP; prints otpauth URL + recovery codes
lv 2fa disable --method totp --label <l>   # Drop a single factor
lv 2fa ls [--user <name>]                  # List enrolled factors
lv 2fa policy                              # Show the mandatory second-factor policy
lv 2fa policy off|all|<realm>[,<realm>...] # Set it (admin); ends sessions in newly covered realms
  [--allow-self-enroll --enroll-by <RFC3339>] # let a first factor be enrolled without a code until then
lv 2fa enroll-code <username> [--ttl 1h]   # Admin: single-use first-enrollment code (max 24h), usable only through the node it names
lv 2fa enroll-totp --code <code>           # Enroll a first factor from an enrollment-only session
```

Under a policy that covers their realm, a login that presents no factor gets
an enrollment-only session: if the account has no factor yet it can enroll one
for itself (with an admin-issued code, unless self-enrollment is open) and
nothing else, and the enrollment ends it. See `docs/auth.md`,
"Mandatory second factor".

WebAuthn enrollment is browser-only; use the `/account/2fa` page.

## Cluster

```bash
lv status                          # Cluster overview (JSON)
lv events [--type <filter>]        # Stream cluster events live
lv events <vm> [--limit N] [--since <time>]   # One VM's activity history (lifecycle + backup outcomes)
lv top [--interval 3s]             # Live resource dashboard
lv ui [--open]                     # Show web UI URL
lv mcp [--max-list-items N] [--allow-write]  # Run the stdio MCP server for operator assistants
lv version                         # Print version
lv cluster digest                  # Per-table state digest for every host (fanned out server-side)
lv cluster converge [--all]        # Kick an immediate anti-entropy pass + report cross-host convergence
                                   #   (`lv cluster sync` is a deprecated alias)
lv cluster failover-scope [cluster|region]  # Show or set whether failover quorum is cluster-wide or
                                   #   per region (see federation.md → Regions and failure)
lv cluster vrrp-transport [unicast|multicast]  # Show or set how load balancer hosts exchange VRRP,
                                   #   cluster-wide (admin to set; see compose.md → Load balancer)
lv cluster relay-restore            # List relay-health demotions and operator holds (since, until, reason)
lv cluster relay-restore <host> [--hold 1h]  # Clear a relay-health demotion now; --hold keeps the lease
                                   #   holder from demoting it again (admin, audited; see operating-model.md → Replication)
lv cluster failback [on|off]       # Show or set whether an undrain moves drained VMs back (see
                                   #   migration-failover.md → Failback after maintenance)
lv cluster ha                      # Show the cluster HA policy, each voter's answer, unconfirmed regions,
                                   #   first-use status and, while disarmed, the hosts an arm would fence
lv cluster ha disarm [--reason "..."]  # Hold every automatic fence and recovery cluster-wide (admin, audited;
                                   #   returns once confirmed, up to 80 s; see migration-failover.md →
                                   #   Disarming HA for planned maintenance)
lv cluster ha arm [--fence-down-hosts] [--reason "..."]  # Resume them; refused while a host is reported
                                   #   down unless --fence-down-hosts
lv cluster upgrade-status          # Latched capability tokens on the connected host, whether each blocks a
                                   #   rollback, and which release features are in use (see upgrades.md →
                                   #   Rolling back after a release token latched)
lv cluster acknowledge-lease-term --key <k> --term <n>   # Acknowledge a contested lease term on the connected host
lv cluster voter ls                # Adopted voter generation; per member: host state, reachable, abstaining
lv cluster voter init [--members a,b,c] [--yes]   # Start a voter generation by hand (unanimous); for a
                                   #   cluster that cannot become clean, or after a reset
lv cluster voter add <host>        # Add one voter (decided by a majority of the current generation)
lv cluster voter rm <host>         # Remove one voter; allowed while it is unreachable
lv cluster voter reset [--yes]     # Decided exit to the voter set derived from host state (sticky)
lv cluster voter force-reconfigure --lost a,b [--dry-run] [--yes]
                                   # Break-glass for a generation whose majority is gone for good:
                                   #   every named member fenced proof-grade, refused while a majority
                                   #   is reachable; audited, raises ha.voter.forced (§4.6 of the design)
lv cluster claim <kind>/<name> [--epoch N]   # Every voter's recorded state for a vm/container recovery
                                   #   claim: ballots, value, destination, source, last refusal
lv cluster claim-release <kind>/<name>       # Release one workload ha.claim.legacy_held holds behind a
                                   #   legacy proof stuck in flight on a live destination; the
                                   #   destination confirms nothing runs it, then abandons it (admin)
lv health [--resolved]             # Cluster health: overall + conditions + coverage (exit 0/1/2)
lv health resolve <code> <kind>/<id> [--reason R] [--evaluator E] [--accept PATH] [--force] [--accept-stale-uefi-vars]
                                   # Resolve one open dual-run condition by hand (admin, audited); re-raised next
                                   #   pass if it still holds; or a vm.move_unresolved (--reason required) on its
                                   #   holding host, or once that host is proven powered off; --accept picks the
                                   #   file to keep of one disk (repeat per disk; required for a move with no pivot
                                   #   recorded, unless the holder owns the VM and its config and record name
                                   #   the source); --force keeps a forked history's file although the other
                                   #   was modified after it; or accept nvram_flush_failed's vars stores as stale
                                   #   (--accept-stale-uefi-vars)
```

## Hosts

```bash
lv host init <user@host> --name <name>    # Bootstrap first host (remote)
lv host init --local --name <name>        # Bootstrap on localhost (standalone)
  [--force]                               # Re-init a host that is ALREADY a cluster
                                          #   member. init rewrites the whole
                                          #   config.yaml and resets join_peers to [],
                                          #   which also makes the node look like a
                                          #   founder — use `lv host add` instead
lv host add <user@host> --name <name>     # Add host to cluster
                                          # new <name> (init, add): letters, digits, '_', '.', '-';
                                          #   not starting with '-' or '.', not ending in -migration,
                                          #   and not ca, client, host, gossip, migration-ca, ui,
                                          #   audit-signing or lv-cli (any case). A host an older
                                          #   release admitted keeps its name; re-adding it after
                                          #   `lv host rm` needs one that follows the rule
lv host ls                                # List hosts (UPDATES column: pending OS package updates, see upgrades.md)
lv host ls --names                        # Print only host names, one per line (for scripts)
lv host inspect <host>                    # Host details, with the capacity reservations counted against it (see diagnostics.md)
lv host drain <host> [--parallel 2]       # Evacuate VMs off host
lv host shutdown-workloads <host>         # Stop VMs in reverse startup-order (honors stop-delay)
lv host undrain <host> [--failback]       # Return a draining, maintenance, fenced or offline host to scheduling (--failback: wait for the failback it started and print results)
lv host failback <host> [--all] [--dry-run] [--follow]   # Live-migrate VMs a drain moved away back to the host
lv host rm <host> [--force]               # Remove host (--force with running VMs); revokes its cert
lv host rm --dead <host> [--dry-run] [--force]  # Remove a host fenced proof-grade and gone for good: checks the
                                          #   fence, `voter rm` if it votes, revokes + publishes the CRL,
                                          #   removes it, and reports the stranded recoveries that now retry
                                          #   at the next claim attempt. --dry-run changes nothing. Refused
                                          #   while a firmware VM's live move to the host is not settled
                                          #   (`lv doctor firmware-move <vm>`); --force removes it anyway
lv host rm <host> --serial <serial>       # Remove one admission by its certificate: the row of <host> if it
  [--address <ip>]                        #   holds it, otherwise no row: once the daemon confirms no row
                                          #   holds it and the machine at --address has its trace and does
                                          #   not serve it, it is revoked and its adds' files there removed;
                                          #   a failed step names this command again, which finishes it
lv host publish-crl                       # Re-publish this machine's crl.pem if `host rm` could not
lv host renew-cert <host>                 # Renew a host's cluster certificate in place: key made on
  [--ssh root@<addr>] [--keep-old]        #   the host, one atomic switch, served without a restart,
  [--revoke-old] [--force]                #   confirmed, then the old one revoked (owed while the
  [--grpc-port 7443] [--wait 90s]         #   voter chain needs it). See auth.md
lv host revoke-cert <host> --serial <hex> # Revoke a certificate a renewal replaced; --force for the
  [--force] [--grpc-port 7443]            #   live/presented one (fences the host)
lv host install-gossip-key                # Put the cluster gossip key on every host (mints it if
  [--ssh-user root]                       #   none); never replaces one. Re-run to see each host's
                                          #   gossip stage. See auth.md "Gossip encryption"
lv host install-migration-tls             # Issue every host the migration-TLS credentials that
  [--reissue] [--ssh-user root]           #   encrypt storage migrations (mints the migration CA if
                                          #   none). See migration-failover.md "Migration with local disks"
lv host rotate-migration-ca               # Replace the migration CA on every host, in three gated
  [--no-overlap] [--force]                #   phases (trust-both, reissue, drop-old); resumable.
  [--ssh-user root]                       #   --no-overlap: one pass, for a compromised or expired CA.
                                          #   --force: leave unreachable hosts behind. See
                                          #   migration-failover.md "Rotating the migration CA"
lv host rotate-gossip-key                 # Replace the gossip key everywhere, live, in three
  [--grace 30s] [--timeout 2m]            #   barriered phases; re-run to settle an interrupted one
  [--ssh-user root]
lv host fence <host> --confirmed          # Manually fence a host (real fence)
lv host fence-confirm <host>              # Confirm an already-powered-off manual-fence (or removed) host;
                                          #   refused while the host still answers health probes
lv host rescan [host]                     # Rescan PCI devices
lv host devices <host> [--type gpu|network|nvme|infiniband]   # List PCI devices
lv host superseded-disks <host>           # List the disk copies a failover set aside, and the
                                          #   .kept- disks and seeds a create made (marked kept, list only)
  [--purge] [--older-than 72h]            #   remove the ones neither retained nor held (admin)
  [--remove <copy>]...                    #   remove exactly these copies, even retained (admin)
  [--restore <copy>]                      #   put a copy back as its stopped VM's disk (admin)
lv host lun-holds [host]                  # List the holds kept on iSCSI LUNs a rebuild or recreate moved
lv host lun-hold discard <lun> --yes      # Move a hold aside so the LUN can be taken again (admin, audited)
  [--host <host>]                         #   on that host (default: the one host holding it)
lv host upgrade --binary <path> [host...] # Rolling upgrade of litevirt
  [--yes]                                 # Skip confirmation prompt
  [--force]                               # Skip preflight blocks (warnings still printed)
  [--no-prestage]                         # Skip the cluster-wide schema pre-stage pass
  [--skip-prestage <host>[,<host>]]       # Members that are down: leave them on their schema
lv host preflight-upgrade <host>          # Report preflight findings without upgrading
lv host label set <host> key=value ...    # Set labels on a host
lv host label rm <host> <key> ...         # Remove labels from a host
lv host label ls <host>                   # List labels on a host
lv host config <host>                     # Configure host settings
  [--fence-strategy ssh|ipmi|redfish|watchdog|manual|best-effort]
  [--ipmi-address <addr>] [--ipmi-user <u>] [--ipmi-pass <p>]
  [--clear-ipmi]                          # Remove the IPMI address, user and password
  [--redfish-endpoint https://<bmc>[:port]] [--redfish-user <u>]
  [--redfish-pass-file <path>|-]          # password from a file or stdin (preferred)
  [--redfish-pass <p>]                    # password on the command line (visible in ps)
  [--redfish-system-id <id>]              # ComputerSystem Id, when the BMC lists several; ="" unsets
  [--clear-redfish-ca]                    # back to the system roots
  [--redfish-auth session|basic]          # default session
  [--redfish-ca-file <pem>]               # CA the BMC certificate must chain to (default: system roots)
  [--clear-redfish]                       # Remove the Redfish settings
  [--watchdog-dev <path>]
  [--role worker|witness]                 # witness = vote-only tiebreaker
  [--region <name>]                       # Region label (federation)
lv host stats <host>                      # Host resource statistics
lv host ceph init                         # Bootstrap Ceph cluster on this host
lv host ceph add-mon <host>               # Add a Ceph monitor
lv host ceph add-mgr <host>               # Add a Ceph manager
lv host ceph add-osd <host> <device>      # Add an OSD on the named device
lv host ceph status                       # Ceph cluster health summary
lv host ceph osd-tree                     # Ceph CRUSH topology
```

## Virtual machines

```bash
lv run --name <vm> --image <img> [flags]  # Create and start a VM
  --cpu <n>             # vCPUs (default 2)
  --cpu-mode <mode>     # host-passthrough|host-model|custom (default host-model)
  --cpu-model <model>   # CPU model for --cpu-mode custom, e.g. x86-64-v3
  --cpu-limit <cores>   # cap total CPU at this many host cores (fractions ok, at most --cpu)
  --cpu-shares <n>      # CPU weight under contention, 1-10000, default 100 (cgroup v2 cpu.weight = Proxmox cpuunits)
  --memory <mib>        # Memory in MiB (default 4096)
  --disk <size>         # Root disk size (default 20G)
  --storage <pool>      # Storage pool for the root disk (default: the host's local disks)
  --overwrite           # iscsi pool + --image: write the image over a LUN that is not blank
                        #   (destroys what it holds; a LUN another VM uses is never written)
  --host <name>         # Target host (auto-placed if omitted)
  --project <name>      # Tenancy project to create in (default _default); charges its quota
  --secure-boot         # UEFI Secure Boot (MS keys; q35 + UEFI). Windows 11 ready
  --tpm                 # Attach a TPM 2.0 emulator (vTPM) — required for Win11/BitLocker

lv ls [--stack <name>] [--host <name>]    # List VMs
lv inspect <vm>                           # VM details
lv start <vm>                             # Start stopped VM; one whose start a forced stop cancelled goes back to starting, and the reconciler defines and starts it
lv stop <vm> [--force]                    # Stop VM (--force = hard power off); a VM already stopped succeeds as a no-op, recording the stop (an error VM is left as it is, its set-aside disk copies held); one being started (pending/starting) is refused until it runs; with --force, one being started with no domain defined has its start cancelled (stopped, its set-aside disk copies still held); an `lv start` libvirt has not answered within its wait is refused at once (Unavailable), and with --force cancelled: the VM is recorded stopped now and a domain libvirt starts for it is destroyed when it answers
lv restart <vm>                           # Restart VM
lv rm <vm> [--keep-disks] [--force]       # Delete VM (--force = hard power off a running VM, only once the delete's checks pass)
lv console <vm>                           # Serial console (Ctrl+] to exit)
lv vnc <vm> [--listen 127.0.0.1:5900]      # VNC connection info; --listen opens the console on a local port (no password)
lv spice <vm> [--launch] [--listen 127.0.0.1:5930] [--show-password] # SPICE info; --launch opens remote-viewer and --listen a local port, both carried through the daemon
lv exec <vm> <cmd> [args...]              # Run command via guest agent
lv ssh <vm> [-u root] [-i key] [-- cmd]   # SSH into VM
lv logs <vm> [-f] [-n 50]                 # VM logs (-f to follow)
```

**A kept disk and a create of the same name.** After `lv rm --keep-disks
<vm>`, the VM's disks stay where they were. A VM of the same name created later
on the same host would take `<data_dir>/disks/<vm>-<disk>.qcow2`, so the create
first renames a kept disk there to `<path>.kept-<time>`, and the kept VM's
cloud-init seed (`cloudinit/<vm>.iso`) to `<seed>.kept-<time>`. Nothing removes
those files; each rename is recorded as a `vm.disk.kept` event of the VM. A disk
recorded `delete_with_vm=false` is handled the same way. The create renames
nothing until the refusals it can judge up front have passed (Secure Boot or
vTPM over kept UEFI vars, a USB device the host does not have, the image not
available), and a create that fails
after the rename puts each file back at the path the kept VM recorded, unless
a file is there by then. The host that holds
kept disks lists them in `<data_dir>/kept-disks/<vm>.json` until a create
renames them. `lv host superseded-disks <host>` lists each `.kept-` file there
as `kept`, the seeds in `<data_dir>/cloudinit` among them, and the seed a
deleted VM was kept with where it was, while no VM of its name exists (a seed
can hold user-data passwords); `--purge`, `--remove` and `--restore` never take one, so
only an operator removes it, by hand. Each is listed under the VM of its name
when that is known; while a VM of that name exists, one that is an earlier
VM's (every kept disk, and a seed not stamped for the VM there now) says so.
A seed whose owner stamp is empty or unreadable is listed as kept. A `--keep-disks` delete whose
`<data_dir>/kept-disks/<vm>.json` cannot be read is refused, naming the file,
with nothing deleted: repair or remove that file, then retry.

**Delete keeps its handle on failure.** `lv rm` removes the VM's record only once
its libvirt domain is gone. If the running (or paused) domain cannot be stopped,
nothing is removed; if it is stopped but cannot be undefined — or its PCI
passthrough devices cannot be released, or another host still owns one of them —
the record and the disks are kept and the VM is recorded `stopped`
(`operator-stop`, so no restart policy brings it back). Either way the command
fails, the `vm.delete` audit entry has result `error`, and a retry is safe. The
record is the only thing in the cluster that names the domain, so it is never
dropped while the domain may still exist.

**Delete holds the start lease.** From before it touches the domain until its
record is gone, `lv rm` holds the VM's start lease on the host that carries it
out, so the reconciler cannot read the stopped, undefined domain of a VM still
recorded `running` as a crashed guest and start it again mid-delete. A delete
that meets a start already holding the lease (the reconciler bringing the VM
back, a restart policy, a failover) waits for it, up to 60 seconds, then goes
ahead. If the lease is still held after that, the delete fails `Aborted`
before anything is touched, naming the holder; a stack teardown retries it,
and a retry by hand is safe. A lease with no live holder behind it is taken
over, as a snapshot restore does.

A daemon that crashes midway through a delete leaves the delete's lease
behind. Until the delete is retried, or the lease expires after 10 minutes,
nothing restarts the VM: the reconciler and the restart policy do not take a
lease over. A retried `lv rm` runs on the same host and is the same holder, so
it takes the lease back at once and completes the delete.

**An interrupted delete still completes.** A delete interrupted before it acts
— `lv rm` or `lv compose down` killed, or the entry host's forward cancelled,
during its checks, its wait for the start lease, or while the VM's host asks
its peers whether one of them has the domain — is refused with nothing
touched. Once it acts (it stops the VM, or for a VM with no domain left, it
begins removing the record), the host that carries it out finishes it whatever
becomes of the client: the record is tombstoned, or the delete fails with the
VM recorded `stopped` (`operator-stop`) as above, unless its record has moved
to another host meanwhile. Its cluster writes from that point have 10 minutes;
libvirt and storage calls are not cut short. `lv ct rm` behaves the same from
the container's runtime delete on. A command interrupted by Ctrl-C or SIGTERM
reports that the delete may still complete on its host, names `lv ls` (`lv ct
ls` for a container, `lv compose ls` for a stack) to see the outcome, and then
ends by the signal (the shell sees 130, or 143 for SIGTERM). A command waiting
at a prompt ends at once. Any other command still running 2 seconds after the
signal (one on an ssh step) ends then, except while it undoes what it already
did (a firewall macro's rollback, up to 30 seconds), and a second Ctrl-C ends
it at once, without the report. `lv daemon`, `lv gitops`, `lv top`, `lv spice`
and `lv vnc` handle Ctrl-C themselves.

`lv rebuild` and a `lv compose up` that re-creates a VM work the same way.
Interrupted before the re-create sends its delete (a rebuild: before its
teardown), nothing is deleted. From then on the replace runs to its create
whatever becomes of the client, so an interrupted replace does not end with no
VM; the command reports that it may still complete, and names `lv ls`. A VM
being re-created is not listed until its create finishes, which can take
minutes: wait until `lv ls` shows it before running the command again, or the
second run may create it again. A create that replaces nothing (the delete found
no VM) stays cancellable. A `lv compose up` interrupted after it has torn a VM
down to re-create it still records the stack's new compose file, with the
stack `degraded`: the rest of its plan did not run, and once `lv ls` shows the
re-created VM, running `lv compose up` again finishes it.

**CPU mode.** The default, `host-model`, gives the guest the host's modern
instruction set — SSE4.2, AVX, AVX2, AVX-512 as the host has them — while keeping
live migration to a host with an equal-or-richer CPU. It matters because the
alternative is not "a slightly older CPU": with no mode at all, QEMU falls back to
`qemu64`, which has no AVX, and guest software built against a modern baseline
will not start.

`host-passthrough` exposes the host CPU verbatim and is the only mode that carries
nested virtualization into the guest, at the cost of pinning live migration to
effectively identical hardware. `custom` needs `--cpu-model` and is how you hold
one baseline across a heterogeneous fleet. The cluster-wide default is
`vm.default_cpu_mode` (see [configuration](configuration.md)); `lv doctor cpu-mode`
lists VMs created before it existed, which are still on `qemu64`.

Changing the mode on an existing VM is an in-place edit — `lv update <vm>
--cpu-mode host-model` on a stopped VM, or with `--restart-if-needed` to fold the
stop/start in. It patches libvirt's own domain XML rather than regenerating it, so
guest PCI addresses and controller models are preserved.

## VM configuration

```bash
lv config <vm> --ip <ip> --network <net>     # Record VM IP in inventory (+ DNS if configured); does NOT reconfigure the guest
lv config <vm> --boot disk|cdrom|network     # Set boot order

# lv update reconfigures an existing VM. Restart policy, autostart and startup
# ordering apply LIVE (no stop needed); the resource fields require the VM stopped.
lv update <vm> --restart on-failure          # set/clear restart policy (live)
  [--restart-max-attempts N --restart-delay 5s --restart-window 1h]
  [--restart none]                           # clear the policy
lv update <vm> [--onboot] [--startup-order N] [--start-delay N] [--stop-delay N]   # autostart/ordering (live)
lv update <vm> [--cpu-limit CORES] [--cpu-shares N]   # noisy-neighbour limits (live; 0 clears the cap / restores the weight)
lv update <vm> --nic-rate 0=12.5 [--nic-rate 1=0]     # per-NIC bandwidth cap in MB/s, NIC numbered from 0 (live; 0 clears it)
lv update <vm> --nic-mtu 0=9000 [--nic-mtu 1=bridge] # per-NIC MTU, NIC numbered from 0; must equal the
                                             # bridge's MTU (VM STOPPED or --restart-if-needed; 0 removes it)
# The NIC number in --nic-rate and --nic-mtu is the NIC's position in the VM's
# NIC list, from 0: its NICs in ordinal order, as `lv inspect <vm>` lists them
# under spec.network. A NIC detached and attached again goes to the end of it.
# --nic-rate needs the NIC's spec entry: give a NIC attached after the create
# one with --nic-mtu <nic>=0. A host on an older build reads the numbers as
# spec entries: an update reaching it through an upgraded node is translated,
# or refused naming the host to upgrade; the CLI talking to it directly
# refuses a number at or past the first gap in the VM's NIC numbering (a NIC
# was detached) and sends the others.
lv update <vm> [--cpu N] [--memory N]        # resources — VM must be STOPPED
  [--cpu-mode host-passthrough|host-model|custom] [--cpu-model <model>]
  [--disable-vnc]
  [--machine q35] [--firmware uefi|bios] [--guest-agent]
  [--min-mem N] [--max-mem N]
  [--max-cpu N]                              # vCPU hotplug ceiling (needs live_resize);
                                             # with it set, --cpu grows a RUNNING VM's
                                             # vCPUs live up to the ceiling
  [--memory-hotplug-max N]                   # virtio-mem hot-add ceiling (0 = off); with
                                             # it set, --memory changes a RUNNING VM live
  [--usb <vendor>:<product>] [--usb-port <bus>-<port>] [--usb-mapping <name>]
                                             # REPLACE the USB passthrough list (repeatable)
  [--clear-usb]                              # remove every USB device
  [--secure-boot] [--tpm] [--force]          # toggle Secure Boot / vTPM (stopped).
                                             # Once firmware state exists, --force is
                                             # required to change them (enabling SB can
                                             # brick an unsigned guest; dropping the TPM
                                             # orphans BitLocker).
lv rebuild <vm>                              # Recreate from stored spec
lv cutover <vm>                              # Snapshot-and-replace update
lv resize-disk <vm> --disk <name> --size <size>   # Grow a disk
lv disk-io <vm> [--disk <name>] [--total-bps <rate>] [--read-bps <rate>] [--write-bps <rate>]
            [--total-iops <n>] [--read-iops <n>] [--write-iops <n>]
            [--read-bps-max <rate>] [--write-iops-max <n>] [--burst-seconds <n>] [--clear]
                                             # Throttle a disk's I/O, live on a running VM
lv stats <vm>                                # VM resource statistics
```

`lv disk-io` sets one disk's I/O limits (default disk `root`): bytes per second
(`--total-bps`, `--read-bps`, `--write-bps`, with a K/M/G suffix such as `50M`) and
operations per second (`--total-iops`, `--read-iops`, `--write-iops`), each with a
`-max` burst ceiling above the sustained rate and `--burst-seconds` for how long it
lasts. A running VM is throttled live and its definition updated; the limits are kept
in the VM's spec, so a restart, a failover start and a migration carry them. **Each call
sets the complete set of limits for the disk**: one you do not name is unlimited
afterwards, and `--clear` removes them all. A `--total-*` limit cannot be combined with
the `--read-*` / `--write-*` of the same kind. A disk the VM's spec does not list yet (the implicit
root disk, a hot-plugged one) is throttled too; its entry is made in the spec. If a step
fails partway the previous limits are put back and the spec is left as it was. The same limits are the `iotune:` key of a compose disk; see
[compose.md](compose.md).

`lv cutover <vm>` gives the `<vm>-next` replacement the original's name. The replaced
VM is deleted first, and a delete is a SOFT delete, so its rows still hold the primary
keys the replacement needs. Taking them is a single guarded transition rather than a
purge or a two-step move: a purge is applied unconditionally by a lagging peer while the
write meant to replace the row is not, and two steps can apply independently there. The
row installed at the name keeps the REPLACEMENT's `created_at` and carries authority
above both VMs, which is what stops a lagging peer's pre-delete copy of the replaced VM
from reappearing on top of it.

A cutover of a RUNNING replacement restarts it, and `lv cutover` prints that before it
starts. libvirt has no operation that moves a live domain to another name, so the
replacement is stopped — a PAUSED one too, since a paused domain is still active — then
redefined under the new name and started again. The cutover's journal makes that restart
survive an interruption.

That needs receiver behaviour an older peer does not have, so cutover **refuses** until
`enforcement.vm_replace` is set on every node and `vm_replace_v1` has latched — refusing
before it stops a domain or writes to either VM. See docs/diagnostics.md.

A cutover retires the replaced VM's domain only on the node it runs on. If the replaced
VM is hosted elsewhere, cutover asks that node instead, and **refuses** unless it reports
no domain left at the name — a domain still defined there, an incomplete survey, or a
node it cannot reach all refuse, before anything is written. Stop and remove the original
on its own host first.

The database transition runs before the replaced VM's disks and firmware state are
freed, so a cutover that fails partway leaves the original intact and can simply be
retried. Because that transition also displaces the rows describing what the replaced
VM owned, the cleanup is journaled as a `vm_replace` operation whose manifest is
recorded first and whose authorizing step is committed with the transition — so a
daemon that dies in between finishes the cleanup when it restarts. Cutover therefore
requires `enforcement.operation_protocol` alongside `enforcement.vm_replace`.

## Secure Boot + vTPM (Windows 11)

```bash
lv run --name win11 --image win11.qcow2 --secure-boot --tpm   # Windows 11-ready VM
lv update win11 --tpm --force                # toggle on a stopped VM (--force if state exists)
lv inspect win11                             # shows secure_boot / tpm
```

Secure Boot uses the Microsoft-keyed OVMF firmware (`OVMF_CODE_4M.secboot.fd` +
`OVMF_VARS_4M.ms.fd`) on a q35 machine; `--tpm` attaches a TPM 2.0 emulator
(swtpm). Together they satisfy the Windows 11 / BitLocker / measured-boot
requirements.

**Host capability.** A VM only lands on a host that advertises the matching
capability: `litevirt.tpm` (host has `swtpm` + `swtpm_setup`) and
`litevirt.secureboot` (host has the secboot + MS-keys OVMF firmware). Placement,
migration, drain and rebalancing all honor these — a Secure-Boot/vTPM VM is never
scheduled onto a host that can't run it.

**Firmware state travels with the VM.** Its UEFI NVRAM (Secure Boot keys) and
swtpm state (the BitLocker-binding secret) are carried through snapshot+revert,
backup+restore, and cold migration — or the operation **refuses clearly** rather
than silently breaking BitLocker. The explicit refusals:

| Operation | Behavior for a Secure-Boot/vTPM VM |
|---|---|
| snapshot (running, disk-only) | refused — use `--memory` (no consistent firmware capture otherwise) |
| snapshot (stopped, or running `--memory`) | firmware captured alongside the snapshot |
| revert with no captured firmware | refused (a pre-firmware/older snapshot can't be reverted safely) |
| backup | snapshot backup only; the legacy raw stream backup is refused. Running VMs are refused — **stop the VM** to back up its firmware consistently. Multi-disk firmware VMs are not supported yet |
| clone | gets a **fresh** vTPM + fresh NVRAM (the secret is never copied) — a cloned BitLocker guest needs its recovery key |
| live migration | supported for a **running** VM between hosts with equal firmware code; its NVRAM and vTPM state move with it and are verified on the target (see [migration-failover.md](migration-failover.md#secure-boot--vtpm-vms)) |
| cold migration | supported for a **stopped** VM; its host-local disks are copied as for any stopped VM, and its firmware is captured quiescent and carried to the target. PCI-passthrough firmware VMs are not supported yet |
| host drain | a stopped VM is moved as cold migration moves it, host-local disks included; a running one is refused — stop it (`lv stop <vm>`), then drain again or `lv migrate <vm> <target-host> --cold` |
| automatic failover (host died) | skipped — firmware is host-local and died with the host; recover via restore from a firmware-carrying backup |
| replica promotion | refused — a disk replica carries no firmware |
| `lv rm --keep-disks` then `lv run --name <same>` | refused — the retained NVRAM isn't inherited; restore the VM instead of recreating it |

**UEFI variable writes and a host power cut.** qemu writes a guest's UEFI
variables (any UEFI VM, not only Secure Boot) to its vars file without
flushing it, and libvirt has no cache setting for that file. The daemon
fsyncs every vars file that changed, in `<data_dir>/nvram/` and
`/var/lib/libvirt/qemu/nvram/`, once a second, and once more as it stops. A
host power cut can therefore lose a variable written in about the last second
before it, or up to `vm.dirty_expire_centisecs` (30 s by default) while the
daemon is not running. A failed fsync raises `nvram_flush_failed`, and a vars
file that cannot be opened for a minute raises `nvram_flush_blocked`
(docs/diagnostics.md).

swtpm writes a vTPM's state without fsync. With `vtpm_state_sync` on (the
default, docs/configuration.md), the daemon sets the sync attribute on
`/var/lib/libvirt/swtpm` and everything under it, at start before it starts
any VM and every minute after. On ext4, and on xfs mounted `dirsync` or
`wsync`, a vTPM command then returns only once its state is on disk. Elsewhere
(xfs without either, btrfs, ZFS, NFS, tmpfs), or when a pass fails or does not
finish within 10 seconds, the host raises `vtpm_state_not_durable`
(docs/diagnostics.md), and a vTPM write made shortly before a power cut can be
lost.

## Containers (LXC / OCI)

```bash
lv ct pull <oci-image> --dest <rootfs>       # Pull an OCI image (skopeo + umoci)
lv ct pull <oci-image> --dest <rootfs> --username <u> --password-stdin   # ad-hoc auth pull
lv ct create <name> [--image <oci>] [--distro alpine --release 3.19] [--local] [--project <p>]
lv ct create <name> --network network=<managed-net>[,name=eth0,ip=<cidr>,security-groups=web;db]  # managed NIC (IPAM/DNS/SG)
lv ct create <name> --network bridge=<br>[,name=eth0,ip=<cidr>,mac=..]   # raw NIC (admin/root only under project tenancy)
lv ct create <name> --restart on-failure [--restart-max-attempts 5 --restart-delay 5s]  # auto-restart on unexpected stop
lv ct create <name> --on-host-failure image-recreate   # rebuild on a surviving host if this one is fenced
lv ct start <name>
lv ct stop <name>                                     # a container already stopped succeeds, recording the stop
lv ct stop <name> --force                             # on a host in write quarantine: stopped, recorded once the quarantine lifts
lv ct rm <name>                                       # a stopped container; a running one is refused
lv ct rm <name> --force                               # a running container: stopped, then deleted
lv ct ls
lv ct inspect <name> [--host <h>] [--size] [-o json]  # one container: limits, privilege, confinement, NICs, rootfs, snapshots, backups
lv ct exec <name> -- <cmd> [args...]
lv ct backup <name> --repo <dir> [--bwlimit <rate>]    # full rootfs backup → dedup chunk store
lv ct restore <name> --repo <dir> --timestamp <ts> [--start]  # rebuild from a backup manifest
lv ct restore <name> --repo <dir> --timestamp <ts> --without-host-access  # without the backup's host mounts/devices (audited)
lv ct migrate <name> <target-host> --repo <src-dir>    # cold-migrate (stop → stream → start)
lv ct snapshot create <name> <snapshot>                # freeze+tar point-in-time snapshot
lv ct snapshot ls <name>                               # list a container's snapshots
lv ct snapshot revert <name> <snapshot>                # roll back (stop → restore → restart)
lv ct snapshot rm <name> <snapshot>                    # delete a snapshot
lv ct template <name> [--revert]                       # convert a stopped ct to a clone template
lv ct clone <source> <new-name> [--project p] [--start] # full-copy clone with a fresh identity
lv ct pull <image> --dest <name> [--project p]       # stage an OCI image; with --project only p (and Admin) may use it
lv ct convert <name> --unprivileged [--confinement default]  # stopped ct → an id range of its own
lv ct convert <name> --confinement default|legacy      # change confinement (legacy: Admin only)
lv ct convert <name> --mount <host>:<ct>[:rw] --device <host>  # replace host mounts/devices (Admin only)
lv ct convert <name> --clear-host-access               # remove them
lv ct convert <name>                                  # finish an interrupted convert (the start refusal names it)
lv ct create <name> --privileged                       # no user namespace, as earlier releases (Admin only)
lv ct create <name> --confinement legacy               # AppArmor nesting, template seccomp/caps (Admin only)
lv ct create <name> --mount /srv/data:/data[:rw]       # host bind mount, read-only unless :rw (Admin only;
                                                       # under the host's containers.bind_mount_paths)
lv ct create <name> --device /dev/ttyUSB0[:/dev/ttyS0] # host device node (Admin only; containers.device_paths)
```

`--local` runs against the local lxc-* binaries instead of the gRPC service
(used during bootstrap and debugging).

`lv ct backup` freezes a running container, archives its rootfs + LXC config,
and pushes a self-contained manifest into a PBS-equivalent repo (dedup against
earlier backups is automatic). `lv ct restore` rebuilds it from the repo alone
— even after `lv ct rm` — refusing to clobber a live container of the same name.

`lv ct migrate` cold-migrates a container to another host by reusing that
backup→restore transport: stop → archive → restore on target → restart (if it
was running). The source archives into `--repo` locally and **streams the
manifest to the target over peer mTLS**, so `--repo` need only exist on the
**source** (no shared/NFS repo required). An older target that predates peer
streaming falls back to re-opening `--repo` by name, which then must be reachable
from both hosts. A failure before cutover leaves the container intact on the
source. No live migration / CRIU.

## Registry credentials

Logins for private OCI/Docker registry pulls. Per-user by default; `--global`
stores a cluster-wide credential (operator-only). At pull time the caller's
per-user credential for the image's registry wins, else the global one, else an
anonymous pull. See [containers.md](containers.md#private-registry-credentials).

```bash
echo "$TOKEN" | lv registry add <registry> --username <u> --password-stdin   # store (per-user)
echo "$TOKEN" | lv registry add <registry> --username <u> --password-stdin --global   # store (cluster-wide; operator)
lv registry ls                               # your own + global (secrets never shown)
lv registry ls --all                         # every user's + global (operator)
lv registry ls --global                      # global only
lv registry rm <registry>                    # remove your own
lv registry rm <registry> --global           # remove the cluster-wide one (operator)
```

`<registry>` is a host: `docker.io`, `ghcr.io`, `registry.example.com:5000`.
Prefer `--password-stdin` over `--password` so the secret stays out of argv and
shell history.

## Migration

```bash
lv migrate <vm> <target-host>                  # Live migrate
lv migrate <vm> <target-host> --cold           # Cold migrate: a stopped VM moves stopped, disks copied
lv migrate <vm> <target-host> --with-storage   # Copy disks to the target during migration
```

## Rebalance

```bash
lv rebalance list [--status pending]                    # List proposals (pending|approved|applying|applied|failed|rejected|expired)
lv rebalance list [--limit N] [--offset N]              # Page through history; the server bounds the page
lv rebalance run [--dry-run]                            # Force one evaluation cycle
lv rebalance approve <proposal-id>                      # Approve → leader's executor live-migrates it
lv rebalance reject  <proposal-id> [--reason "text"]    # Reject a pending proposal
```

The rebalancer runs automatically every 60 s on the leader (proposing moves);
the leader's executor applies approved proposals (`approved → applying →
applied/failed`), bounded by the cluster rebalance budget.
See `docs/placement.md` for policies, modes, and execution.

## Regions (federation)

```bash
lv region ls                                   # List regions and host counts
lv region status [--region <name>]             # Region health rollup (all, or one)
lv region migrate <vm> <target-host> \
    [--with-storage] [--target-pool <pool>]    # Cross-region VM move (region inferred from host)
lv region anycast add --name <svc> --ip <ip> --region <r> [--weight N]   # one endpoint per call
lv region anycast ls [--name <svc>]
lv region anycast rm --name <svc> --ip <ip>
```

See `docs/federation.md` for the model.

## Compose stacks

```bash
lv compose up [-f litevirt-compose.yaml] [-y]      # Deploy/update stack
lv compose down [-f litevirt-compose.yaml] [-y]    # Tear down stack
lv compose down --name <stack> [-y]                # Tear down by stack name
lv compose ps [-f litevirt-compose.yaml]           # List stack VMs
lv compose diff [-f litevirt-compose.yaml]         # Preview changes
lv compose up --allow-weaken                       # Also restore declared NIC security groups / looser guards over runtime changes
lv compose diff --allow-weaken                     # Preview what up --allow-weaken would change
lv compose ls                                      # List all stacks
lv compose export <stack> [-o file.yaml]           # Export stack compose YAML
```

## Networks

```bash
lv network ls                                     # List networks
lv network inspect <name>                         # Show network details
lv network create <name> --type bridge [flags]    # Create a network
  --interface <name> | --vni <int> --underlay <iface>
  --subnet <cidr> [--dhcp]
  --pf <iface> --spoof-check                      # SR-IOV variants
  --project <name>                                # owning project (empty = global/shared)
  --netbox-prefix-id <id>                         # bind to a NetBox prefix
  --gateway <ip> --reserved-address <ip>          # the network's router when it is not litevirt's, other infrastructure (repeatable); no guest NIC may claim them
lv network set <name> [--gateway <ip>] [--reserved-address <ip>]... [--allowed-vlans 100,101]
                                                  # change what a network keeps from its NICs (network.update; each flag replaces its setting)
                                                  # on a flat bridge (no network row): --allowed-vlans only, network.update at the cluster root
lv network rm <name> [--force]
```

`--project` makes the network owned + isolated: only that project's workloads (or
a root operator) may attach. Omit it for a global/shared network. `lv network ls`
shows the owner. See `docs/tenancy.md`.

`--netbox-prefix-id` binds the network to a NetBox prefix so VM NICs on it claim
their address from NetBox. See `docs/networking.md#binding-a-network-to-netbox`
for the preconditions (VRF with `enforce_unique`, the `netbox_ipam_v1` latch).

## NetBox IPAM

```bash
lv netbox rekey <network>                         # re-stamp a bound network's identities under the current fingerprint
lv netbox rekey                                   # re-stamp the mirrored inventory, cluster-wide
lv netbox resume <network>                        # finish an owed adoption and lift a suspension
```

A bound network's binding is suspended when the NetBox prefix drifts out of what
the bind validated, or when the cluster fingerprint stamped on every NetBox
object litevirt owns no longer matches the one the binding recorded. New
allocations then refuse while running VMs continue untouched. Replacing the
cluster CA on disk does **not** move that fingerprint — it is minted once from
the replicated `cluster` row, which nothing rewrites — so it does not produce
this suspension.

`lv netbox rekey <network>` is the moved-fingerprint case: it rewrites those identities under
the current fingerprint and resumes the binding, and is safe to re-run. It covers
the bound prefix's addresses, the mirrored VM and interface objects, and
litevirt's local identity index — in that order. It resumes nothing while another
drift is still present.

`lv netbox rekey` with no network is the same operation for a cluster that
mirrors inventory without binding a prefix, where there is no binding row to take
the old fingerprint from. It re-stamps the mirrored objects and the local index
only, deriving its pin from that index, and resumes nothing. With no old
fingerprint recorded anywhere it refuses rather than re-stamping by any other
rule. See `docs/networking.md#recovering-from-a-moved-cluster-fingerprint` for what the
order buys and why the refusal matters.

`lv netbox resume` is every other case, and it does two things rather than one:

- it re-checks the bind-time preconditions and clears the suspension, refusing
  while the drift is still there and never accepting a changed CIDR (re-CIDRing
  a bound prefix is unsupported);
- it **finishes any adoption the bind left owed** — the addresses this network's
  guests already hold that NetBox has not been told about — and lifts the
  suspension only once every one of them is recorded. That is what makes "re-run
  to finish" true for a bind whose adoption stopped partway, and it is why a
  resume is a NetBox *write* pass: it refuses while another pass or a re-key is
  running on the same node.

A binding suspended because the node could not corroborate its VM inventory
lifts itself on the next NetBox maintenance pass; running this finishes it
immediately instead. See `docs/networking.md#resuming-a-suspended-binding`,
`docs/networking.md#adopting-the-addresses-guests-already-hold` and
`docs/networking.md#recovering-from-a-moved-cluster-fingerprint`.

## Storage pools

```bash
lv pool create <name> --driver <d> [--source <s>] [--target <t>] [--option k=v]
  [--project <name>]                              # owning project (empty = global/shared)
  # drivers: local | dir | nfs | iscsi | ceph | zfs | btrfs | lvm-thin
lv pool ls
lv pool inspect <name>
lv pool delete <name>
```

`lv pool create` runs the driver's Prepare() hook (mount NFS, log into
iSCSI, …) before persisting. See `docs/storage.md` for driver details.
A pool that names a host path (`dir`, `--target`, a btrfs `--source`, NFS
mount options, a Ceph conf or keyring), attaches network storage (`nfs`,
`ceph`, `iscsi`) or allocates from host block storage (`zfs`, `lvm-thin`) needs `storage.hostpath` at `/` (the Admin role), and system and litevirt-internal directories are refused to
everyone; see `docs/storage.md#host-paths`.

## Installer ISOs

```bash
lv iso ls [--host <h>] [--project <p>]         # ISOs a VM may name: project libraries, then the global one
lv iso pull <pool>/<file>.iso --url <url> [--checksum <sha256>] [--host <h>]
lv iso pull <pool>/<file>.iso --from-host-path <path> [--host <h>]   # Admin; a copy, never a link
lv iso rm <pool>/<file>.iso [--host <h>]
lv cluster iso-library-mode [sync|shared]      # where the global library "isos" lives
```

A VM names its installer ISO (`VMSpec.iso`, a compose file's `iso:`) as
`<pool>/<file>.iso`: `isos/debian-12.iso` from the cluster-global library, or
`<project-pool>/<file>.iso` from a project library (a pool the project owns,
created with `--option content=iso`). Only an Admin writes the global library;
a project's operators write its own. An Admin may still give an absolute host
path. See `docs/storage.md`, "Installer ISOs".

## Volumes

```bash
lv move-volume <vm> <disk> <target-pool>       # Move a disk between pools (live or offline)
lv replicate-volume <vm> <disk> <target-pool>  # Point-in-time copy: plain if shut off, else a backup session or external snapshot; a last-resort -U copy is reported NOT point-in-time
lv resolve-pit-overlay <vm> <disk>                       # Admin: the verdict on a point-in-time overlay that holds a VM, and what each action would do (see backups.md)
lv resolve-pit-overlay <vm> <disk> --commit --confirm    # Commit it; refused unless the verdict says it is safe (--force-commit overrides, experts only)
lv resolve-pit-overlay <vm> <disk> --commit --force-commit --overwrite-newer-writes --confirm  # Expert only: commit an overlay already in the disk, over the guest's newer writes
lv resolve-pit-overlay <vm> <disk> --discard --confirm   # Discard it; of a half-written disk only with --accept-torn-disk
lv pit-overlays ls [--host <h>] [--vm <vm>]              # Set-aside overlays (.<disk file>.lv-pit.orphan-<time>) of a host's VMs, on their host; IN USE says why one is kept
lv pit-overlays rm <vm> <disk> <name> [--yes]            # Admin, audited, asks first: remove one and its binding; refused while in use (see backups.md)
lv pit-overlays rm --host <h> --path <path> [--yes]      # Admin, audited, asks first: remove a DETACHED one (no live disk where it was set aside)

# Migrate every VM's volumes in a stack to a different pool (rolling, online):
lv stack migrate-volumes <stack> --to <pool>
lv stack migrate-volumes <stack> --to fast --map pg-1/data=archive --map pg-2=warm
#   --map vm=pool | vm/disk=pool   per-VM/per-disk override (most-specific wins)
#   --parallel N                   VMs migrated at once (default 1 = rolling)
#   --order a,b,c                  explicit VM sequence (e.g. replicas before primary)
#   --delete-source                reap each source after cutover
#   --dry-run                      preview the resolved plan, move nothing
```

## Images

```bash
lv image pull <url> --name <name> [--format qcow2] [--checksum sha256:...]
lv image import <file> --name <name>
#   Content is published as <name>@<sha256-prefix>.qcow2 (every host names the
#   same content the same) and the name points at it. A pull or import under
#   an existing name is a refresh: a new version that new VMs are built on. A file a disk is built on is never written over or removed.
#   The one exception is a heal: a local copy whose bytes no longer match the
#   sha256 recorded when it was published is put back from byte-identical
#   content (the reconciler fetches it from a peer); any other content becomes
#   a new version, and an unhealable base under disks is logged at ERROR.
lv image prune [<image>] [--host <host>] [--dry-run] [--version <file>]
#   Removes, on one host, the image files no disk there is built on — judged
#   from every visible disk's backing header, never from the image's name —
#   keeping each image's current version, every version a kept image is
#   layered on, every version a disk create in flight may use, and every
#   version a disk-file backup was taken on: the backup pins it on the VM's
#   host (<file>.pinned, permanent) wherever the manifest goes — a sink host,
#   an absolute repo path. A backup taken before pins is honoured through its
#   manifest when that is in a backup repo on the host; one taken by an older
#   build records no base and pins nothing.
#   Needs image.import. Nothing is removed unless the whole view can be read
#   within 2 minutes: a pool directory, a disk header, an nfs share that is
#   not mounted or a backup repo that cannot be read refuses the prune,
#   saying which. A directory (the image store's own included) whose
#   listing does not answer within 5 s refuses it at once, with "nothing is
#   pruned". On an image store on a network filesystem (nfs, cifs, ceph,
#   fuse, ...), or one whose filesystem cannot be told, no version is
#   removed: other hosts may share the store, and a disk on their own
#   storage, which this host cannot see, may be built on it. Each such
#   version is listed as kept, with that reason. This protects only once
#   every host sharing the store runs a build with it: an older host still
#   prunes by its own disks alone.
#   --version <file> removes that one file of <image> (its name as listed,
#   or at least 8 digits of the digest after '@') even on such a store: you
#   assert that no other host's disk is built on it. Every other rule above
#   still keeps it, saying why. A daemon that does not know --version is
#   detected with a dry run first, and nothing is removed.
#   A refresh prunes the image's older unused versions by
#   itself, in the background, keeping the one it superseded. What it keeps
#   only because the store may be shared is logged at WARN after every
#   refresh, with the bytes, and notified (image.versions_kept) at most
#   daily per image.
#   A deleted image (lv image rm) has no current version to keep: prune
#   removes all its files, under the rules lv image rm lists below, and
#   lists each one it keeps with the reason.
lv image push <image> --to <host>
lv image build <vm> --name <name>        # Create image from running VM
lv image ls
lv image rm <image>
#   Deletes the image from the catalog, then asks every host to remove its
#   files of the image, the current one too. Needs the operator role, as the
#   catalog delete always has; each host's part runs as that host. Each host
#   judges only its own files and removes one only when nothing keeps it:
#     - a disk, staged disk (a restore, import or replica in progress — a
#       backup repo's chunks there are guest data and are not read), backup
#       base or other image this host can see is built on it, a kept file of
#       a deleted image is built on it, or it is pinned;
#     - a VM anywhere in the cluster records the image: a disk built on it, or
#       a VM created from it (a failover, recreate or migration onto this host
#       may need this host's copy) — so while any VM records it, every host
#       keeps its copy. A VM deleted in the last 10 minutes still counts: a
#       rebuild or rolling recreate deletes the VM and creates it again,
#       possibly on another host. A host that has not yet received the record
#       of a VM created moments before the rm may remove its own copy; the
#       VM's own host keeps the copy its disk is built on;
#     - a disk recorded on this host cannot be read here (a device path such as
#       a logged-out iSCSI LUN does not count), a staging directory cannot be
#       read or nests deeper than four levels, or the image store is on a
#       network filesystem (nfs, cifs, ceph, fuse, ...) that other hosts may
#       share;
#     - a process holds it open (a running qemu), or some process's open files
#       cannot be read: the reason names that process and fd (a daemon not
#       running as root keeps every file; a process holding a dead FUSE or a
#       stale share's file keeps them until it ends);
#     - a disk create, pull, import or build of the image is in flight, or a
#       rebuild, rolling recreate or compose deploy update that recreates a VM
#       from it: each holds the image it creates from, from before its
#       teardown until its create returns;
#     - the file was published (or the same content imported again) less
#       than 5 minutes before the delete, or after it — more when hosts have
#       measured a larger clock skew: the deleting host's clock and this
#       one's may differ by that much, so it may belong to an import of the
#       name since the delete. A skew counts for a delete made up to an hour
#       (plus the skew) after it was last measured. Each host keeps the
#       skews it has seen in image-delete-skew.json in its data directory,
#       so a skew still counts after its measurements age out (an hour) and
#       across a restart. A delete time or publish time that cannot be read
#       keeps the file too, and so does that file when it cannot be read,
#       empty or corrupt (the host logs it at WARN; remove it to start it
#       afresh). lv image rm again, after the time the
#       reason names, removes it.
#   The last check and the removal are one step against a create of the image:
#   a create that begins afterwards finds no file. Each kept file is printed
#   with its reason; once nothing uses it, lv image prune <image> --host <host>
#   removes it. A host that cannot be reached, or runs an older build, keeps
#   its files and is named. A host waits up to 15 seconds for the delete to
#   replicate to it; one that still shows the image (or where it was pulled
#   again) keeps the file. The delete itself is never refused. The REST and
#   web UI delete (DeleteImage) removes the files the same way, in the
#   background, and logs each host's outcome.
#   An import, pull or build under a deleted image's name, or a compose
#   deploy's download of it, makes it a live image again on every host. A
#   compose deploy lv gitops runs does too, for a deleted image the compose
#   file still declares. A copy from a peer (lv image push, a VM create's or
#   the reconciler's copy) does not: one of a deleted name is refused.
#   An lv image rm stamped after one of them began wins on every host: where
#   the delete has already arrived, the operation records nothing and leaves
#   its copy for lv image prune. An lv image rm stamped before it began that
#   has not reached its host when it records loses to it; "before" is by the
#   two hosts' clocks. Two exceptions, where the operation's host has not
#   received the delete when it records:
#     - another import, pull, build, compose download or copy of the image,
#       begun after this one, recorded first: an import, pull, build or
#       compose download then records at that moment, and wins over a delete
#       stamped before then. (A copy from a peer leaves the image's record
#       to the newer one and records only its host's copy, when the newer
#       record is of the same content. A copy of other content is not
#       recorded: it fails, and the VM create or heal that made it copies
#       the image again.) A newer record stamped ahead of this host's clock
#       by more than 5 minutes fails the import, pull, build or compose
#       download instead, naming the clock skew to correct.
#     - lv image pull: its host's record of its copy is rewritten as the
#       download progresses. The image stays deleted, but that host record,
#       and the file, stay until lv image rm runs again when the delete was
#       stamped before the pull finished: its record, or its last progress
#       write, whichever is later.
#
#   The host's own record of its copy (the image's hosts in lv image ls,
#   which peers pull from and placement reads) is revived on the other hosts
#   only once the cluster upgrade has finished (lv cluster upgrade-status).
#   Before that the record reads deleted on every host, this one too once
#   anti-entropy runs, so no peer pulls the copy and placement does not see
#   it; the host logs this at WARN, and importing the image again after the
#   upgrade publishes the copy.
```

`pull` and `import` accept only standalone images. A qcow2 that names a
backing file or an external data file, and any VMDK (whose extents can name
other files), is refused, because qemu would open the named file on the host
for every VM built from the image. Flatten it first with
`qemu-img convert -O qcow2 <in> <out>`. A VM is also refused a new overlay on an
already-stored image that names another file.

## Import (migrate VMs in)

Import an existing VM from VMware (OVA/OVF) or Proxmox (qemu-server `.conf` or a
`vzdump` `.vma`). Disks are converted to qcow2 and the VM is defined **stopped**
(use `--start` to boot it). The source bus, SCSI controller model, firmware and
VLAN are preserved. A source with **Secure Boot** is imported with Secure Boot,
and a source with a **vTPM** gets a **fresh** vTPM — the source TPM secret is not
carried, so a BitLocker guest needs its recovery key on first boot (the new TPM
can't unseal the old volume). The import host must be Secure-Boot/vTPM capable
(see below).

```bash
lv import <file> --name <name> [--from auto|ova|ovf|proxmox|vma]
lv import win2022.ova --name win2022 --network br0 --start
lv import --from proxmox --server-path /srv/stage/100.conf --name app \
          --disk-map scsi0=/srv/stage/vm-100-disk-0.qcow2 --network br0
lv import dump.vma.zst --from vma --server-path /srv/stage/dump.vma.zst --name app --inspect
#   --net-map <foreign>=<bridge>   map a specific source network to a bridge
#   --preserve-mac                 keep source MACs (default: regenerate)
#   --server-path <path>           use a file/dir already staged on the target host
#   --inspect                      print the mapping + warnings, import nothing
#   Each disk lands as a NEW <vm>-<disk>.qcow2 in the target pool (or
#   <data_dir>/disks without one); an existing file of that name is refused
#   (AlreadyExists), never replaced.
```

`--server-path`, `--disk-map` and any disk a Proxmox `.conf` names must be
under the target host's import staging root (`<data_dir>/imports/staging`).
A path outside it needs an admin (`storage.hostpath` at the root). An import
forwarded with `--target-host` is judged on the target as its caller — by the
session the entry node relays, or as an admin when the caller signed in with
an admin certificate — so an admin's forwarded `--server-path` works and an
operator's is refused. Every file a foreign disk makes qemu open (backing
files, VMDK extents, a data file) must sit beside the disk or in the import
directory.

Disk formats: raw, qcow2, VMDK (a single-file sparse or stream-optimized
disk), VHD, VHDX and VDI, each read from its header when the source does not
declare it and converted with that format named, never probed. A differencing
VHDX or VDI depends on a parent and is refused; merge it into its base first.
QED and VMDK descriptors are refused; convert them to qcow2 first.

Several imports can run on one host at once. Before each write — an upload
(reserved 64 MiB at a time), unpacking an OVA, a VMA's device data as it
arrives, copying a mapped disk (its allocated blocks; the copy is sparse),
converting a disk into the pool (what `qemu-img measure` says the qcow2
needs, not the disk's capacity) — an import reserves the bytes it will write,
and is admitted only if that filesystem has room for them on top of what the
running imports writing to the same filesystem have reserved and its free space
does not yet show written. No margin is kept beyond that (unlike a cold
migration's headroom): an import that fits is imported, however full the
filesystem is otherwise, as before these checks existed. Imports into
unrelated storage do not count against each other; btrfs subvolumes, datasets
of one ZFS pool and exports of one NFS server (by address) count as one
filesystem, and one litevirt cannot identify counts as shared with every other.
A reservation shrinks as the filesystem's free space shows the import's writes,
and is released when it finishes or fails, so an import that does not fit
beside the others is refused with the space it needs and what the others hold;
retry it when they finish. Two imports of the same VM name on one host do not
run at once (`--inspect` is not held back), and an import never replaces a file
already at its disk's name in the pool. A file there is taken for a crashed
earlier import's leftover — moved aside to `<name>.orphan-<unix time>`, kept,
and logged, after which the import goes ahead — only when all of these hold:

- no disk (of a live VM, kept from a deleted one, or under a kept snapshot)
  and no image records it;
- no operation in flight (a create, clone, restore or disk attach) names a VM
  whose disks would be named like it, and no other import on the host does;
- it is a dead import's leftover (below), or both: no VM exists whose name
  followed by `-` begins the file's name, and it has not been modified in the
  last 15 minutes;
- no file beside it whose name begins like its own up to any `-` (so for
  `web-3-root.qcow2`, any `web-*` file), and no other host's conversion
  scratch file or partial copy for such a name, has been modified in the last 15 minutes —
  except files a disk row or an image records (a running VM's own disks, such
  as `web-1`'s beside an import of `web-3`, never hold it back), files named
  for an existing VM whose name does not begin the leftover's the same way,
  files of another import running on the same host under a name that does
  not begin the leftover's, and dead imports' leftovers (below).

**A dead import's leftover.** Every file an import writes into a pool is
recorded on its host, in `<data_dir>/import-placements/`: its path, which file
it is (its inode), and the size, modification time and (once placed) change
time it was left with, under the import and the daemon process that wrote it.
The device number is not part of it, so the record survives a reboot or a
remount of the pool. A file whose record names an import that is no longer
running on that host (the daemon stopped or restarted mid-import; an import
that ends drops its records), and which still has that inode, size and
times, is that import's leftover at once, without the 15-minute wait and
whatever VM it is named like. The record works on every filesystem, NFS
without user xattrs and FUSE included; where the pool keeps user xattrs, the
file also carries its origin in `user.litevirt.import-origin`, which must then
name the same import. A file written since its import left it — rewritten in
place by a replication into that path, say, even with its modification time
set back — is not a leftover by its record: it waits out the 15 minutes like
any file whose origin is unknown.

The record is the importing host's own. A re-import on another host into a
pool several hosts share (the first host is being drained, say) asks the other
hosts that have the pool, over their peer connection, whether their record
shows each file it cannot prove — the leftover and the fresh files beside it —
as their dead import's, in exactly the state it sees; it takes a file for a
leftover only on a yes. A host that does not answer within a few seconds
leaves the file judged by age, and the refusal names it. The default pool
(`<data_dir>/disks`) is each host's own and asks no one.

Any other file there refuses the import, saying why. On a pool with neither
hard links nor a rename that cannot replace a file (some FUSE filesystems), a
converted disk is copied into place: into a recorded temp name beside the
disk (`.<name>.place-<random>`), and only the finished copy takes the disk's
name, so a crash mid-copy leaves a partial at the temp name that the next
import of that name removes at once. That second copy is reserved like the
first, and a leftover there is moved aside to
`<name>.orphan-<unix time>-<random>`.

## Snapshots

```bash
lv snapshot create <vm> <name>            # disk-only (external qcow2 overlay)
lv snapshot create <vm> <name> --memory   # also capture guest RAM (live snapshot);
                                          # revert resumes the running VM at that instant.
                                          # Falls back to disk-only if the VM is stopped.
                                          # Refused for a VM holding a PCI passthrough
                                          # device (docs/pci-passthrough.md).
lv snapshot ls <vm>                       # TYPE column shows disk | memory
lv snapshot restore <vm> <name>           # repeatable; memory snapshots are host-local
lv snapshot rm <vm> <name>
```

`lv snapshot rm` lets libvirt merge the snapshot's overlay into the disk it
was taken of and remove the overlay; deleting the last disk-only snapshot of a
running VM does the same with a block commit of its own. A restore leaves the
restored snapshot libvirt's current one, which is what makes libvirt merge
rather than unlink. Two cases keep every file:

- the delete is **refused**, naming the VMs, while another VM (a linked clone)
  backs on the snapshot's overlay or on the disk it was taken of;
- a snapshot libvirt does not hold as current and that has no children — as
  a restore by an earlier build left one — is deleted as metadata only: the VM
  keeps its backing chain, and the space is not reclaimed;
- so is a snapshot libvirt cannot merge because its overlay is no longer in
  the VM's live chain. Restoring an older snapshot while a later one exists
  leaves the restored one so: its overlay file stays on disk, unused.

A metadata-only delete says so: `lv snapshot rm` prints a warning naming the
files it kept and their size, and the VM gets the event `snapshot.files-kept`
(`lv events <vm>`). Nothing is lost, and no `lv` command reclaims that space.

Restoring an older snapshot while a later one exists puts the VM on a new
overlay (`<disk>.<snapshot>-r<time>`) directly on the disk that snapshot was
taken of, in libvirt's definition and in the image headers alike. The later
snapshot's files are left as they were, outside the VM's chain, so it can
still be restored. Restoring the same snapshot again reuses that overlay.
Files left outside the chain this way are removed when the VM is deleted.

The refusal for a linked clone comes first, and applies to these metadata-only
deletes too.

`lv snapshot restore` empties the VM's live overlay and starts the VM on it,
so it is refused, naming the VMs, while another VM (a linked clone) backs on
one of the VM's live disk files. A clone of the disk the snapshot was taken of
does not stop it: a restore only reads that disk. When libvirt will not take
the restored snapshot back as its current one, the restore still succeeds,
but `lv` prints a warning and the VM gets a `snapshot.restore-not-current`
event: deleting that snapshot later keeps its files rather than merging them.

A restore holds the VM's start lease while it brings the domain down and back,
so no start path restarts it midway; it is refused while a live start holds
it. A lease with no live holder behind it — taken by this host before its
daemon last started, or held by a host that is no longer an active member — is
taken over instead.

## Memory ballooning

```bash
# Set min/max at create time (compose: min-memory / max-memory):
lv run --name web --image ubuntu --memory 2048 --min-mem 1024 --max-mem 4096
lv set-memory <vm> <MiB>                   # live balloon target, within [min, max]
```

## Memory hot-add and USB passthrough

```bash
# virtio-mem: boot with 2 GiB, raise live up to 16 GiB
lv run --name db --image ubuntu --memory 2048 --memory-hotplug-max 16384
lv set-memory db 8192                      # plug 6 GiB into the running guest
lv update db --memory 4096                 # the same, through update

# USB: raw devices bind the VM to its host (pin it); a mapping follows the VM
lv run --name pos --image ubuntu --host node-1 --usb 046d:c52b --usb-port 1-2
lv mapping create dongle && lv mapping add-device dongle usb:096e:0006 --host node-1
lv run --name lic --image ubuntu --usb-mapping dongle
lv update lic --clear-usb                  # stopped, or --restart-if-needed
```

See docs/passthrough.md.

## Resource mappings (cluster-wide passthrough device aliases)

```bash
lv mapping create <name> [--description <text>]
lv mapping add-device <name> <address> [--host <h>] [--vendor <v>] [--device <d>]
                                           # address: a PCI address, or usb:<vendor>:<product>
                                           # / usb:<bus>-<port> (a mapping is PCI or USB)
lv mapping rm-device <name> <address> [--host <h>]
lv mapping ls
lv mapping rm <name>
# Reference from a VM: `lv run … ` device spec / compose `devices: [{mapping: <name>}]`
```

## Boot ordering

```bash
lv run … --onboot --startup-order 10 --start-delay 5 --stop-delay 0
# onboot VMs start in startup-order on host boot (not on a plain daemon restart),
# including one its operator stopped before the reboot.

lv host shutdown-workloads <host>
# Gracefully stop every running VM on a host in REVERSE startup-order (highest
# startup-order first), honoring each VM's ACPI stop-grace-period and waiting its
# --stop-delay before moving to the next VM. This is the ONLY thing that consumes
# --stop-delay. It is an explicit operator action for an orderly host shutdown —
# a normal daemon restart/upgrade leaves VMs running and does NOT trigger it.
```

## Restart policy

```bash
lv run … --restart on-failure --restart-max-attempts 5 --restart-delay 5s --restart-window 1h
# Auto-restart a VM that stops UNEXPECTEDLY (crash, fence/external destroy).
# A clean guest shutdown or an `lv stop` always sticks — under `on-failure` AND
# `always` (the guest-stick rule). Default is `none` (opt-in). See docs/compose.md
# "Restart policy" for the full reason→action matrix and the container caveat.
```

## Notifications

```bash
lv notify target add --name ops-slack --type slack --url <incoming-webhook-url>
lv notify target add --name ops-hook --type webhook --url <url>
lv notify target add --name ops-mail --type email --smtp-host smtp.example.com \
    --smtp-user lv@example.com --smtp-password-file /root/smtp.pw \
    --from litevirt@example.com --to ops@example.com --to oncall@example.com
lv notify target ls
lv notify route add --pattern "backup.*" --target <target-id> --min-severity error
lv notify route add --pattern "*" --target <target-id> --min-severity warn
lv notify route ls
lv notify test <target-id>
lv notify route rm <id>
lv notify target rm <id>
# Events: backup.failed, host.fenced, host.recovery.stalled, replication.failed, quota.exceeded. See notifications.md.
```

## Web UI certificate (ACME, custom)

```bash
lv acme status [host]   # show the TLS cert the UI is serving (subject/issuer/SANs/expiry)
# Configure under `acme:` in the daemon config (http-01 or dns-01); see configuration.md.
lv host ui-cert set <host> --cert chain.pem --key key.pem [--name <fqdn>]...
                        # install a corporate-PKI certificate for the UI: validated
                        #   (key, chain order, expiry, names), key 0600, served at once
lv host ui-cert clear <host>   # back to ACME / the cluster certificate / plain HTTP (ui_tls)
```

## Backups

```bash
# Repository management (host-local)
lv backup repo init <path> [--encrypted --key-file <file>] [--compression zstd|none] [--force]
#   Default: a local, uncompressed repo, as on every release. zstd (feature
#   backup_zstd) is explicit, and refused until the cluster's release token
#   has latched. zstd marks the repo schema 2, which releases
#   without backup compression refuse to open; --force allows it before the
#   latch, locally, for a repo no older host reads. Without --force a zstd
#   repo is created by the connected host's daemon (release feature gate), so
#   <path> is a path on that host, which the command prints.
lv backup repo set-compression <path> zstd|none [--force]   # for chunks written from now on; zstd gated as above
lv backup repo ls <path>
lv backup repo verify <path>
lv backup repo gc <path>
lv backup repo prune <path> [--keep-{last,daily,weekly,monthly,yearly} N] [--apply]
lv backup repo sync <src> <dst>

# Schedule management (cron-driven). Scope is inferred from --pool/--project
# when --scope is omitted; with neither, pass a <vm> arg or --scope cluster.
lv backup schedule add <vm> --repo <name> --cron "0 2 * * *" [--keep-* N]   # per-VM
lv backup schedule add --pool <pool> --repo <name> --cron "..."            # per-pool fan-out
lv backup schedule add --project <name> --repo <name> --cron "..."         # per-project
lv backup schedule add --scope cluster --repo <name> --cron "..."          # every VM
lv backup schedule ls
lv backup schedule rm [vm] --repo <repo> [--scope vm|pool|project|cluster] [--pool <p>] [--project <p>]

# Push / restore via the daemon
lv backup snapshot <vm> --repo <path> [--disk <name>] [--incremental] [--quiesce auto|off] [--bwlimit <rate>]
#   --bwlimit 50MiB: cap this backup's read (and remote send) rate, per second;
#   the repo's backup_bwlimits limit still applies, and the lower one wins.
#   --quiesce auto (default): freeze guest filesystems via the qemu-guest-agent for an
#   application-consistent backup when the VM has an agent, else crash-consistent.
#   --quiesce off: always crash-consistent. A freeze failure never fails the backup.
lv backup restore-from --repo <p> --vm <v> --disk <d> --timestamp <ts>
# Single files, read inside a throwaway restore VM (never mounted on the host):
lv backup file-ls --repo <r> --vm <v>|--ct <c> --timestamp <ts> [--disk <d>] [/<volume>/<dir>]
lv backup file-restore --repo <r> --vm <v>|--ct <c> --timestamp <ts> [--disk <d>] <path>... -o <archive.tar|-> [--max-bytes <size>]
  [--in-place]        # restore over the VM's own disk from its record (VM stopped)
  [--target-path <f>] # admin only; never an existing file but the VM's own disk (then as --in-place). Default: a new daemon-named file
lv backup restore-live --repo <p> --vm <v> --disk <d> \
    --timestamp <ts> [--target-path <overlay.qcow2>] [--bind 127.0.0.1:0]
  [--auto-start]      # define + start the VM against the overlay automatically
  [--name <new>]      # rename the restored VM (avoids collision with the original)
  [--blockpull]       # after start, localize the disk then tear down the NBD server
  [--from-existing]   # fall back to an existing vms record for the VM spec
  [--without-devices] # with --auto-start: start without the backup's PCI devices (dropped from the spec, audited)

# Aliases: `lv backup create` is `lv backup snapshot`, `lv backup restore` is `lv backup restore-from`
lv backup create <vm> --repo <path> [flags as snapshot]
lv backup restore --repo <p> --vm <v> --disk <d> --timestamp <ts> [flags as restore-from]
```

## Replication

```bash
# Cron-driven volume replication to a target pool/host.
lv replication schedule add <vm> --target-pool <pool> --cron "0 */4 * * *"
  [--target-host <host>]   # explicit destination (else shared-pool / auto-selected peer)
  [--keep N]               # keep N newest replicas (0 = keep all)
  [--incremental]          # transfer only dirty extents (raw replicas)
  [--auto-promote]         # failover may promote the freshest replica on host loss
  [--disabled]             # create the schedule disabled
  [--scope vm|pool|cluster|project|container] [--pool-name <p>] [--project-name <p>]
  [--container]            # a container: --target-host is the peer, --target-pool the backup repo on it
  [--bwlimit <rate>]       # per-schedule bandwidth limit, shared by its runs on a host (e.g. 50MiB); 0 removes it, absent keeps it
lv replication schedule ls # RATE column: the limit, "-" for none
lv replication schedule rm <vm> --target-pool <pool> [--scope ...] [--container] [--pool-name <p>] [--project-name <p>]

# A container's replicas on its replica host; restore one, or remove set-aside/orphaned ones (admin).
lv replication replicas <container> --target-pool <repo> [--host <h>] [--project-name <p>]
  [--restore <timestamp>]  # lay that replica down as the container, stopped (never a second copy)
  [--remove <timestamp>]   # a SET-ASIDE or ORPHANED replica to remove (repeatable; asks first)
  [--yes]                  # remove without asking

# Incremental-replication checkpoint rows (the anchor of each VM's chain into a pool).
lv replication checkpoints ls [--vm <vm>]                # IN USE: a live schedule uses it; VM DELETED: the VM has no live row
lv replication checkpoints rm <vm> --target-pool <pool>  # Admin, audited: refused while a live schedule uses it; run on the VM's host, which drops its bitmap (printed); the next run is a full copy

# Disaster recovery: bring a VM up from its replica.
lv replication promote <vm>
  [--pool <p>] [--host <h>]   # where the replica lives (default: from the VM's schedule)
  [--replica <file>]          # one of the VM's recorded replicas, <disk>-<time>.<ext> (default: newest)
  [--new-name <name>]         # promote alongside a still-running original
  [--no-localize]             # boot off an overlay backed by the replica (fast; pins it)
  [--force]                   # promote even if the original's host is not proven fenced or removed
  [--accept-not-point-in-time] # promote a replica recorded as not point-in-time (a -U copy of a running disk)
```

## Clones and templates

```bash
lv template <vm> [--revert]        # Convert a stopped VM to a clone template (or revert)
lv clone <source> <new-name>       # Clone a template or stopped VM into a new VM
  [--mode auto|linked|full]        # auto (default): linked on shared storage, full on local
  [--project <name>]               # tenancy project for the clone (default: source's)
  [--ip <ip>]                      # static IP for the clone's first NIC (default: DHCP)
  [--start]                        # start the clone after creation
  [--snapshot <name>]              # clone from this snapshot of the source
  [--host <host>]                  # end up on another host: a full copy, moved there like `migrate --cold`
  [--pool <pool>]                  # put the clone's disks in this file-based pool on that host
```

`--host` makes the clone where the source's disks are, as a full copy (a linked
clone cannot span hosts), then moves it to the host as `lv migrate <vm> <host>
--cold` moves a stopped VM: its disks stream over the cluster's mTLS connection
with a checksum, its domain is defined there, and the staged copy is removed
once the handoff commits. The source host therefore needs room for the copy
while it travels. `--pool` puts the disks in a pool: directly on the source's
host, or, on another host, by a move-volume after the move. The caller needs the
clone's permissions and the project must be allowed to use the pool; a clone on
another host also needs `vm.migrate` and `vm.delete` on the new VM, `vm.move` for
a pool there and `vm.start` for `--start`. All are checked as you, before any
copy starts. The staged copy is admitted against the source host's free space
with the same headroom a cold migration leaves, and refused if it would take the
filesystem that holds running guests' disks that close to full. A request that
entered at another node is carried to the source host with your identity; where
forwarded identity is not enforced it is refused rather than run as a cluster
peer. If the move fails, the staged copy is removed and nothing is left behind (a
crash of the source host's daemon between staging and the move leaves the staged
clone as a complete stopped VM there, whose events show `vm.clone.staged` without
`vm.clone.moved`; `lv rm` removes it); the staged copy and a copy into a pool
are admitted for space with headroom, a same-host clone is as it always was;
if the move succeeded and a later step (the pool, the start) fails, the VM is
complete on its host and the error names the command that finishes the job
(`lv move-volume`, `lv start`).

## GitOps

```bash
lv gitops --repo <url>             # Reconcile a Git repo of compose YAMLs into the cluster
  [--branch main]                  # branch to track
  [--local-dir <path>]             # working-tree location
  [--compose-glob '**/compose.yaml']
  [--poll 60s]                     # polling interval (0s disables polling)
  [--webhook-bind 127.0.0.1:7700]  # reconcile webhook listener (empty = disabled)
```

See `docs/gitops.md` for the controller model.

## Load balancers

```bash
lv lb ls                                          # List load balancers
lv lb inspect <name>                              # LB details + backends (real HAProxy health; state=degraded if VIP unassigned)
lv lb create <name> --vip <cidr> --port <l:t/proto> --backend <name=addr>
  --algorithm roundrobin     # roundrobin | leastconn | source
  --host <name>              # Hosts to run LB on (repeatable)
  --vm-backend <vm-name>     # Use VM IP as backend (repeatable)
  --snat                     # SNAT a host-isolated network's outbound guest traffic to the VIP (default off)
lv lb update <name> [flags]                       # Update config (zero-downtime)
lv lb update <name> --snat=false                  # Turn an explicit LB's outbound SNAT off (--snat turns it on)
lv lb delete <name>
lv lb stats <name>                                # Live backend metrics
lv lb drain <name> --backend <vm>                 # Graceful drain
lv lb disable <lb> --backend <vm>                 # Hard disable
lv lb enable <lb> --backend <vm>                  # Re-enable
```

## Capacity and overcommit

```bash
# Per-host overrides (cluster defaults come from `capacity:` in the daemon config)
lv host config node-1 --cpu-overcommit 2.0     # 0 = inherit the cluster default
lv host config node-1 --mem-overcommit 1.5     # only with ballooning/KSM/swap behind it
lv host config node-1 --mem-reserve 2048       # MiB held back for the host; negative = inherit
lv host config node-1 --cpu-reserve 2          # vCPUs held back; negative = inherit

# Deliberate density for one VM — skips the HOST capacity check, audited.
# Project quota still applies. Available on both create and start, because
# starting a stopped VM is when its memory is actually consumed.
lv run    --name db --image ubuntu --memory 4096 --host node-1 --allow-overcommit
lv start  db --allow-overcommit
lv update db --memory 8192 --restart-if-needed --allow-overcommit
```

A `--mem-reserve 0` is a real setting meaning "hand guests every last MiB", which
is why *inherit* is a negative value rather than zero. Placement and admission use
the same numbers, so a pinned `--host` create is checked exactly like a resize.

## Hot-plug (attach/detach)

**Requires `enforcement.operation_protocol`.** These commands are journaled and
at-most-once, and refuse while the `operation_protocol_v1` capability is
inactive — which is the default:

```
Error: attach disk: disk attach requires the operation_protocol_v1 capability to be active
```

The capability activates only once **every** node has `enforcement.operation_protocol: true`
and the token has latched cluster-wide, so enabling it on one host changes nothing.
See docs/configuration.md.

```bash
lv hardware-ls <vm>                               # List a VM's disks/NICs/PCI devices
lv attach-disk <vm> <disk> --size 50G [--bus virtio]
lv detach-disk <vm> <disk>
lv attach-nic <vm> <network> [--model virtio] [--mac ...] [--spoof-guard on|off] [--allow-address <ip>]
lv detach-nic <vm> <mac>
lv attach-pci <vm> --type gpu [--vendor 10de] [--count 1] [--sriov]
lv attach-pci <vm> --address <pci-address>   # one device; also a stopped VM once hardware_v2 is active
lv detach-pci <vm> <pci-address>
```

`lv attach-nic` sets no MTU. Give an attached NIC one with
`lv update <vm> --nic-mtu <nic>=<MTU|bridge>` ([networking](networking.md#per-nic-mtu)).

`lv detach-disk` removes the disk from the VM but **keeps its file**, on the
host the VM was running on when it was detached. A migration does not move a
detached disk: it stays on that host. The file is freed when the VM is deleted
— `lv rm <vm>` asks each host the VM left to remove the disks detached there
and the VM's `vms/<name>/owner_epoch` marker. The deleting host names only the
disks detached from this VM since it was created; nothing else can make that
request (it is refused for every user, admin included). The host holding the
file still keeps it if anything uses it: another VM's disk or backing image, a
domain defined on that host, or a snapshot of the VM. `lv rm --keep-disks`
keeps detached disks too. A host that is `active` or `draining` is asked. One
that is down, in `maintenance` or otherwise out of service during the delete
keeps its copy of a detached disk; remove it by hand
(`<data_dir>/disks/<vm>-<disk>.qcow2`). Its `vms/<name>/owner_epoch` marker it
removes itself when it is next `active` (at a daemon start, once its replica
has caught up with a peer, or after `lv host undrain`), if its own records
show the VM deleted and no domain of that name is defined there.

## Users and tokens

```bash
lv user create <username> --role admin|operator|viewer
lv user ls
lv user delete <username>             # Revokes its sessions and API tokens in the same write
lv user delete <username> --exact     # List the accounts named like <username> (case-duplicates) with ids; deletes nothing
lv user delete <username> --exact --id <id>   # Delete the one chosen by id (admin, audited)
lv user unbind <username> <realm>     # Clear an LDAP/OIDC account's directory bindings (all of them, a conflict too); next login binds afresh (admin)
lv user passwd [username]           # Change your own password (or, as admin, another user's)
  [--old-password <p>] [--new-password <p>]   # prompts if unset; old not needed for an admin reset
lv user token-create <username> <token-name> [--expires <RFC3339>]
  [--scope-path <path>] ...        # Repeatable; intersect with role bindings
lv user token-revoke <token-id>
lv user reset-admin                # As root on a node: reset the EXISTING admin password (does not create one); audited as user.reset-admin
                                   # It also re-enables a disabled or expired admin account, and logs it out everywhere
lv user reset-admin --clear-2fa    # Also remove the admin's second factors and print an enrollment code
lv user reset-admin --user <name>  # Reset another admin-role account, e.g. the one the admin floor reinstated with no credential
lv user disable <username>         # No login; sessions ended, sessions and API tokens refused (admin)
lv user enable <username>          # Re-enable; API tokens work again, ended sessions stay ended (admin)
lv user expire <username> <RFC3339|never>   # Stop authenticating at that instant; "never" clears it (admin)
```

`lv user ls` shows each account's STATUS (`active`, `disabled`, `expired`) and
EXPIRES. Disable and expiry are refused for the last admin that can log in,
enabled with no expiry, and until the cluster upgrade has finished (the release feature
`login_policy`; `lv cluster upgrade-status`). See
`docs/auth.md`, "Account lifecycle".

## Roles (path-based RBAC)

```bash
lv role grant <role> <principal> --path <path> [--propagate]
lv role revoke <binding-id>
lv role ls [--principal user:alice@local] [--role <role>]
```

Principals are `user:<name>@<realm>` (a local account is `user:<name>@local`),
`group:<role>@<realm>` (a legacy role), or a directory group
`group:<realm>/<group>` (an LDAP group is its DN). Callers are matched as
`user:<name>@<realm>`, so a bare `user:<name>` would grant nothing: `lv role
grant` and the web UI refuse it, and warn if an older daemon stored one anyway. Paths are RBAC
scopes (`/`, `/projects/acme`, `/projects/acme/vms/web-1`). See
`docs/auth.md` for the role catalog and propagation semantics.

A cluster admin may grant anything anywhere. A caller holding `perm.modify`
at a path (the `PermissionAdmin` role) may grant and revoke there and below,
never a role carrying a verb it does not itself hold there, never a
principal's first binding or last. See `docs/auth.md`, "Delegated
administration".

## Projects (tenancy)

```bash
lv project create <name> [--display "..."] [--parent <name>]
lv project ls
lv project rm <name>
lv project quota <name> --vcpu N --mem N --disk N \
    --nics N --ips N --backup N
  # --mem is MiB; --disk/--backup are GiB; --ips is the public-IP count; 0 = unbounded
lv project usage <name>
```

Hierarchical names like `/acme/team-foo`. Admission gates VM creation on
all six quota dimensions. See `docs/tenancy.md`.

## Security groups and firewall

```bash
lv sg create <name> [--project <p>]   # --project: owned by p; only p's workloads may bind it
lv sg ls [--project <p>]              # --project: p's groups and the global ones
lv sg rm <id>
lv sg rule-add <sg-id-or-name> --direction ingress|egress --proto tcp \
    --port <p> --cidr <c> [--action accept|drop|reject] [--priority N] [--log]
lv sg rule-add <sg-id-or-name> --macro <name> [--cidr <c>] [--direction ingress|egress] \
    [--action accept|drop|reject] [--priority N] [--log]    # one rule per macro row; prints every id
lv sg rule-ls <sg-id-or-name>
lv sg rule-rm <rule-id>       # Takes the RULE id from rule-ls, not the group id
lv sg bind <vm> --network <name> --sg <name> [--sg <name>...]   # Bind SGs to a VM NIC
  # --network matches the compose network name on the NIC; --sg is repeatable
  # (an empty --sg list clears the bindings).
  # create/rm/rule-add/rule-rm go through the daemon: they need sg.write and
  # each leaves an sg.* audit row (see docs/firewall.md#audit-trail).
  # rule-add takes a group id or name. A name no group has is NotFound; a name
  # two groups hold is refused (use the id). rule-ls takes either too; for a
  # name two groups hold it lists every group's rules, labelled by group id.
  # Rules an older client stored under a group's NAME are read as that group's
  # own while the name is unique, and are removed with the group. While two
  # groups share the name those rules apply to neither: `lv sg ls` and
  # `lv sg rule-ls` warn, and the firewall reconciler logs it once per rule.
  # Deleting either group removes them (the sg.rm audit row records them).

lv firewall macros            # List the rule macros and their rows
lv firewall show              # Render the live nft ruleset for this host
lv firewall reload            # Force the reconciler to re-read state and apply now

# Cluster-tier rules (apply to every NIC on every host):
lv firewall cluster-rule add --direction ingress|egress --proto tcp \
    --port <p> --cidr <c> [--action accept|drop|reject] [--comment <s>] [--priority N] [--log]
lv firewall cluster-rule add --macro <name> [--direction ...] [--cidr <c>] [--action ...] [--comment <s>] [--log]
lv firewall cluster-rule ls
lv firewall cluster-rule rm <id>

# Host-tier rules (apply to every NIC on one host):
lv firewall host-rule add --host <name> --direction ingress|egress --proto tcp \
    --port <p> --cidr <c> [--action accept|drop|reject] [--comment <s>] [--priority N] [--log]
lv firewall host-rule add --host <name> --macro <name> [--direction ...] [--cidr <c>] [--action ...] [--comment <s>] [--log]
lv firewall host-rule ls [--host <name>]
lv firewall host-rule rm <id>

# Named CIDR lists (reference from a rule with --cidr @<name>):
lv firewall ipset add <name> --cidr <c> [--cidr <c> ...]   # --cidr repeatable
lv firewall ipset ls
lv firewall ipset rm <id>

# Default forward policy (deny = drop anything not explicitly accepted):
lv firewall default-deny <on|off> [--scope <host>]   # no --scope = cluster-wide
  # --scope names a host lv host ls shows (an unknown name is refused). A host named
  # cluster cannot have its own default-deny: --scope cluster is then refused.

# NIC guards (anti-spoofing). New NICs are guarded by default; relaxing one
# needs network.update on its network. --allow replaces the list (repeatable).
lv firewall nic-guard set <vm> --network <net>|--mac <mac> --mode on|off \
    [--allow <ip-or-cidr>] [--allow-dhcp-server] [--allow-router-advertisement] [--allow-vlan-tags]
lv firewall nic-guard set --container <ct> --host <host> --network <net> --mode on|off
lv firewall nic-guard ls [<vm>]   # VM NICs, then container NICs
lv firewall nic-guard resume <vm> # let a VM held paused for its guards run, guards in force first

# Per-NIC enforcement: an upgraded cluster observes (counts would-drops) until enforced.
lv firewall enforce status          # mode per host + would-drop totals per workload, NIC and rule, since <time>
lv firewall enforce on              # enforce (admin, audited); off = observe
lv firewall enforce reset-counters  # restart every host's would-drop totals from now (admin, audited)

# Logging (docs/firewall.md, "Logging"). --log on a rule-add logs each packet the rule
# matches; rule ls shows such a rule's action as "<verdict> log". lv asks the daemon first
# and refuses --log against one that predates logging; an --action holding "+" is refused.
lv firewall log-policy status                                          # the cluster's policy, then each host's
lv firewall log-policy on  [--scope <host>] [--rate N] [--burst N]     # log each NIC's default verdict
lv firewall log-policy off [--scope <host>] [--rate N] [--burst N]     # logged rules still log
lv firewall log-policy inherit --scope <host>                           # clear a host's own policy
lv firewall log [--host <h>] [--workload <name>] [--since 15m] [--limit 200] [--follow]
  # TIME HOST WORKLOAD DEVICE SIDE RULE VERDICT PROTO SRC DST LEN, merged by time across every
  # active host (a host that does not answer is named on stderr); --follow polls from each
  # host's newest sequence. Needs firewall.log.view at / (Admin; docs/auth.md).
  # --rate is log records per second per guest NIC side (1-10000, default 5); --burst is
  # packets (1-10000, default 10). Every logged line of one NIC side shares that budget.
  # Role operator; audited as firewall.log_policy; refused until the cluster upgrade has finished.
  # --scope names a host, a host named "cluster" included; leave it out for the cluster-wide
  # policy. status shows a row the daemon cannot read, or a host inheriting one, as
  # "unreadable (read as off at 5/10)"; the API returns such a row with rate 0 and burst 0.

# Firewall tags: per-workload key/value pairs, kept apart from labels (sg.write to change; audited).
lv firewall tag set <vm> <key>=<value>...                          # adds or replaces keys
lv firewall tag set <ct> --container [--host <host>] <key>=<value>...
lv firewall tag rm <vm> <key>...                                   # --container [--host <host>] for a container
lv firewall tag ls [<workload>] [--container [--host <host>]]      # every tagged workload, or one

# Tag groups: selectors over firewall tags; reference one from a rule with --cidr tag:<group>
# (sg.write to change; audited; refused until the cluster upgrade has finished).
lv firewall tag-group set <name> --match <k>=<v> [--match <k>] [--sg <sg>] [--network <net>]   # upsert; matches are ANDed
lv firewall tag-group ls [--members]   # --members: each member's allocated addresses, or "no allocated address"
lv firewall tag-group rm <name> [--force]
  # rm is refused while a rule references tag:<name>, the group binds security groups to a
  # member's NICs, or its row cannot be read; --force overrides accept rules and the binding, never a drop or reject rule.
  # set is refused for a name ending in _v6, beside a group <name>_v6, over an ip set named
  # lv_tg_<name> or lv_tg_<name>_v6, for an --sg or --network that does not exist (or an --sg name
  # two groups hold), and for --match k= or a key matched twice. rm also asks --force while a
  # workload whose tags cannot be read sits on a network the group binds. lv asks the daemon
  # before sending a tag: cidr (a rule, a compose file, or a gitops file that may hold one) and
  # refuses unless the daemon shows it knows tag groups.
  # A member leaving a group does not cut its open connections (docs/firewall.md, "Tag groups").

# SYN-flood protection on guest NICs (docs/firewall.md, "SYN-flood protection")
lv firewall synflood status                     # cluster policy, then per host: policy, in force (on/ipv4-only/ipv6-only/observe/guards-only/no-guest-nics/unavailable/off/predates), rate, burst, drops v4/v6 since its last reload
lv firewall synflood on [--rate 200] [--burst 1000] [--scope <host>]   # no --scope = cluster-wide
lv firewall synflood off [--scope <host>]
lv firewall synflood inherit --scope <host>     # clear a host's own policy; the cluster's applies
  # on, off and inherit need the operator role, are audited (firewall.synflood) and are refused
  # until the cluster upgrade has finished. --rate is new SYNs per second per guest NIC and source
  # address, --burst packets; each 1-100000.
```

See `docs/firewall.md` for the three-tier model, where each tier is enforced
(the `bridge litevirt-nic` table), IPv6 rules and NIC guards.

## Audit log

```bash
lv audit ls [--limit N] \
    [--target <path>] [--action <a>] [--user <u>] [--since <time>] [--until <time>]   # Tail/filter recent audit entries
  #   --action supports a trailing-* prefix glob (e.g. sg.*)
lv audit verify                                # Walk the SHA-256 hash chain
lv audit export [--since <time>] [--until <time>] [--out audit.json] [--allow-gaps]   # Export WORM-ready JSON
  #   --allow-gaps exports a chain with seq gaps, listed under seq_gaps (investigation, not attestation)
```

See `docs/audit-log.md` for the chain semantics.

## Monitoring

```bash
lv health [--resolved]                       # Cluster health: overall state, active conditions,
                                             #   evaluator coverage, connectivity, capacity.
                                             #   --resolved includes the 30-day resolved history.
                                             #   Exit code: 0 healthy · 1 degraded/unknown · 2 critical.
lv health resolve <code> <kind>/<id> [--reason R] [--evaluator E] [--accept PATH] [--force]
                                             # Resolve one open dual-run condition by hand, named as
                                             #   `lv health` prints it. Admin (cluster.health.resolve),
                                             #   audited, ha.condition.resolved event. Refused until a
                                             #   detector scan after its last sighting probed every host
                                             #   it names; raised again next pass if it still holds.
                                             #   Also vm.move_unresolved (an unresolved volume move),
                                             #   with --reason: on the host holding its record, or once
                                             #   that host is proven powered off. --accept PATH points
                                             #   a disk record at one of its move's two files first, on
                                             #   the VM's owner; once per disk, and required for a
                                             #   move with no pivot recorded unless the holder owns
                                             #   the VM and its config and record name the source.
                                             #   On the owner the domain's config must name each file
                                             #   kept, and a running domain's record is not changed.
                                             #   After a pivot only the copy is accepted, unless the VM
                                             #   changed hands since the move began (a forked
                                             #   history, on the owner): a record, and a shut-off
                                             #   domain's config, on the copy are pointed at the
                                             #   source; refused while the file not kept was
                                             #   modified later, unless --force.
                                             #   `lv health` lists the moves first (docs/diagnostics.md).
lv health resolve nvram_flush_failed host/<host> --accept-stale-uefi-vars --reason R
                                             # Accept that the UEFI vars stores nvram_flush_failed names
                                             #   may be stale, for a VM kept as it is. Admin, audited
                                             #   naming every file; a new failed flush raises it again.
lv audit ls [--limit N] [--target T] [--action A] [--user U] [--since <time>] [--until <time>]   # Audit log (default 50 entries)
lv host stats <host>                         # Host resource statistics
lv stats <vm>                                # VM resource statistics
```

## Cluster diagnostics

```bash
lv doctor divergence [--json] [--table <name>]... [--include-sensitive]   # Report replicated rows that disagree across nodes (read-only)
lv doctor repair-owner <vm> <host>           # Re-assert a VM's owner on the host that actually runs it (audited)
lv doctor fence                              # Report whether a shared-disk VM's cross-host transfer would be fenced and whether every host enforces recovery claims (read-only)
lv doctor privileged-containers              # Report privileged or legacy-confined containers (read-only)
lv doctor firmware-move <vm> [--json]        # Show a live firmware migration's records on every host, with every hash and path (read-only)
lv doctor firmware-move <vm> --accept-target | --reverify | --adopt-target-copy | --discard-target [--stop-target]
lv doctor firmware-move <vm> --adopt-target-copy --acknowledge-rollback   # keep a leftover as the VM's own (older state)
lv doctor firmware-move <vm> --accept-source [--acknowledge-rollback] [--stop-target]
lv doctor firmware-move <vm> --confirm-target-nvram --accept-nvram-hash=<sha256>
lv doctor firmware-move <vm> --push-source-nvram [--acknowledge-rollback] [--stop-target]
lv doctor firmware-move <vm> --resolve unverified|quarantine
                                             # Resolve a parked live firmware move (admin, vm.firmware-move; audited)
lv doctor migration-tls [--json]             # Show every host's migration credentials and when they expire (read-only)
```

`divergence` is read-only, and lists a lease-term tie that every host has
acknowledged as `acknowledged_tie`, not as a divergence. `repair-owner` is an
audited, admin-gated repair for an equal-timestamp ownership split a stationary VM can't self-heal. Most ownership
splits are reclaimed automatically by the runtime-repair reconcilers — see
`docs/diagnostics.md` for the full model (categories, metrics, alerts, and the
operational repair flow).

`firmware-move` resolves a live Secure Boot / vTPM migration that parked, on
the host whose record it acts on, by the move's state: see
[Live firmware migration](diagnostics.md#live-firmware-migration-firmware_migration_)
for which action takes which state. It refuses an action the state has no row
for. `--acknowledge-rollback` is required where the source's copy may be older
than the target's.

`migration-tls` is read-only. It prints one row per host — HOST, STATUS,
TRUSTS (the migration CAs it trusts), CERT FROM (which CA issued its
certificate), EXPIRES — and exits non-zero when a host is unreachable, holds a
set its daemon would refuse to install, expires within 90 days, falls back to
plaintext (`migration.allow_unencrypted_storage`), or trusts a different CA
set from its peers while no rotation (`lv host rotate-migration-ca`) is running from this machine.

## Ansible integration

```bash
lv ansible-inventory --list     # JSON inventory for Ansible
lv ansible-inventory --host <ip>
```

## Uninstall

```bash
lv uninstall <user@host> --confirmed              # Remove litevirt from host
lv uninstall <user@host> --confirmed --keep-data  # Keep VM images and disks
```
