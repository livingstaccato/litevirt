# Installation

## Prerequisites

Each host needs:

- Linux (x86_64) with KVM support (`/dev/kvm` must exist)
- QEMU/KVM and libvirt installed (`apt install qemu-system-x86 libvirt-daemon-system`)
- `genisoimage` for cloud-init ISO generation
- SSH access (`lv host init root@<ip>` uses it to install the host)

Optional:

- `haproxy` and `keepalived` for load balancing
- `socat` for HAProxy runtime API
- `conntrackd` for stateful SNAT failover (used when `snat: true` on load balancers)
- `nftables` for host isolation and SNAT rules
- IOMMU enabled in BIOS/kernel for PCI passthrough

## Build from source

```bash
git clone https://github.com/litevirt/litevirt.git
cd litevirt
make build
```

This produces a single static binary (no CGO, no runtime dependencies):

- `bin/litevirt` — the whole platform. `litevirt daemon` runs the server;
  `litevirt <cmd>` is the CLI; `litevirt schema-migrate <db>` pre-stages schema.
- `bin/lv` — a convenience symlink to `litevirt` (so `lv <cmd>` keeps working).

Requires Go 1.26+. Install Go from https://go.dev/dl/ if needed.

## Standalone single-node setup

The fastest way to get started — run everything on one machine:

```bash
sudo cp bin/litevirt /usr/local/bin/
sudo ln -sf /usr/local/bin/litevirt /usr/local/bin/lv
sudo litevirt host init --local --name node-1
```

This generates the PKI, installs dependencies (libvirt, QEMU), writes the config, and sets up the systemd unit — all locally, no SSH needed. It also enables and starts `litevirt.service`, and says so; there is nothing more to start.

```bash
export LV_HOST=root@127.0.0.1
lv status
```

## Bootstrap a remote host

1. Copy the daemon binary to the host:

```bash
scp bin/litevirt root@10.0.50.10:/usr/local/bin/
```

2. Initialize the cluster from your workstation:

```bash
export LV_HOST=root@10.0.50.10
lv host init root@10.0.50.10 --name host-a
```

This generates the cluster PKI (CA + host certificate), creates `/etc/litevirt/config.yaml`, and installs, enables and starts the systemd unit.

`lv host init` is for the first host only. It refuses a target that is already a
member: one whose `join_peers` lists peers, or one whose address the cluster this
CLI is configured for lists beside other hosts. The second check is what catches
the first host itself, whose `join_peers` stays empty when later hosts are added
from a workstation. A member that lost its disk is removed with `lv host rm` and
added back with `lv host add`. It also refuses a target holding another
cluster's state, as `lv host add` does (see [Add hosts to the cluster](#add-hosts-to-the-cluster)),
and `--force` does not override that check.

3. Verify the cluster is running:

```bash
lv status
```

### The first admin password

The cluster's admin account is created exactly once, by the node that founds it.
`lv host init` (remote or `--local`) writes a founder marker,
`/var/lib/litevirt/genesis-pending`, but only while that data directory holds no
`state.db` and no capability latches (`split_brain_activated.*`, which a daemon
writes once it has run as a member and which survive losing `state.db`). On its first start the daemon creates the `admin` account, writes the
password to `/etc/litevirt/admin-password` (mode 0600) on that node only, and
deletes the marker.

No other node creates an admin. A node added with `lv host add` gets the account
by replication, and has no password file. A node re-initialised with
`lv host init` after its daemon has run gets no marker, so losing its `state.db`
later cannot mint a second credential over the cluster's.

If you founded a cluster without `lv host init`, the daemon logs that no admin
was created. On that founding node only, create the marker and restart:

```bash
touch /var/lib/litevirt/genesis-pending
systemctl restart litevirt
```

The daemon still refuses if `join_peers` is set, any user account has ever
existed, or the data directory holds capability latches from an earlier run. Do not use `lv user reset-admin` for this: it resets an existing admin
and never creates one.

## Add hosts to the cluster

1. Copy the daemon binary:

```bash
scp bin/litevirt root@10.0.50.11:/usr/local/bin/
```

2. Add the host (this copies the CA cert and generates a host certificate):

```bash
lv host add root@10.0.50.11 --name host-b
```

The host is admitted in state `joining` (`HOST_JOINING` in `lv host ls`; a
server on an older release reports it `HOST_OFFLINE`, and an older `lv` shows
the number `5`) and
becomes `active` when its daemon first starts. Until then nothing is placed on
it and the failover coordinator never fences it, however long its setup takes:
it is down to every peer by construction, and runs nothing. A host removed
with `lv host rm` and added back under the same name starts with no failure
history; every peer forgets the old machine's failed probes when it leaves the
host table.

`lv host add` refuses a machine that holds another cluster's litevirt state,
before anything is admitted or pushed. A machine that founded its own cluster
with `lv host init --local` is the usual case: adding it would merge that
cluster's users (a second `admin`), audit history, capability latches and
gossip key into this one. The proof that state belongs to this cluster is
the host identity the daemon loads from the config's `pki_dir`
(`/etc/litevirt/pki` when it names none): a `host.crt` that chains to this
cluster's CA and is a host certificate (ServerAuth usage, not the lv-cli
client or an audit certificate), and a `host.key` beside it that is its key.
Certificates are public, so a certificate alone proves nothing. The machine
proves it holds the key by signing a random, domain-separated challenge
with `openssl` there, bounded by a 30-second timeout; where it has no
`openssl`, or that run fails or times out, the key is read over the same
root SSH session, compared in memory, and never written or logged. A
`host.key` that is not a regular file (a device, a FIFO, or a link to one)
is refused before `openssl` runs. The add refuses:

- a `ca.crt` in `/etc/litevirt/pki` or the config's `pki_dir` holding any CA
  but this cluster's (a bundle with another CA in it included), or a CA key
  with no certificate beside it;
- a `state.db` or capability latches (`split_brain_activated.*`) in the data
  dir (`data_dir`, `/var/lib/litevirt` by default), or a running
  `litevirt.service`, without that proof: no `host.crt`, one another CA
  issued, one that is not a host certificate, or no `host.key`, an
  unreadable one or one that is not its key;
- a `config.yaml` it cannot read or parse, since then it cannot tell where the
  state or the host identity lives.

An add that failed after the cluster admitted the host, whose daemon may
already have started, and whose rollback left no `host.crt`, is finished by
running it again: the admitted pair it left staged on the machine is the
proof. A `host.crt` that is present always has to prove itself.

There is no override. The refusal names what it found and the two ways
forward: stop and disable `litevirt.service` on the machine and move
`/etc/litevirt`, the data dir, `/root/.config/litevirt` and `/etc/pki/qemu`
aside, then add it again as a new machine; or join in the other direction,
adding this cluster's machines to the one it founded. A host removed with
`lv host rm` keeps its host certificate, revoked but issued by this cluster's
CA, and its files, so it is added back as before, with its database and even
a daemon still running.

`lv host add` uploads the binary and the host's credentials to staged paths
on the machine, and moves them into place only once the cluster has admitted
the host, so a refused add leaves the machine as it was. Each attempt's
staged files are its own, named for the serial of the certificate it asks the
cluster to admit and a nonce the attempt prints
(`.host.crt.add-<serial>-<nonce>`), so two adds of one machine at once, or a
rerun while the first add is still running, do not replace or remove each
other's, and the install takes only the pair it was admitted with. It refuses a machine that serves another live member's
certificate or has its address. While it
installs, each file it replaces in `/etc/litevirt/pki` is kept beside it as
`<file>.pre-add-<time>` (0600): the copies are put back if the add fails after
the admission, and removed once it succeeds. A host admitted by an add that
did not finish shows `HOST_JOINING`: run the same `lv host add` again, from
any machine holding the cluster CA, to finish it, or
`lv host rm <name> --serial <serial> --address <ip>` to undo the admission.
That removal also deletes the files every attempt left
staged under the revoked serial on the machine (the config's beside the file
`config.yaml` resolves to), when it can reach the machine over
SSH as root within 10 seconds.

Each attempt records, beside its staged certificate
(`.host.crt.add-<serial>-<nonce>.before`), the certificate the machine served
before it. A rerun of an admission keeps what its first attempt recorded: it
installs only over that certificate, the admission's own, or one this
cluster's CRL revokes, and otherwise stops nothing and installs nothing. An
earlier release's staged add recorded nothing, so its rerun installs only on
a machine serving no certificate, the admission's own, or a revoked one. Any add also refuses, before it is
admitted, a machine on which another add's attempt was neither finished nor
undone and that now serves a certificate that attempt did not find. Each
refusal names the certificate the machine serves and
`lv host rm <name> --serial <serial> --address <ip>`, which settles the
unfinished admission and leaves that certificate in place.

`lv host rm <name> --serial <serial> --address <ip>` selects an admission by
its certificate, in any spelling of the number (case, leading zeroes, `0x`).
When the row of `<name>` holds it, this is `lv host rm <name>`, with its
checks, refused if the row changes first. When no row holds it (the
admission's row is gone, or `<name>` is now another admission), no row is
touched. The daemon first runs a removal's checks (admin, caught up, voter
majority, a pull of the hosts table) and confirms no live row holds the
serial; a daemon from an earlier release cannot, and the command refuses. On
the machine at `--address`, under its add lock, the serial must have left a
staged file, record or install record for `<name>`, and no add may hold the
machine; a machine that serves the serial may be a completed add, so only the
serial's staged files, and the claim of an earlier run of the command, are
removed and nothing is revoked. The command then
claims the machine for that serial alone
(`/etc/litevirt/.lv-add-settle-<serial>`, taken only while the install record
and the certificate are as it checked), so no add of that admission runs
there until it has finished; it revokes the serial, publishes the CRL,
removes that serial's staged files and records, and removes its claim last.
It never writes `/etc/litevirt/.lv-add-installed`: another admission's
install keeps its record, name and time, and so the hour in which it keeps a
fresh add out, whatever runs between or fails. Only the serial's own add's
claim is removed from it, and never the installed identity. A step that fails after the revocation, the
publication or the cleanup, says so and names the same command, which
finishes it. `lv host rm <name>` of a
joining host whose cleanup on the machine fails does the same. Install and
attempt records quote a host name that holds a blank, and with no row the
command takes such a name when it prints safely; the machine's trace must
name it exactly before anything is revoked. `lv host add` refuses, before
anything, a name that command would not take: one with a control character,
one longer than a host name may be, or one that begins with `-`. A rerun refuses when the key staged or installed
on the machine is not the admitted certificate's. The machine running
`lv host add` keeps its copy of the admitted credentials in
`hosts/<name>/` under its pki directory.

One machine is admitted under one name: an add is refused at an address
another live or joining host holds at port 7443. Two adds made through two
hosts at once can each be admitted before either admission reaches the
other. Of those, a host already `active` at the address keeps it, and
otherwise the one admitted first (the lesser name on a tie); `lv host add`
asks the cluster again right before it installs, and the other's is refused
there, naming `lv host rm` for its admission. A host that does not keep its
address is never activated: it stays `joining` (a restart of its daemon
activates it once the other is removed), and `lv health` shows
`host.address_shared`.

From just before it installs to the end of its setup or rollback, an add
holds the machine: it claims it in `/etc/litevirt/.lv-add-installed`, and every
command it then runs there takes an `flock` on `/etc/litevirt/.lv-add.lock` in
the shell that runs it and acts only while that record is still its claim,
and no `lv host rm --serial` of its admission has claimed the machine. A
command delayed past a lost connection therefore runs under the lock or does
nothing, and never acts on a machine another add has claimed since. Without
`flock` (util-linux) on the machine the add refuses. Another add of the machine
is refused while the claim is younger than 10 minutes (setup holds the lock
while it runs); an older claim is an add that died, and is taken over. An add
that finds the machine's certificate changed since it began, or another
admission (under any name) installed there in the last hour whose certificate
this machine's CRL does not revoke, installs nothing: of two adds of one machine, the second to install is
refused, whatever its admission. A rollback moves back only files that are
what that add installed. `lv host rm` removes the record of the admission it
revoked only while it is still that record, in one locked command.

A machine that already has `/etc/litevirt/config.yaml` keeps it. The add
edits in place only `host_name`, `advertise_address`, `join_peers`, `pki_dir`
(set to `/etc/litevirt/pki`, where it installs the credentials) and
`enforcement`, which becomes the cluster's block, or is removed when the
cluster has none. Every other line (a `migration.network`, say) is kept as it
was, as is a symlink to it. The file is replaced by an atomic rename, written
as root: its mode is kept but capped at 0600 (a group- or other-readable
config becomes owner-only), and its owner and group become root's. The file as it was is kept
beside it as `config.yaml.pre-add-<time>` (0600). The add refuses a config it
cannot parse, one with more than one document, one of 1 MiB or more, and a
`grpc_port` other than 7443 or a `gossip_port` other than 7946, on which
peers would not reach the host.

Such a host is a new machine to the cluster and inherits nothing the old one
was configured with: its fencing and IPMI settings, labels, role, region and
capacity overrides return to their defaults, and its IPMI password is retired
(already at `lv host rm`). Its `lv host network` intents are dropped too,
since they name the old machine's NICs and addresses: record the new
machine's wiring before its first `lv host network apply`. Its host-tier
firewall rules (`lv firewall host-rule`) are kept: they are policy for guest
traffic through the host of that name, not a property of the hardware.

Nor does it inherit the old machine's workloads. `lv host add` refuses a name
while VMs or containers are still recorded on the host removed under it, and
names them. They are recovered onto live hosts by the claim path for a host
removed for good, which needs the name to stay removed; wait until they have
moved (`lv health` shows `ha.claim.stranded` for any that cannot), or remove
them, and add the host again. `lv rm <vm>` and `lv ct rm <name>` work on a
workload recorded on a removed host without contacting it: they delete its
cluster rows and audit the delete as one on a removed host. Nothing on the
removed machine is touched, and disks on shared storage are kept.

Stopped workloads are the exception: they do not block the name. Failover
never starts a VM stopped on purpose or a stopped container, and never rebuilds a stopped VM's
host-local disk elsewhere, so a stopped one can still be recorded on the
removed host with its data on that machine. `lv host add` admits the name
anyway, and the stopped workloads come back with the machine, still stopped
(see [Stopped workloads](migration-failover.md#stopped-workloads)). Added on a
different machine, whose disks do not hold them, they cannot run there: `lv start`
fails, because that machine has no domain for them, and nothing starts them on a
blank disk. Remove them with `lv rm <vm>` if their data is gone for good.

A workload that no live host can take waits until one can. The usual case is a
container whose host was the only one with a container runtime: it is left on
the removed host, marked `relocate-skipped`, and the name stays refused. Bring
up a host that can run it (this machine, added under another name, will do)
and the coordinator relocates the container onto it by claim, as it would
have at the failure. The old name is then free to add again. The name itself
cannot take the container back, because a claim is refused while the host it
recovers from answers under that name, and a re-added machine does.

3. Edit `/etc/litevirt/config.yaml` on the new host to set the join address:

```yaml
join_peers:
  - "10.0.50.10:7946"
```

4. Start the daemon:

```bash
ssh root@10.0.50.11
systemctl enable --now litevirt
```

5. Verify both hosts appear:

```bash
lv host ls
```

Repeat for each additional host.

## SSH targets and `~/.ssh/config`

Every command that reaches a host over SSH (`lv host init`, `lv host add`, `lv host rotate-audit-key`
and the `--ssh-user` commands) reads the ssh config through the system `ssh -G`, so a `Host`
alias that works with `ssh <alias>` works here, even when the alias is not in DNS.
`HostName`, `User`, `Port`, `IdentityFile`, `IdentitiesOnly`, `IdentityAgent` and the host-key
options below are used, and `Include` and `Match` are resolved
by OpenSSH itself. Two files are read, in the order `ssh` reads them: `~/.ssh/config` (under
`$HOME`), then `/etc/ssh/ssh_config` (with whatever it `Include`s, such as
`/etc/ssh/ssh_config.d/*.conf`). The first value obtained wins, so your own config beats the
system one, and a setting made only in the system file (a fleet's `RevokedHostKeys`,
`KnownHostsCommand` or `GlobalKnownHostsFile`) is enforced or refused exactly as if you had set
it. Every `Include` in the system file, and in the files it includes, must be an absolute
path: lv refuses a relative one (or one starting with `~`), naming the file and line, because it
reads the system file the way `ssh -F` does, which would look for it under `~/.ssh` instead of
`/etc/ssh`. Distribution defaults (`Include /etc/ssh/ssh_config.d/*.conf`) are absolute.

- The `--ssh-user` commands (gossip and migration key rotation) and `lv host rm` dial
  `user@<recorded address>`, so a config `User` never applies to them, but a `Host` block that
  matches the recorded address (`Host 10.0.0.*`) does: its `HostName`, `Port` and `IdentityFile`
  redirect those dials as they would `ssh`.
- `lv host renew-cert` and `lv host ui-cert set` default to `root@<host name>`. When your ssh
  config turns that name into a `HostName` that does not resolve to the address the cluster
  records for the host, they refuse rather than carry the host's credentials elsewhere; fix the
  config or name the target with `--ssh`.
- The config is read once per command, and its `HostName` is the one address used everywhere:
  the DNS step, the certificate SAN, the address recorded for the host, and the SSH dial.
  It must still be IPv4.
- A host, and a user written on the command line, may contain only letters, digits and
  `.` `_` `-` `:`, and may not start with `-`; anything else (`ops+ci@host`, `DOMAIN\user`, an
  IDN name, `[10.0.0.1]` without a port) is refused with `invalid SSH host` or `invalid SSH user`
  before `ssh -G` runs. This applies even with no `~/.ssh/config`: the host can come from the
  cluster's replicated host records, and a `Match exec` line would hand it to a shell.
- A user or port written on the command line (`admin@alias`, `alias:2222`) beats the
  config; the config beats the defaults (user `root`, port 22).
- Keys are offered in one publickey attempt, as OpenSSH orders them: the configured
  `IdentityFile` keys first (the agent's copy of one when it holds it, matched by public key, so
  a passphrase-protected key or a `.pub`-only hardware-token key held by the agent still goes
  first), then the agent's other keys, then `~/.ssh/id_ed25519`, `id_ecdsa` and `id_rsa`. A key
  is never offered twice, and a busy agent cannot use up the server's attempts before the
  configured key. `%d %h %i %k %l %L %n %p %r %u %%` are expanded; an `IdentityFile` with any
  other `%` token is skipped with a warning, and under `IdentitiesOnly yes` nothing is offered
  in its place. `IdentitiesOnly yes` limits the ssh agent (which is still used) and the key
  files to the configured identities, matched by public key, so an `IdentityFile` that is a
  `.pub` file whose private key is in the agent works.
- `IdentityAgent` is honoured: `none` uses no agent, a socket path (or `$VAR`) uses that agent,
  and `SSH_AUTH_SOCK` or no setting uses `$SSH_AUTH_SOCK`.
- `ProxyJump` and `ProxyCommand` are not supported. lv warns, naming the directive, and
  dials the address directly, as it always did.
- Nothing in the config makes lv accept a host key that `ssh <alias>` would refuse. lv refuses:
  a changed key for a known host (always; `StrictHostKeyChecking no` or `accept-new` change
  nothing); a host with no known_hosts entry under `StrictHostKeyChecking yes` (otherwise it is
  accepted on first contact, accept-new); a key, or a certificate over a key or from a CA, listed
  in `RevokedHostKeys`; a host certificate its CA signed with SHA-1 `ssh-rsa`, as OpenSSH's
  default `CASignatureAlgorithms` does; and any key whose check depends on something lv cannot
  read:
  - `KnownHostsCommand` (anything but `none`): lv does not run it, so every dial refuses, naming
    it. Put the keys it serves in a known_hosts file instead.
  - `RevokedHostKeys` must be a plain list of public keys (`#` comments allowed). A binary KRL,
    a line that is not a public key, or a missing or unreadable file refuses every dial, naming
    the file.
- The known_hosts files checked: `~/.ssh/known_hosts` and `~/.ssh/known_hosts2` always;
  `UserKnownHostsFile` adds files on top of them, so `/dev/null` or `none` drops no entry; and
  `GlobalKnownHostsFile`, by default `/etc/ssh/ssh_known_hosts` and `ssh_known_hosts2`, so a host
  key distributed there is enforced. Each file is checked on its own: a key is accepted only
  when at least one file matches it and every file that has an entry for the host (under the
  `HostKeyAlias`, or the dialled address) agrees. One file with a different key for the host, a
  key only of another type, or no `@cert-authority` for a presented certificate refuses the
  connection as changed and names that file. A file with only plain entries vouches for a host
  certificate by the key inside it, so a `@cert-authority` line in one file and the same host's
  plain key in another accept; a different plain key refuses. lv asks the host for the key types
  every such file records, so files that all hold the host's RSA key agree even when one of them
  also holds an ed25519 key; files with no type in common refuse. This is stricter than `ssh`, which reads a
  configured `UserKnownHostsFile` instead of `~/.ssh/known_hosts` and accepts any match: a stale
  entry in `~/.ssh/known_hosts` for a host you pinned elsewhere must be removed
  (`ssh-keygen -R <host>`) before lv connects. Two certificate cases are also stricter: a host
  that presents no certificate while a `@cert-authority` line in one file covers it refuses
  (give the host a certificate, or remove the CA line's coverage of it); and a CA rotation split
  across files, the old CA in one and the new in another, refuses (put both CA lines in the same
  file for the rotation). A known_hosts pattern with a wildcard port (`[10.0.0.*]:*`), which
  OpenSSH matches but lv cannot evaluate, refuses any host its address part could match, naming
  the file and line; write the port explicitly. Several keys for the host in one file still
  accept on any match. A host no file has an entry for is first contact. lv only reads these files;
  it never records a key in any of them. A configured file that does not exist is skipped, as
  `ssh` skips it, with a warning naming it. A file that exists but cannot be read or parsed (a
  default, configured or global one) refuses the connection and names the file and line.
  lv's parser is stricter than OpenSSH's: a line `ssh` skips, such as one with a key type lv
  does not support (`ssh-xmss@openssh.com`) or one over 64 KiB, fails the whole file. One such
  line in any of these files, including a global one config management writes, stops every lv
  SSH dial until it is fixed or removed, even though `ssh` itself accepts the file. With no
  known_hosts file at all there is nothing to compare, and first contact is accepted with a
  warning.
- `HostKeyAlias` is honoured as `ssh` honours it: the host's key (and a host certificate's
  principal) is looked up under the alias, so a key pinned there is enforced. When known_hosts
  has nothing under the alias, lv checks the dialled address instead rather than treating the
  host as new, except under `StrictHostKeyChecking yes`, which refuses an unknown alias as `ssh`
  does.
- lv asks a known host only for the key types its known_hosts entries record (and for a host
  certificate when a `@cert-authority` line covers it), so a host that also holds keys of other
  types is not refused as changed; a host known_hosts does not know is asked for any plain key
  type. RSA keys are asked for with SHA-2 signatures only: an sshd that can sign only SHA-1
  `ssh-rsa` is refused. `HostKeyAlgorithms` in the config is not used.
- `Match exec` lines in your config run with lv's privileges, as they do for `ssh`: as root
  under `sudo lv host init`. OpenSSH refuses a config file not owned by that user.
- With neither config file present the defaults apply even without an `ssh` binary. If either
  exists but `ssh -G` fails or takes longer than 10 seconds, the command refuses with an error
  naming `ssh -G` and the config files, rather than dropping what they pin.
  `ssh` also refuses a config it does not own: under `sudo -E`, run lv as the config's owner or without `-E`.

## CLI setup

The `lv` binary connects to litevirtd over gRPC/mTLS. On a node it connects to
the local daemon automatically. It looks, in order, at:

1. `/run/litevirt/endpoint`, which the daemon writes at every start (0644,
   replaced atomically). It holds only `grpc_port` and `pki_dir`, nothing
   secret, so any user on the node can read it. Its `pki_dir` is the CA lv
   trusts, so it is read only as a regular file owned by root that only root
   can write, in a root-owned directory only root can write (the daemon
   refuses to write into any other `/run/litevirt`, and opens a 0700 one it
   owns up to 0755). A file that fails that,
   does not parse, has another key, or holds an invalid port or a relative
   path is ignored as a whole, with a warning.
2. `/etc/litevirt/config.yaml`, which is root's and 0600 because it can hold
   inline secrets: readable under `sudo`.
3. If that file cannot be read by the user, the defaults: the daemon on
   `127.0.0.1:7443`, with the user's CLI client bundle. lv says so on stderr.
   With no bundle either, it refuses, naming the file: set `LV_HOST` or run
   with `sudo`.

In local mode the user's CLI client bundle (below), when there is one, takes
the place of `pki_dir`. Only root uses the node's own identity in `pki_dir`:
a user other than root without a bundle is refused before anything in it is
read. For a remote entry point, set the target host:

```bash
export LV_HOST=10.0.50.10
```

Or specify per-command:

```bash
lv --host 10.0.50.10 status
```

Any host in the cluster can serve as the entry point since state is replicated.
The CLI uses the client certificate bundle in `~/.config/litevirt/pki` by
default. `lv host init --local` creates this bundle for the installing user so a
single-node install does not require copying daemon certificates out of
`/etc/litevirt/pki`.

## Directory layout on hosts

```
/usr/local/bin/litevirt        # daemon binary
/etc/litevirt/config.yaml       # daemon configuration
/etc/litevirt/pki/              # TLS certificates
  ca.crt                        # cluster CA certificate
  ca.key                        # cluster CA private key (first host only)
  host.crt                      # this host's certificate
  host.key                      # this host's private key
~/.config/litevirt/pki/         # per-user CLI client bundle
  ca.crt
  client.crt
  client.key
/var/lib/litevirt/              # data directory
  images/                       # base VM images
  disks/                        # VM disk images
  state.db                      # local SQLite state store (0600: it holds the credentials)
/var/cache/litevirt-restore/    # file restore: restore-VM kernel copy + initramfs (root:litevirt-restore 0750)
/run/litevirt/file-restore/     # file restore: per-session export sockets and pidfiles
/run/litevirt/endpoint          # grpc_port and pki_dir for a local lv (0644, nothing secret)
```

`lv` run on a host as a user other than root uses that user's CLI client
bundle in `~/.config/litevirt/pki/`, never the host's own identity in
`/etc/litevirt/pki/`. A user without a bundle is told to run the command with
sudo; `sudo lv host init --local` installs a bundle for `SUDO_USER` when it
founds a cluster.

### What file restore changes on the host

Single-file restore (`lv backup file-ls` / `file-restore`,
[backups.md](backups.md#single-file-restore)) is on by default. The daemon must
run as **root** for it (a non-root daemon refuses it). At start, the daemon:

- **creates a system account `litevirt-restore`** if there is none — its own
  group, no other group, no home, no login shell. To create it yourself (or
  in your configuration management) beforehand:

  ```bash
  useradd --system --user-group --no-create-home \
      --home-dir /nonexistent --shell /usr/sbin/nologin litevirt-restore
  ```

  An existing account of that name is used only if it looks like this — a
  system uid, a nologin shell, no supplementary group but `kvm` (which
  earlier builds added), a uid no other account shares — otherwise file
  restore is refused, naming what differs. Restore VMs do not run as this
  account: each runs as its own uid from a reserved range
  (`file_restore.uid_base`, 64 uids from 3800000000, which must belong to no
  account or group NSS knows and lie outside `/etc/subuid`, `/etc/subgid` and
  the containers' id-map range), with this account's group and its own slot
  group (the same number as its uid) only. A starting
  daemon kills any process left running as one of these uids;
- **adds and removes POSIX ACL group entries on `/dev/kvm`**: one per restore
  VM, giving its slot group read-write for as long as the session runs (`getfacl
  /dev/kvm` shows them). A starting daemon removes any a daemon that died
  left;
- **loads an AppArmor profile `litevirt-restore-qemu`** into the kernel where
  AppArmor is enabled (it stays loaded until reboot; nothing is written under
  `/etc/apparmor.d`). With AppArmor enabled but `apparmor_parser` not
  installed, restore VMs run under Landlock alone (a warning says so), or
  file restore is refused on a kernel without Landlock;
- **starts each restore qemu in a network namespace of its own** (nothing to
  configure: it has a loopback interface only, down);
- **confines each restore qemu with Landlock** where the kernel has it
  (`landlock` in `/sys/kernel/security/lsm`); nothing is installed for it. A
  host with neither AppArmor nor Landlock refuses file restore;
- **creates `/var/cache/litevirt-restore`** for the restore VM's boot files and
  `/run/litevirt/file-restore` for its sessions.

None of this happens with `file_restore: {enabled: false}` in the daemon
config (the start-up sweep of leftover restore VMs still runs).

## Upgrading

litevirt tracks the daemon version on each host. You can see which version every host is running with:

```bash
lv host ls
```

The VERSION column shows the build version of litevirt on each host. Hosts running older versions show their current version; hosts that haven't reported yet show `-`.

### How upgrades work

Upgrading litevirt is safe and non-disruptive:

- **Running VMs** are managed by libvirt/QEMU, not by litevirt directly. They survive daemon restarts without interruption (the systemd unit ships `KillMode=process`, which the daemon also self-checks at startup).
- **HAProxy** runs in its own session (via `setsid`) with PID files. The LB Manager re-discovers running instances on startup.
- **Keepalived** double-forks and reparents to init. VIPs remain assigned through daemon restarts.
- **Schema migrations** are applied automatically on daemon startup via `InitSchema()`. Each host creates its own tables/columns/indexes locally — DDL is not replicated across the cluster. A DB forward-migrated by a NEWER binary does **not** stop an older one from starting: migrations are additive-only, so the old binary tolerates the extra columns, and that is the normal mid-rolling-upgrade state. There is no downgrade refusal — do not rely on one when rolling a binary back.
- **Pre-flight gate**: `lv host upgrade` runs `PreflightUpgrade` first and refuses on blocking conditions (in-flight migrations or backups, leader-lease holdings with pending fences, replication backlog, clock skew, witness-host risk). Pass `--force` to override.
- **`upgrading` host state**: the host marks itself `upgrading` in the cluster state before the binary swap. Failover coordinators on peer hosts skip fence candidacy for `upgrading` hosts, so the restart window can't trigger a destructive false-positive failover.
- **Automatic rollback**: if the new binary panic-loops past `StartLimitBurst=10` within 5 minutes (systemd's threshold), the `litevirt-rollback.service` companion unit fires, restores the previous binary from `litevirt.old`, and restarts. It fires only while an upgrade is in progress (gated on the `.upgrade-pending` sentinel), so a restart storm against a healthy binary cannot downgrade it. Operator sees a `litevirt-rollback` tagged entry in `journalctl`.
- **Cluster version-skew check**: each `PushMutations` push carries the sender's DB-applied schema version. A receiver refuses the push whenever the sender's schema is strictly ahead of its own (any gap ≥ 1), so a node missing migrations can't be corrupted by a newer peer. The check is one-directional — a sender that is *behind* the receiver is still accepted.

No drain is needed for typical upgrades. The upgrade flow per host is:
preflight gate → mark `upgrading` → copy binary → checksum → backup `.old`
→ atomic swap → re-exec via `syscall.Exec` (preserving PID for systemd) →
new daemon clears `upgrading` state on healthy startup.

### Scenario 1: Rolling upgrade from a workstation (recommended)

Build new binaries on your dev machine (or download a release), then push to all hosts with a single command:

```bash
# Build
make build

# Push to every host in the cluster
LV_HOST=root@10.0.50.10 lv host upgrade --binary ./bin/litevirt
```

The CLI connects to the cluster via SSH, lists all hosts, identifies which ones are outdated, and upgrades them sequentially. The connected host (10.0.50.10 in this example) is automatically upgraded **last** so the control-plane connection stays alive throughout.

You'll see a plan before anything happens:

```
Upgrade plan: 3 host(s) → v0.2.0

  HOST      ADDRESS       CURRENT     NOTE
  host-b    10.0.50.11    v0.1.0
  host-c    10.0.50.12    v0.1.0
  host-a    10.0.50.10    v0.1.0      (connected — upgraded last)

Proceed? [y/N]
```

To upgrade specific hosts only:

```bash
lv host upgrade --binary ./bin/litevirt host-b host-c
```

To skip the confirmation prompt (useful in scripts):

```bash
lv host upgrade --binary ./bin/litevirt --yes
```

### Scenario 2: Upgrade from a cluster node

If you're running `lv` directly on a cluster host (local mode, no `LV_HOST`), the workflow is similar but you first need to get the new binary onto that host:

```bash
# On your dev machine — copy the new binary to a cluster host
scp bin/litevirt root@10.0.50.10:/tmp/litevirt-new

# On the cluster host
lv host upgrade --binary /tmp/litevirt-new
```

The command detects that it's running on a cluster node and upgrades the local host last. The SSH session used for the self-upgrade is handled by sshd (not litevirt), so the copy-swap-restart sequence completes even though litevirt restarts underneath.

### Scenario 3: Manual single-host upgrade

If you prefer to upgrade hosts one at a time without the rolling upgrade command:

```bash
# Copy new binary to the host
scp bin/litevirt root@10.0.50.10:/usr/local/bin/litevirt.new

# SSH in and swap
ssh root@10.0.50.10
cp /usr/local/bin/litevirt /usr/local/bin/litevirt.old    # backup
mv /usr/local/bin/litevirt.new /usr/local/bin/litevirt
chmod 755 /usr/local/bin/litevirt
systemctl restart litevirt

# Verify
systemctl is-active litevirt
lv host ls   # check version column
```

If the new binary fails to start, roll back:

```bash
mv /usr/local/bin/litevirt.old /usr/local/bin/litevirt
systemctl restart litevirt
```

### Scenario 4: Debian/Ubuntu packages (deb)

litevirt does not publish official `.deb` packages yet, but you can build your own for integration with `apt` and unattended-upgrades.

**Building a deb package:**

```bash
# Build the binary
make build

# Create the package structure
mkdir -p litevirt_0.2.0/DEBIAN
mkdir -p litevirt_0.2.0/usr/local/bin
mkdir -p litevirt_0.2.0/etc/systemd/system

cp bin/litevirt litevirt_0.2.0/usr/local/bin/

cat > litevirt_0.2.0/DEBIAN/control << 'EOF'
Package: litevirt
Version: 0.2.0
Architecture: amd64
Maintainer: your-team <team@example.com>
Depends: qemu-system-x86, libvirt-daemon-system, genisoimage
Recommends: haproxy, keepalived, socat
Description: litevirt hypervisor daemon
 Lightweight KVM/QEMU orchestrator with decentralized WAL-based replication.
EOF

cat > litevirt_0.2.0/DEBIAN/postinst << 'EOF'
#!/bin/bash
set -e
systemctl daemon-reload
# Restart only if already running (upgrade), don't start on fresh install.
if systemctl is-active --quiet litevirt; then
    systemctl restart litevirt
fi
EOF
chmod 755 litevirt_0.2.0/DEBIAN/postinst

dpkg-deb --build litevirt_0.2.0
```

**Installing/upgrading with dpkg:**

```bash
# Copy the deb to each host and install
scp litevirt_0.2.0.deb root@10.0.50.10:/tmp/
ssh root@10.0.50.10 dpkg -i /tmp/litevirt_0.2.0.deb
```

The `postinst` script restarts litevirt automatically if it was already running, so VMs continue uninterrupted.

**Hosting in a local apt repository:**

For larger clusters, host the `.deb` in an apt repository (using `reprepro`, Aptly, or a simple Nginx directory with `dpkg-scanpackages`). Then upgrade all hosts with your existing config management:

```bash
# On each host (or via Ansible/Salt/etc.)
apt update && apt install --only-upgrade litevirt
```

This integrates with standard Debian tooling: unattended-upgrades, apt pinning, version holds, and rollback via `apt install litevirt=0.1.0`.

### Rollback

The `lv host upgrade` command always backs up the old binary to
`/usr/local/bin/litevirt.old` before swapping. There are two rollback paths:

**Automatic:** If the new daemon panics on startup and systemd
restarts it past `StartLimitBurst` (10 restarts within 5 minutes) while an
upgrade is in progress, the `litevirt-rollback.service` oneshot fires
automatically:

1. Restores `litevirt.old` over `litevirt`.
2. Runs `systemctl reset-failed litevirt.service`.
3. Restarts the main service.
4. Logs the rollback to journal with `litevirt-rollback` tag.

It is conditional on **both** the `.upgrade-pending` sentinel and `litevirt.old`
existing: with no sentinel the service deliberately declines and leaves the
failed binary in place, and with no `.old` it logs that there is nothing to roll
back to and exits non-zero. Either way the unit stays failed, so a daemon that
will not start is not by itself evidence that a rollback was attempted.

**This path has not been confirmed through a live systemd upgrade** — treat the
behaviour above as expected rather than verified, and read the journals. Note
also that restoring `.old` restores the previous binary's behaviour in full,
including any limitations that build had.

Verify with **both** journals — the rollback service's own log is the only place
its decision is recorded:

```bash
journalctl -t litevirt-rollback          # ran, declined, or found no .old
journalctl -u litevirt-rollback.service  # the unit's start/exit status
journalctl -u litevirt.service           # why the daemon failed in the first place
systemctl status litevirt
```

**Manual (anytime after a successful upgrade):**

```bash
ssh root@10.0.50.10
mv /usr/local/bin/litevirt.old /usr/local/bin/litevirt
systemctl restart litevirt
```

### Mixed-version clusters

During a rolling upgrade, hosts temporarily run different versions. This is safe because:

- **WAL replication streams data mutations, not schema.** Each host applies its own DDL on startup.
- **Schema changes are always additive** (new columns, tables, indexes). Columns are never removed or renamed.
- **Schema-version pin**: the daemon refuses to start if the DB has been forward-migrated by a newer binary (`schema_state.version > CurrentSchemaVersion`). This catches the "old binary onto new DB" footgun.
- **Skew guard (asymmetric)**: each push carries the sender's DB-applied `schema_version`. A receiver whose schema is *behind* the sender's rejects the push with a `FailedPrecondition` error (logged at WARN); a sender that is behind the receiver is accepted (logged at INFO). It is a hard reject of the push, not warn-and-continue.
- **Proto3 forward compat**: the gRPC API handles unknown fields gracefully in both directions, but the schema-skew check above provides the actual safety guarantee.

Recommended practice: keep version skew to one release within the cluster. The CLI's rolling-upgrade command sequences hosts serially so the skew window is bounded by your network bandwidth + restart time per host (typically a few minutes for the whole cluster).

## Uninstall

Remove litevirt from a host using the CLI:

```bash
# Remove host from cluster first (if cluster is still active)
lv host rm host-a --force

# Uninstall litevirt from the host
lv uninstall root@10.0.50.10 --confirmed
```

This stops the daemon, removes the binary, config, PKI certificates, systemd unit, udev rules and the managed fence SSH sshd drop-in (`/etc/ssh/sshd_config.d/60-litevirt-fence.conf`). By default it also deletes all VM data (images, disks). To keep VM data:

```bash
lv uninstall root@10.0.50.10 --confirmed --keep-data
```

To uninstall manually via SSH:

```bash
systemctl stop litevirt
systemctl disable litevirt
rm -f /etc/systemd/system/litevirt.service
rm -f /usr/local/bin/litevirt
rm -rf /etc/litevirt
rm -rf /var/lib/litevirt          # remove VM data
rm -f /etc/udev/rules.d/99-litevirt-pci.rules
rm -f /etc/ssh/sshd_config.d/60-litevirt-fence.conf && systemctl reload ssh   # managed fence SSH
systemctl daemon-reload
# File restore's host state:
apparmor_parser -R /dev/stdin <<<'profile litevirt-restore-qemu {}' 2>/dev/null || true  # or reboot
rm -rf /var/cache/litevirt-restore /run/litevirt/file-restore
userdel litevirt-restore
```
