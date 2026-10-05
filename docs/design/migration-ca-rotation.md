# Rotating the migration CA

Status: **implemented.**

## Why

Storage migrations (`--with-storage`) are encrypted with credentials from a
separate migration CA (`internal/pki/migration.go`). `lv host init`, `lv host
add` and `lv host install-migration-tls` issue one certificate per host from it,
and each daemon installs its host's set into `/etc/pki/qemu` for QEMU.

Three things are missing:

- **The CA cannot be replaced.** `install-migration-tls --reissue` re-signs host
  certificates from the *same* CA, and every path refuses to mint a second CA
  once any host holds credentials. A leaked `migration-ca.key`, a decommissioned
  operator machine, or plain hygiene has no remedy short of re-provisioning by
  hand.
- **Nothing warns before expiry.** The CA is valid for 10 years and host
  certificates for 5. No code reads a certificate's `NotAfter` except
  `lv acme` (`cmd/litevirt/acme.go`). An expired migration certificate surfaces
  as a refused storage migration — or, where `allow_unencrypted_storage` is set,
  a plaintext one.
- **A credential push can be torn.** `pushMigrationCredentials` copies
  `ca.crt`, `host.crt` and `host.key` one at a time, and the daemon re-installs
  into `/etc/pki/qemu` before every storage migration. A migration that starts
  between the certificate copy and the key copy hands QEMU a new certificate
  with the old key, and the handshake fails. Today's `--reissue` already has
  this race; a rotation pushes to every host twice.

## What this adds

1. `lv host rotate-migration-ca [--no-overlap] [--force] [--ssh-user]` — replaces
   the migration CA across the cluster, with an overlap window by default.
2. `lv doctor migration-tls`, backed by a `MigrationTLSStatus` RPC — per-host
   view of which CAs each host trusts, who issued its certificate, and when
   things expire. The rotation's phase gates use the same RPC.
3. A daemon log warning when migration credentials are within 90 days of expiry.
4. A validated, change-only install into `/etc/pki/qemu`, which closes the torn
   write for `--reissue` as well.

Out of scope: automatic renewal. It would need the CA key on every host so the
daemons could sign; today it lives only on the operator machine, and copying it
out would undo the containment the separate migration CA exists for.

## Why no restart is needed

`Server.migrationTLSReady()` (`internal/grpcapi/server.go`) runs the installer
before each storage migration, and libvirt builds QEMU's `tls-creds-x509` object
fresh for each migration. Files pushed into `<pki_dir>/migration/` therefore
take effect on the next migration. A migration already in flight has loaded its
credentials and is unaffected.

## The command

```
lv host rotate-migration-ca [--no-overlap] [--force] [--ssh-user USER]
```

It sits beside `install-migration-tls` and reaches hosts the same way
(`SSHMigrationTLSHosts`). It runs only on the machine holding
`migration-ca.key`; anywhere else it refuses with the wording of
`secondMigrationCAError`.

### Operator-machine state (in `pki_dir`)

| File | Meaning |
|---|---|
| `migration-ca.crt` / `.key` | the current CA |
| `migration-ca.next.crt` / `.key` | the new CA; exists only mid-rotation (key 0600) |
| `migration-rotation.json` | `phase` (`trust-both`, `reissue`, `drop-old`, `cutover` (`--no-overlap`'s single pass), `done`), `no_overlap`, the new CA's fingerprint, and per host which phases completed or were `skipped`. It remains after a rotation, recording the last one with phase `done`, and is overwritten by the next |
| `migration-ca.retired-<YYYYMMDD>.crt` | the old CA certificate, kept for audit after a rotation (`-2`, `-3`, … for further rotations the same day; a retired certificate is never overwritten); its key is deleted |

Re-running the command reads `migration-rotation.json` and continues from where
it stopped. It never mints a second `next` CA: if `migration-ca.next.crt`
exists, it is the rotation's CA.

### Phases

One run walks all three. Every push is idempotent, so a re-run redoes the
current phase's unfinished hosts.

1. **trust-both.** Each host's `migration/ca.crt` becomes a two-certificate PEM:
   old CA, then new CA. QEMU's GnuTLS loads every certificate in
   `ca-cert.pem` (to be proven on the lab first; see Testing). Host
   certificates are unchanged.
2. **reissue.** Each host gets a new `host.crt` / `host.key` issued by the new
   CA, for its recorded IPv4 address, exactly as `issueMigrationCredentials`
   does today. Hosts on old and new certificates still accept each other,
   because every host trusts both CAs.
3. **drop-old.** Each host's `ca.crt` becomes the new CA alone. Only then does
   the operator machine rename `migration-ca.next.*` over `migration-ca.*`,
   delete the old key, keep the old certificate as `retired-<date>` (`-2`,
   `-3`, … for further rotations the same day), and mark
   the rotation `done`.

### Gates

Before each phase advances, the command calls `MigrationTLSStatus` and requires
every host to report what that phase delivered — asking the daemon what it
would *install*, not reading files over SSH, so a host whose daemon cannot
install them (a refused `/etc/pki/qemu`, a failed validation) holds the gate.

- Before a fresh start (not on resume), before anything is minted: every host
  answers, holds a complete set that passes validation and that its daemon can
  install, and trusts this machine's current migration CA. `--force` passes a
  host that cannot answer; nothing passes the rest.
- Before phase 2: every host trusts the new CA's fingerprint, with a set that
  passes validation.
- Before phase 3: every host's certificate was issued by the new CA.

### `--no-overlap`

For a compromised CA key. It mints the new CA, then pushes the new-CA-only
`ca.crt` together with the new certificate and key to each host in a single
pass, and finalizes as phase 3 does. Until every host is done, a migration
between an updated host and one not yet updated fails the handshake and is
refused. It is never sent in plaintext unless that host set
`migration.allow_unencrypted_storage` — which `lv doctor migration-tls` flags.

### `--force`

Means what it means elsewhere in the CLI: override a safety check. Here it skips
a host that cannot be reached, or that runs a build without
`MigrationTLSStatus`. The host is recorded as `skipped`. When the rotation
finishes it still holds the old certificate, which its peers no longer trust,
so migrations with it are refused. The final output names each skipped host and
the remedy: `lv host install-migration-tls --reissue` once it is back.

Without `--force`, an unreachable host stops the run with progress saved, and
the message names the host and says to re-run.

### Interactions

- **`lv host add` / `lv host init` during a rotation** issue from the new CA and
  push the `ca.crt` the current phase uses (both CAs before phase 3, the new one
  after), so a host joining mid-rotation is never left on the old CA.
- **`lv host install-migration-tls`** refuses while `migration-rotation.json`
  says a rotation is in progress, and names `rotate-migration-ca`.

## The installer: validate, and write only what changed

`pki.InstallQemuMigrationTLS` changes in two ways. This is its own commit; it
fixes `--reissue` whether or not rotation lands.

1. **Validate before installing.** The key must match the certificate
   (`tls.X509KeyPair`), and the certificate must verify against the `ca.crt`
   bundle. A set that fails is not installed; the error makes that migration
   not TLS-ready, so it is refused (or plaintext where allowed). A torn push
   resolves itself once the copy finishes, so a retry a few seconds later
   succeeds.
2. **Skip unchanged files.** Today every storage migration rewrites all five
   files, so two concurrent migrations can tear each other's server pair. Only
   files whose bytes differ are rewritten, so writes happen only when a push
   actually changed something.

## `MigrationTLSStatus` and `lv doctor migration-tls`

### RPC

`MigrationTLSStatus(MigrationTLSStatusRequest{local_only})` returns one row per
host:

- `host`, and `error` when the host could not answer;
- `valid` and `validation_error` — whether the set passes the installer's
  validation above;
- `trusted_ca_fingerprints` — SHA-256 of each CA in `ca.crt`;
- `cert_issuer_fingerprint` — the CA that issued the host certificate;
- `cert_not_after` and each CA's `not_after`;
- `allow_unencrypted_storage` — this host would fall back to plaintext;
- `install_error` — why the daemon's install hook, run for the answer, refused
  the set (a refused `/etc/pki/qemu`, an unresolvable QEMU user). Every gate
  requires it empty.

The daemon the CLI calls answers for itself and fans out to every host in the
`hosts` table through `s.peerClient`, with `local_only=true` so the fan-out does
not recurse. An unreachable host, or one returning `Unimplemented` (an older
build), becomes a row with `error` set, not a failed call. The RPC changes
nothing an operator owns (the install it runs is the same change-only,
serialized install a storage migration runs) and returns nothing secret, so it
takes the role the other read-only doctor RPCs take.

### Command

```
HOST    STATUS   TRUSTS          CERT FROM  EXPIRES
node-1  ok       a1b2…           a1b2…      2031-10-04 (1826d)
node-2  ok       a1b2…,9f8e…     9f8e…      2031-10-04 (1826d)
node-3  expiring a1b2…           a1b2…      2026-12-01 (58d)
node-4  error    —               —          unreachable
```

`--json` gives machine-readable rows. It exits non-zero when any host:

- expires (certificate or a trusted CA) within 90 days;
- is unreachable, or fails validation;
- trusts a different CA set from its peers while no rotation is running;
- has `allow_unencrypted_storage` on.

### Daemon log

At startup and every 24 hours, a daemon with migration credentials logs a
**Warn** when its certificate or any CA it trusts expires within 90 days, naming
`lv host install-migration-tls --reissue` (certificate) or
`lv host rotate-migration-ca` (CA). Once something has expired it logs an
**Error**. 90 days is a constant, not a config key.

## Testing

**First, prove the assumption.** On the kvm003 lab, before any rotation code:
a storage migration between a host whose `ca-cert.pem` holds two CAs and a host
holding only one of them, in both directions. If GnuTLS does not accept the
bundle, the overlap phase needs a different shape and this design is revisited.

**Unit.**

- `internal/pki`: a mismatched key/certificate is refused; a certificate from a
  CA outside the bundle is refused; a two-CA bundle validates; an unchanged
  file is not rewritten (same inode).
- `internal/cli`: the rotation state machine against fakes of
  `MigrationTLSHost` and of the status source — interruption at each phase then
  resume; refusal without the CA key; `--force` recording `skipped`;
  `--no-overlap`; `host add` mid-rotation issuing from the new CA;
  `install-migration-tls` refusing mid-rotation.
- `internal/daemon`: the expiry warning with an injected clock — none at 91
  days, Warn at 89, Error once expired.

**Fleet** (`tests/fleet/`): the `MigrationTLSStatus` fan-out returns a row per
node, with a stopped node as an error row; the phase gate refuses while one node
reports the old CA. `libvirtfake` does no TLS, so a real handshake is lab-only.

**Lab** (kvm003, 5 nodes): a storage migration with a tcpdump TLS-record count,
as for the original migration-TLS proof, before rotation, after phase 1 (across
a phase-1 host and one not yet updated), after phase 2 and after phase 3. With
`--no-overlap`, a migration between an updated and a not-yet-updated host is
refused, never plaintext.

Every assertion is mutation-verified.

## Delivery

Three stacked PRs on the fork:

1. `fix(pki)`: validate before installing, and skip unchanged files.
2. `feat(doctor)`: `MigrationTLSStatus`, `lv doctor migration-tls`, and the
   expiry warning.
3. `feat(cli)`: `lv host rotate-migration-ca`, with the lab proof.

Docs: `docs/cli-reference.md` for both commands, and a "Rotating the migration
CA" section in `docs/migration-failover.md` including the compromised-key
runbook (`--no-overlap`).

## Future work: rotating the cluster CA

The cluster CA has the same gaps — a 10-year CA, 5-year host certificates, no
rotation and no expiry warning — but every gRPC and gossip connection trusts it,
so rotating it is a rolling-trust problem across the whole fleet rather than a
refused migration. It needs its own design. `MigrationTLSStatus` and the expiry
warning are the pattern to extend to it.
