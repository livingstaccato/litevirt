# Clearing the old secret columns

Status: **implemented** behind `credentials_clear_v1`. This note records the
second half of the secret-column move (colonelpanik/litevirt#268). Operator
documentation: [upgrades.md](../upgrades.md#the-old-secret-columns-are-emptied).
"Next release" below means the build that carries `credentials_clear_v1`;
"this release" means the dual-write build before it.

## Where this release leaves things

`credentials_split_v1` (mandatory, replication-gated) moves `hosts.ipmi_pass`,
`users.password_hash` and `tokens.token_hash` onto the sensitive lane as the
dual-write step of a column move
([upgrades.md](../upgrades.md#secrets-move-to-the-sensitive-lane-after-the-roll)):

- once latched, every writer writes the credential table **and** the old
  column, in one batch under one `updated_at`;
- the periodic split pass copies old column to credential table where the
  credential row is missing or older, and never clears;
- readers take the credential row whenever one exists, and the old column only
  when none does. A retired row (its host removed or re-admitted) reads as no
  secret, and no pass copies over it. A secret an unlatched node writes to the
  old column alone is absorbed into the credential row where it is applied.

So the old columns are always current. A host rolled back below
`credentials_split_v1` still enters WAL quarantine (the capability-rollback
preflight) and emits no replicated writes until it is upgraded again or
reseeded, so the rollback is not clean. What the two copies buy is that its
old-column reader still validates tokens, checks passwords and fences, and that
upgrading it again loses nothing. The cost is
that the public rows, and the operator-safe state dump, still carry every
secret. Taking them out of the dump is the step described here.

## The next release: `credentials_clear_v1`

A second token, `credentials_clear_v1`, with the same class as the first:

- **Mandatory.** It states a fact about the binary: *this build never needs the
  old column to find a secret*. That is not a policy an operator can decline,
  and a flag would stop it latching (`driveCapabilityActivation` skips a flag-off
  token that has not latched).
- **Replication-gated** (`capabilities.replicationGated`). The claim is about
  every host still receiving replication, including one parked in
  `maintenance`. The clear must not reach a host that would still read the old
  column. Confirming against voting members alone would clear the column out
  from under such a host.

Once `credentials_clear_v1` has durably latched on a node:

1. **Writers stop writing the old column.** They write the credential row and
   put `''` in the old column, in the same statement shapes this release
   already emits. They add no new shapes on `hosts`, `users` or `tokens`.
2. **The split pass clears.** For each parent row with a non-empty old column,
   one batch re-emits the credential row (so this node's stream carries the
   value ahead of the clear) and sets the old column to `''`. The clear shapes
   are `UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?`,
   `UPDATE tokens SET token_hash = ?, updated_at = ? WHERE id = ?` and the
   `hosts.ipmi_pass`-only ConfigureHost subset. All three are already in the
   receive ledger. The first two sit in the historical family
   `credentials_split_clear_v56`, retained because the pre-release clearing
   build emitted them. The next release moves them back to the generated
   ledger.
3. **The clear is stamped one microsecond past the parent row's own
   `updated_at`, not with a fresh clock.** Every node clears every row at about
   the moment the latch forms. With a fresh clock, a revoke or delete a peer
   issued just before, still in flight, would lose LWW to the clear, and
   anti-entropy would then spread the un-revoked row. The first clearing build
   had this rule and a test for it (`AnInFlightRevokeBeatsTheClear`, removed
   with it). Bring both back.
4. **Credential readers need no change** (but see the shadow-user guard
   below). They already take the credential row whenever
   one exists, so a cleared column is transparent to them. The absorb step
   already ignores empty values, so the clears are never absorbed. A reader
   that ignores the old column entirely is the release *after* this one, if
   ever.

## What a rollback from the clearing release costs

`credentials_clear_v1` cannot latch while any replication recipient runs a
build without it. A host rolled back from the clearing release lands on the
release before it, which is **this** release. That rollback is not clean
either: this release does not know `credentials_clear_v1`, so the startup
preflight puts the host under WAL quarantine, and it emits no replicated writes
until it is upgraded again or reseeded. But its readers still find every
secret. This release reads the credential row whenever one exists, so it
reads every secret from the credential rows the clearing release kept writing. Upgrading it again loses nothing.

A rollback two releases, to before `credentials_split_v1`, is not supported
once `credentials_clear_v1` has latched. That build reads only the old
columns. The startup rollback preflight (`preflightCapabilityRollback`)
refuses to start a binary that does not know a latched token, but only in
builds that carry the preflight. docs/upgrades.md must say so in that release.

## One consequence outside the credential readers

The anti-entropy refusal of a re-minted admin account
(`users_admin_guard.go`, colonelpanik/litevirt#224) recognised the refused
account's `user_credentials` row by VALUE: the refused `users` row carried the
same hash. A re-minting node that has latched the clear sends `''` there, so the
refusal is remembered by username instead, and the sensitive lane refuses a
`user_credentials` row for that username whose hash differs from the one the
receiving node holds — in the anti-entropy exchange with the peer that offered
the re-mint, and only there (`remintScope`). The peer keeps offering it until
an operator resolves the re-mint, so every exchange with it, including the
first after a restart, refuses again. The cost stays with that peer: a genuine
rotation of the account is still repaired from every other peer, and the WAL
lane delivers it as usual. A deliberate attacker with a host certificate can
therefore stop only its OWN copy of an account from repairing others.

A node rolled back one build recognises a cleared re-mint by nothing: its
refusal memory ignores an empty hash. Under WAL quarantine it still merges
anti-entropy, so during a re-mint incident it can take the re-minted
credential. docs/upgrades.md says to resolve a re-mint before rolling back.

## A second consequence: external-realm shadow users

`auth.EnsureUserShadow` refuses an LDAP or OIDC principal whose name belongs to
a local account, and a non-empty `password_hash` was what identified a local
account. After the clear every local account's old column is empty, and
anti-entropy can deliver its users row before its credential row. The guard
now reads the credential row (`corrosion.UserLocalCredential`) and refuses when
it cannot tell. An empty old column with no credential row is judged
"external" only on POSITIVE evidence, never from the absence of a cleared row
in view (`credentials_live.go`):

- the node created the shadow itself while it could not write a credential row
  yet (recorded node-locally, `credentials_external_seen`);
- or the node started on this build with its users rows already in its
  database (the credentials baseline, recorded once at first start), so its
  first split pass ran before any clear could exist — `credentials_clear_v1`
  is advertised only by a node that has completed that pass.

On that evidence the node's first pass gives each such user an empty
credential row stamped with the users row's own time moved 40 years back, which
replicates the evidence to every peer and never beats a real credential. A node that started with an empty database — every host added after
the clear — has no such evidence: it never materialises, and until a user's
credential row arrives it refuses an external login under that name
("its credential has not reached this node yet"). That is fail-closed and
lasts until its sensitive lane merges. A node whose gates open together
decides before its own clears are in view.

The evidence is PER USER and bound to the users row AS IT STOOD (username,
created_at and the row's own updated_at): the credentials baseline lists the
users that had an empty old column and no credential row in this node's own
database when this build first started on it (fsynced, bound to the state.db
incarnation, recorded before replication starts), and the external-seen set
lists the shadows this node created itself. created_at alone does not identify
an account: users rows are never hard-deleted, so `lv user rm` followed by
`lv user create` under the same name REACTIVATES the row and keeps its
created_at. Every write to the account moves the row's updated_at, and nothing
else writes the users table, so a local account cleared later never matches the
evidence, and neither does a name deleted and created again. The same holds
for the replicated evidence: an empty credential row counts only when it was
made no earlier than the users row's current version — a shadow writes both in
one batch at one timestamp, a first pass stamps the users row's own time 40
years back (the shift is fixed and undone on read), and a mark is stamped with
the time it was made, 40 years back. Evidence about an earlier version fails
closed: the login is refused (`Unavailable`, or `FailedPrecondition` naming
`lv user mark-external`), never adopted. This compares a row with its own
earlier stamp, or reads an empty credential row fail-closed against it; it
never chooses between a copy and its parent by `updated_at`.

Where no host holds evidence for a pre-split external user (its hosts were
replaced, not upgraded), an administrator states it with
`lv user mark-external`. The mark is refused while the host sees any local
credential for the name — a password in the old column, or a credential row
with one, live or tombstoned — and on a host whose replica has not caught up.
It holds for the users row as it stands when it is made: if the name is later
deleted and created again, the administrator decides again.

### Receivers never demote an account they cannot judge

A users row that arrives with a DIFFERENT created_at under a live account's
name is a different account, and receivers refuse it over a local account
(`users_admin_guard.go`). After the clear a local account whose credential row
lags reads as an empty old column with no credential row, so the receiver
judges the local row exactly as `UserLocalCredential` does and refuses unless it
KNOWS the row is external. In the same anti-entropy exchange, the refused
account's empty credential row is refused too: the account this node kept has
no credential in view to compare it with. Refusing is fail-closed; the row is
offered again by the next exchange and judged on what has arrived by then.
The cost: an external shadow this node holds no evidence for is judged the same
way, so if two hosts created a shadow for one new external user at the same
time (two created_at), a host that holds the older one keeps it until evidence
for it arrives (its credential row, after the split latches), and counts the
refusal (`admin_remint`). Both rows are viewer shadows; nothing is demoted.

### A shadow reactivation never wipes a local password

An external login whose name this node holds only as a tombstone reactivates
that row as a shadow. It is stamped two successor steps past the newest write
this node holds for the row or its credential, never with a fresh clock. One
step is what another node's clear of the same tombstone carries; two keep the
shadow strictly newer than both the tombstone and that clear. Any write a peer
made after the tombstone — the name created again as a local account, still in
flight — is newer still, so it wins on every node and the local account keeps
its password and role. With a fresh clock the shadow, written later in real
time, replaced it cluster-wide (pre-existing on main).

## Tests

- Fleet: after `credentials_clear_v1` latches on every node, no public row and
  no public dump carries a secret, and login, token and fence still work from
  every node.
- Fleet: a node on this release (credentials split latched, clear not) keeps
  authenticating against a peer that has cleared, which is the rollback half.
- Unit: an in-flight revoke beats the clear (the stamping rule above).
- Mutation: stamp the clear with a fresh clock, and the revoke test goes red.
  Drop the replication gate, and a maintenance-host fleet test goes red.
