# Clearing the old secret columns (next release)

Status: **proposed, not implemented.** This note records the second half of
the secret-column move (colonelpanik/litevirt#268) so that the release carrying
`credentials_split_v1` does not have to.

## Where this release leaves things

`credentials_split_v1` (mandatory, replication-gated) moves `hosts.ipmi_pass`,
`users.password_hash` and `tokens.token_hash` onto the sensitive lane as the
dual-write step of a column move
([upgrades.md](../upgrades.md#secrets-move-to-the-sensitive-lane-after-the-roll)):

- once latched, every writer writes the credential table **and** the old
  column, in one batch under one `updated_at`;
- the periodic split pass copies old column to credential table where the
  credential row is missing or older, and never clears;
- readers take the newer of the two copies.

So the old columns are always current. A host rolled back below
`credentials_split_v1` still enters WAL quarantine (the capability-rollback
preflight) and emits no replicated writes until it is upgraded again or
reseeded, so the rollback is not clean. What the two copies buy is that its
old-column reader still validates tokens, checks passwords and fences, and that
upgrading it again loses nothing. The cost is
that the public rows, and the operator-safe state dump, still carry every
secret. Taking them out of the dump is the step described here.

## The next release: `credentials_clear_v1`

A second token, proposed name `credentials_clear_v1`, with the same class as
the first:

- **Mandatory.** It states a fact about the binary: *this build never needs the
  old column to find a secret*. That is not a policy an operator can decline,
  and a flag would stop it latching (`driveCapabilityLatches` skips a flag-off
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
4. **Readers keep the newer-copy rule.** An empty old column never wins, so a
   cleared column is transparent to them. A reader that ignores the old column
   entirely is the release *after* this one, if ever. Keeping the rule costs
   one join column.

## What a rollback from the clearing release costs

`credentials_clear_v1` cannot latch while any replication recipient runs a
build without it. A host rolled back from the clearing release lands on the
release before it, which is **this** release. That rollback is not clean
either: this release does not know `credentials_clear_v1`, so the startup
preflight puts the host under WAL quarantine, and it emits no replicated writes
until it is upgraded again or reseeded. But its readers still find every
secret. This release reads the credential tables and takes the newer copy, and
an empty old column never wins, so it reads every secret from the credential
rows the clearing release kept writing. Upgrading it again loses nothing.

A rollback two releases, to before `credentials_split_v1`, is not supported
once `credentials_clear_v1` has latched. That build reads only the old
columns. The startup rollback preflight (`preflightCapabilityRollback`)
refuses to start a binary that does not know a latched token, but only in
builds that carry the preflight. docs/upgrades.md must say so in that release.

## Tests the next release needs

- Fleet: after `credentials_clear_v1` latches on every node, no public row and
  no public dump carries a secret, and login, token and fence still work from
  every node.
- Fleet: a node on this release (credentials split latched, clear not) keeps
  authenticating against a peer that has cleared, which is the rollback half.
- Unit: an in-flight revoke beats the clear (the stamping rule above).
- Mutation: stamp the clear with a fresh clock, and the revoke test goes red.
  Drop the replication gate, and a maintenance-host fleet test goes red.
