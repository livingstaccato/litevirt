# Binding auth rows to an account, not a username

Status: **accepted residual, fix proposed and not implemented.** This note records
what the re-minted-admin guard leaves open and the fix that would close it, so the
decision to leave it open is written down rather than rediscovered.

## What the guard already does

A node that mints an `admin` account while the cluster already has one produces a
DIFFERENT account under the same name. `users.created_at` tells the two apart: it is
written once, by the INSERT in `InsertUser`, and no update path touches it. Both
replication lanes refuse an incoming `users` INSERT whose `created_at` differs from
the live admin's (`internal/corrosion/users_admin_guard.go`), together with the
`user_credentials` upsert that travels beside it. `lv user reset-admin` keeps
`created_at` and replicates normally, so the legitimate replacement is unaffected.

The re-mint itself carries no factor rows. `InsertUser` emits the `users` INSERT and
the `user_credentials` upsert and nothing else, so refusing it leaves nothing behind.

## What it leaves open

The node whose re-mint was refused keeps its own `admin` account locally. Every
other auth table is keyed by username alone, so whatever that account does LATER is
indistinguishable from the cluster's admin doing it:

- **Factor enrollment.** `user_2fa`, `user_2fa_sets`, `recovery_codes` and
  `recovery_code_sets` carry no account identity. A TOTP enrollment or recovery-code
  set made there replicates as the real admin's and, being newer, wins
  last-writer-wins on the `*_sets` pointer. For TOTP and recovery codes that is a
  lockout: the real password is still required. A WebAuthn credential (stored in
  `user_2fa` with method `webauthn`) is worse: `FinishWebAuthnLogin` mints a
  session from the assertion alone, so it is an admin login on every node without
  the real password.
- **Password change on the WAL lane.** `UpdateUserPassword` sends a `users` UPDATE
  and a `user_credentials` upsert. The WAL guard inspects INSERTs only, which is
  sufficient for the invariant it enforces (no UPDATE writes `created_at`) but not for
  this one. Anti-entropy does catch it, because the different-account `users` row is
  judged again on every sync.

## Why it is accepted for now

Reaching it needs a node that minted an admin while the cluster had one. The
sender-side guard (a node with `join_peers` set declines to mint) and the joiner
rule already remove the ordinary path. What remains is an old `lv` binary
provisioning a node, or a node whose `join_peers` was reset, AND someone then logging
in to that node as `admin` and enrolling a factor. `adminRemintAdvice` and the join
guard already treat a node's admin as trusted to replace the cluster credential
through `lv user reset-admin`; refusing its factor enrollment is the same trust
question, and the answer chosen here is to leave that trust where it is.

## The fix (option 1)

Give every auth row the identity of the account it belongs to, and refuse a row whose
identity is not the live account's.

1. Add an `account_created_at` column to `user_credentials`, `user_2fa`,
   `user_2fa_sets`, `recovery_codes` and `recovery_code_sets`, written
   from the owning `users.created_at` in the same batch.
2. Both lanes refuse an incoming auth row whose `account_created_at` does not match
   the local `users.created_at` for that username, with the same counting and logging
   the `users` guard does (`adminRemintAdvice`). A row with no value (written by an
   older build) is accepted, as today.
3. The WAL lane also refuses a `users` UPDATE from a node whose own `users` row for
   that name has a different `created_at`. That needs the sender's identity in the
   entry, which the column above provides on the paired `user_credentials` upsert.

This changes the wire shape of credential tables, so it cannot be an edit to the
apply path alone: a mixed-version cluster would disagree about what a row means. It
needs a `capabilities.ReplicationGated` token, the way `credentials_split_v1` and
`lease_term_ledger_v1` got one. Refusal starts only once the token latches; until then
every node writes the column and nobody refuses on it, so a rolling upgrade loses
nothing.

The rejected alternative was remembering which node offered a refused re-mint and
refusing its later auth writes for that username. Anti-entropy rows carry no origin,
and the memory is lost on restart, so it would cover one lane until the next restart.
