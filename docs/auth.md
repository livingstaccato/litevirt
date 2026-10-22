# Authentication & authorization

litevirt's auth model has two halves:

- **Authentication** asks "who are you?". A *realm* validates the
  credentials and returns a *Principal* (subject + groups).
- **Authorization** asks "may you do this?". A *path-based RBAC engine*
  evaluates role-bindings to grant or deny each operation.

Tokens, sessions, and 2FA all sit on top of these primitives.

## Realms

A realm is a pluggable authentication backend. Three are shipped:

| Realm | Name format | When to use |
|---|---|---|
| Local | `local` | Single-cluster, small team. Bcrypt passwords stored in the cluster DB. Always present. |
| OIDC | `oidc:<short-name>` | Federated SSO with corporate IdPs (Okta, Auth0, Keycloak, Azure AD, Google Workspace). Auth-code flow with PKCE. |
| LDAP / AD | `ldap:<short-name>` | On-prem Active Directory or OpenLDAP. Search-then-bind; group memberships pulled from `memberOf` (or a follow-up search). |

Realms are configured under `auth.realms:` in `/etc/litevirt/config.yaml`
— see `docs/configuration.md` for the YAML shape. Group memberships are read
at login (the OIDC groups claim, the LDAP group search); nothing refreshes
them in between (below).

Roles map to *principal IDs*: `user:<subject>@<realm>`, the legacy-role
group `group:<role>@<realm>` (`admin`, `operator`, `viewer`), and a directory
group `group:<realm>/<group>`. Bind a role to a principal in the engine and the
caller gets the role's verbs at the binding's path.

### Directory group bindings

A role bound to `group:<realm>/<group>` applies to every session whose login
through that LDAP or OIDC realm verified membership of `<group>`:

- **OIDC:** the group is a value of `groups_claim` in the verified ID token,
  as the IdP sends it: `group:oidc:kanidm/lv-operators`.
- **LDAP:** the group is its **full DN**, normalized: lower case, no spaces
  around separators, RFC 4514 escaping. For example,
  `group:ldap:corp/cn=lv-operators,ou=groups,dc=corp,dc=example`. Groups come
  from `user_group_attr` (`memberOf`) and from the group search. With
  `group_base_dn` set, only groups at or under it count, `memberOf` included.
  A `cn` is unique only within its container, so a same-named group in another
  OU is a different principal, never the managed one. A `memberOf` value that is
  not a DN is ignored.

```bash
lv role grant Operator group:oidc:kanidm/lv-operators --path /projects/acme --propagate
lv role grant Viewer   group:ldap:corp/cn=contractors,ou=groups,dc=corp,dc=example --path /projects/acme
```

**Trust boundary.** A group binding trusts whoever can create a group, or add
members to it, at the directory. A user who can create a group named like a
bound one and join it holds that binding. Bind only groups that directory
administrators alone manage:

- restrict the OIDC groups claim to admin-managed groups (a Keycloak group
  mapper on a managed subtree, Entra "groups assigned to the application", a
  kanidm claim map listing specific groups);
- for LDAP, point `group_base_dn` at the OU only administrators write.

A directory group never equals a legacy-role principal: an IdP group named
`admin` is `group:oidc:corp/admin`, not `group:admin@oidc:corp`, so it cannot
take on bindings meant for the realm's legacy admins. A binding written in the
earlier `group:<g>@<realm>` form names a legacy role, not a directory group;
re-grant it as `group:<realm>/<g>`.

- **Union.** A session holds every grant of its user binding, of its legacy
  role's `group:<role>@<realm>`, and of each of its directory groups. No
  binding subtracts. Holding any binding switches the caller from the legacy
  role to the bindings, as for user bindings.
- **Per session, fixed at login.** The groups are recorded with the session,
  in the same replicated batch (`session_groups`, schema v66), so every node
  evaluates the same groups for it.
  - A group the directory removes stops granting at the user's **next login**.
  - A session minted before keeps its groups until it ends: the idle timeout
    (default 8h), the hard expiry (default 7d, at most 30 days:
    `session_hard_expiry` above `720h` is clamped to `720h`, with a startup
    warning naming the configured and effective values), logout,
    `lv session revoke`, or any account lifecycle change (`lv user disable`).
  - To cut a removed member off at once, revoke their sessions.
  - A group added at the directory applies from the next login.
- **Only sessions carry groups.** API tokens, and actions re-checked later
  for a stored user (an upload's owner), carry no directory groups. They run on
  the user's own bindings and legacy role.
- **Audited.** Each external login with groups writes `auth.group_bindings`:
  - the number of groups, and each group binding they hold (principal, role,
    path, binding id);
  - the groups that hold no binding, as a count and a hash of their names;
  - `skipped` when the groups were not recorded (below).

  The detail is capped at 4 KB.
- **Visible to the user.** `lv role ls` run by a non-admin lists the bindings
  that apply through their session's groups along with their own.
- **Release feature.** The groups are written only once the `login_policy`
  release feature is open (`lv cluster upgrade-status`). Before that, a login
  records none, and group bindings apply to nobody, as on the previous release.
  Once it is open on a node, a login whose groups that node cannot record is
  **refused** (`Unavailable`, retry). It is never minted without them, because
  such a session would fall back to the legacy role.
- **Bounds.** At most 256 groups of at most 256 bytes are recorded per session.
  Names with control characters or invalid UTF-8 are dropped and logged, as are
  any over the limits.
- **Local realm.** It has no directory groups.
- **Unreadable groups.** If a session's recorded groups cannot be read, or name
  another realm, its requests are refused (`Unavailable`), not authorized
  without them: dropping a group can widen a caller back to its legacy role.

### External users and local accounts share one name space

A user's first LDAP or OIDC login creates a row in the users table with no
local password (a "shadow"), so roles and audit can name it. Because users
are keyed by name alone, an external login is refused when the name belongs
to a local account, which would otherwise hand the external principal that
account's role.

Once `credentials_clear_v1` has latched (docs/upgrades.md), every local
account's users row also has an empty password column, so a host decides
"external" only on positive evidence: an empty credential row for the user,
written when the shadow was made after `credentials_split_v1`, by a host's
first split pass for a shadow that host could vouch for, or by an
administrator. When a host cannot tell, the login is refused:

- `Unavailable` ("retry") while the host has not synced or not finished its
  first credentials pass: retry, or log in through another host;
- `FailedPrecondition`, naming the command below, when the host is up to date
  and still holds no evidence. That is an external user created before
  `credentials_split_v1` latched on a host that has since been removed without
  running this build. If the user is external, an administrator marks it:

  ```bash
  lv user mark-external <username>
  ```

  The command is audited (`user.mark-external`, refusals included),
  admin-only, refused while the host it runs on sees any local password for
  the name (in the users row, or in a credential row, live or deleted), and
  refused while that host has not caught up with its peers. The mark is an
  empty credential row with a timestamp older than any real write, so it never
  replaces a password. It holds for the account as it stands when it is made:
  if the user is deleted and created again, the login is refused again until an
  administrator decides again.

A host that has not synced its users table yet also refuses to create a NEW
shadow (`Unavailable`): "no row under this name" there may only mean the
local account has not arrived, and the new row would replace it everywhere.

### OIDC realm keys

Under `auth.realms[].oidc:`. `issuer_url`, `client_id`, and `redirect_url` are
required; prefer `client_secret_file` (checked for 0600 at load) over inlining
`client_secret`.

| Key | Purpose |
|---|---|
| `redirect_url` | This node's web UI callback, `https://<this node's UI>/oidc/callback`. **Per node**: the login must come back to the node that began it (below). Must be `https` (plain `http` only to a loopback address); a login is refused to begin otherwise. Register every node's URL with the IdP. |
| `cli_redirect_url` | The loopback address `lv login --realm oidc:<name>` listens on, `http://127.0.0.1:<port>/<path>` (RFC 8252 §7.3): IPv4 loopback, an explicit port, no query. Checked at load. Unset: the CLI sign-in is off for this realm (the web UI still works). Register it with the IdP too. |
| `ca_file` | PEM CA bundle the IdP's certificate must chain to (discovery, JWKS and the token endpoint). Unset: the system trust store. Verification is never skipped. |
| `scopes` | Scopes to request. Default `openid profile email groups`; `openid` is always added. |
| `groups_claim` | Token claim carrying group membership; each value becomes a `group:<realm>/<value>` principal of the session ("Directory group bindings"). Restrict it to admin-managed groups. |
| `subject_claim` | Claim used as the stable subject — the `user:<subject>@<realm>` principal. Override when `sub` is an opaque id and you want a readable, stable alternative. |
| `email_claim` | Claim read as the user's email address. |
| `name_claim` | Claim read as the user's display name. |

The claim overrides exist because IdPs disagree on claim names. Changing
`subject_claim` on a live realm re-keys every principal id, so existing role
bindings stop matching — rebind before switching it.

### OIDC sign-in

The flow is the authorization code flow with PKCE (S256 only) and a nonce.

**Web UI.** The login page shows a *Sign in with oidc:&lt;name&gt;* button for
each OIDC realm (`GET /oidc/login?realm=oidc:<name>`). The node:

1. begins a flow (`BeginOIDCLogin`): 256 random bits of state, a PKCE verifier,
   a nonce and a separate **binding secret**, held in memory **on that node
   only**, single-use, for 10 minutes;
2. binds the flow to the browser: the binding secret goes into a short-lived
   `HttpOnly`, `SameSite=Lax`, `Path=/` cookie. It is never put in a URL. The
   cookie's kind follows the realm's `redirect_url` (the URL the browser comes
   back on), not the request. With an https redirect it is
   `__Host-lv_oidc_flow`: `Secure`, no `Domain`, so a sibling host cannot
   plant one. The callback then accepts only that cookie, even when a TLS
   proxy omits `X-Forwarded-Proto`. A plain-http redirect is allowed only to a
   loopback address (a developer's own machine). There the cookie is the
   unprefixed, non-`Secure` `lv_oidc_flow`;
3. sends the browser to the IdP.

In-progress sign-ins are bounded, and beginning one is never refused:

- **Per client address: 16.** An IPv6 client counts by its /64. An address
  over its bound loses its own oldest sign-in, so clients sharing an address
  (a NAT, or a proxy without `trusted_proxies`) cannot lock each other out
  with a handful of requests.
- **Per realm: 4096.** When the realm's table is full, one sign-in is
  dropped. Which one is chosen in three steps:
  1. the network holding the most sign-ins: an IPv6 /48 or an IPv4 /24;
  2. within it, the client address (above) holding the most;
  3. that address's oldest sign-in.

  A flood spread over many addresses of one network therefore counts as one
  heavy network, and a user from another network outlasts it. Ties go to the
  candidate whose newest sign-in is the oldest. Among equally loaded
  networks that is first in, first out, so every sign-in, including one
  begun during a flood, lasts at least one turnover of the table: about
  4096/R seconds while sign-ins begin at R per second. The networks are used
  only to choose what to drop, never to refuse.

  Limits, all availability only (password, LDAP and local logins are
  unaffected):
  - A legitimate NAT that shares a /24 with an attacker is dropped along
    with it.
  - An attacker holding at least as many networks as the bound (4096 /24s
    or /48s, for example a botnet or a large IPv6 allocation) keeps every
    network at one sign-in and ties with everyone. It can then shorten every
    OIDC sign-in's window to about 4096/R. At a few hundred requests per
    second that is shorter than a round trip to the IdP, and OIDC sign-in on
    that node fails while the flood lasts.

The client address is:
- for the web UI and the REST gateway, the TCP peer. When that peer is in
  `trusted_proxies` (below), it is the right-most `X-Forwarded-For` hop that is
  not itself a trusted proxy.
- for a direct gRPC caller, its own address. A `client_address` it sends is
  honoured only from a caller presenting a cluster **host** certificate over
  loopback (the `local-root` identity). That is this node's own UI and REST
  gateway, which dial with the host certificate; a process that can read a
  host key on the node is root there anyway. The distributable `lv-cli`
  certificate, or no certificate, over loopback is an ordinary client: its
  `client_address` is ignored and it is counted at its own address.

**Behind a reverse proxy**, list the proxy in `trusted_proxies` (CIDRs or
addresses, default empty). Without it, every browser arrives from the proxy's
one address and shares its bound. Two warnings point at this:
- the daemon warns at startup when an OIDC realm is configured, the UI is
  bound to loopback, and `trusted_proxies` is empty;
- the UI warns when a sign-in arrives with `X-Forwarded-For` from a peer
  that is not listed. This catches a proxy on another host. It warns at most
  every 10 minutes for each peer, and remembers the last 16 peers, so a
  client that reaches the UI directly and sends the header cannot hide the
  proxy's warning.

Requirements on the proxy:
- It must **append** the client's address to `X-Forwarded-For`, or overwrite
  the header. A proxy that passes the client's own header through unchanged
  lets every client choose its own address.
- Hops are read as addresses, with an `:port` suffix dropped. A hop that is not
  an address (`unknown`, an obfuscated name) is not believed; the address of
  the proxy that recorded it is used instead.

Never list an address that clients can reach directly: a forwarding header
is believed only from a listed proxy. Listing `127.0.0.1`, as a proxy on the
node itself needs, trusts every local process on that node to name a client
address to the UI and the REST gateway, with no cluster certificate needed.
Do it only on a node where local users are trusted that far.

The IdP returns the browser to `redirect_url`. `GET /oidc/callback` then calls
`Login` with the code, the state and the cookie's binding secret on the same
node. The node:

- consumes the flow (single use), then refuses it unless the binding secret is
  the one its beginner was given — before the code is presented to the IdP. A
  callback from a browser that did not begin the login (login CSRF), or a code
  and state lifted from a URL or a log, therefore redeem nothing, and the flow
  is spent;
- exchanges the code with the verifier and the client secret, and verifies the
  ID token against the discovery document's JWKS: signature, issuer, audience
  (`client_id`; `azp`, when present or when there are several audiences, must
  be `client_id`), expiry, and the flow's nonce.
- maps the principal (`subject_claim`) and creates the session exactly as a
  password login does: the external shadow user, the directory identity
  binding, the account lifecycle, and the login policy below.

The callback answers with `Cache-Control: no-store` and
`Referrer-Policy: no-referrer`. The code, the state, the binding secret and
the session token are never logged and never put in another URL. The login
page shows only fixed messages: no text from the IdP (`error`,
`error_description`, error bodies), from a crafted link, or from the daemon's
refusal (which can name the account) reaches it — the detail is in the daemon
log and the audit log.

**Logging out.** `lv logout` and the UI's *Log out* end the litevirt session
only. The identity provider's own session is untouched, so on a shared
workstation the next *Sign in with* may sign in as the previous user without a
prompt. Sign out at the identity provider too, or configure it to always ask
(`prompt=login`-style policies on its side).

**The login must finish on the node that began it.** A callback that reaches
another node finds no flow and is refused (`Unauthenticated`, "state unknown
... on this node"); the code is not presented to the IdP. Give each node its
own `redirect_url` naming itself. Behind a load balancer, pin `/oidc/` to one
node (sticky sessions), and list the balancer in `trusted_proxies`.

**CLI.** `lv login --realm oidc:<name>` asks the node it is connected to for a
CLI flow. The node returns the IdP URL and the realm's `cli_redirect_url`. lv
then:

- listens on that loopback address;
- opens the URL in a browser on the same machine (`--no-browser` prints it
  instead);
- accepts only the flow's own state on the configured path;
- keeps the flow's binding secret in memory and sends it with the code.

It completes the login on the same node. The code goes only to the user's
loopback and to the node; the client secret stays on the node. A remote shell
needs the loopback forwarded, e.g. `ssh -L 18765:127.0.0.1:18765`. The IdP must
list `cli_redirect_url` as a redirect URI for the client.

**API.** `BeginOIDCLogin` (REST `POST /api/v1/auth/oidc/begin`,
`{realm, client}`) returns `auth_url`, `state` and `binding`; then `Login` with
`oidc_code`, `oidc_state` and `oidc_binding` on the same node. Keep `binding`
out of URLs and logs. `client` is `web` (the default) or `cli`. The redirect is always the
realm's configured one for that client; a caller cannot choose it. An
`oidc_redirect_uri` sent to `Login` must equal it.

**Second factor.** The login policy (below) applies to an OIDC login exactly as
it does to a password login. litevirt does not read the IdP's `amr`/`acr`
claims: an IdP that did its own MFA does not stand in for the account's
litevirt factor. The OIDC code is single-use, so when a covered user with a
factor signs in without one, `Login` answers `requires_2fa` with an
`oidc_pending` handle and mints no session. The handle is node-local, lasts 5
minutes and allows 5 attempts, reserved atomically, so concurrent guesses
cannot exceed them. Send it back with `realm` and `totp_code` (the
web UI asks for the code; `lv login` prompts). A client may still send
`totp_code` together with the code in one call.

### LDAP / AD realm keys

Under `auth.realms[].ldap:`. `url` and `user_base_dn` are required; prefer
`bind_password_file` over inlining `bind_password`.

| Key | Purpose |
|---|---|
| `user_filter` | LDAP filter selecting the typed user's entry; `%s` stands for the typed name, e.g. `(&(objectClass=person)(uid=%s))`. Without `user_login_attr`, the attribute `%s` is compared against is the one whose value must equal the typed name, so a filter with no `%s` — `(objectClass=person)` alone — matches no login, and one with `%s` inside a longer value (`(userPrincipalName=%s@corp.example)`) needs `user_login_attr` (see the upgrade note in docs/upgrades.md). |
| `group_base_dn` | Subtree searched for groups. |
| `group_filter` | LDAP filter selecting group entries. |
| `user_login_attr` | Attribute that must hold the typed login name. When set, the entry must carry it with exactly one value, equal to the typed name ignoring ASCII case and surrounding spaces; an entry where it is missing or multi-valued is refused, with no fall-through to other attributes. Unset: some value of an attribute `user_filter` matches the typed name against (`(uid=%s)` → `uid`), or the entry DN's RDN when its attribute is one of those, must equal the typed name that way. A directory that matched the filter by a looser rule (width or accent folding, a second attribute) does not log in. |
| `user_name_attr` | Attribute read as the display name. |
| `user_mail_attr` | Attribute read as the email address. |
| `user_group_attr` | Attribute on the user entry listing group membership (typically `memberOf`). |
| `group_name_attr` | Attribute on a group entry holding its name. Not used for group principals: groups are keyed by their DN ("Directory group bindings"). |
| `skip_tls_verify` | Disables certificate verification on the LDAPS connection. **Leave off outside a lab** — it makes directory traffic, including bind credentials, trivially interceptable. |

The account is named by the typed login name, normalized (ASCII lower case,
surrounding spaces trimmed), exactly as before this release: upgrading re-keys
no account. Moving or renaming a group entry changes its DN, and so its
principal: re-grant its bindings.

**Directory identity binding.** An LDAP or OIDC account is bound to the
directory entry it is reached through, by an id the directory never reuses:
for LDAP the entry's `entryUUID` (OpenLDAP), `objectGUID` (Active Directory)
or `nsUniqueId` (389 DS), and only when the entry has none of those, its full
DN (lower-cased) — a weaker id, since a renamed or moved entry gets a new one;
for OIDC the token's issuer and subject. The binding is written on the
account's first successful login after the upgrade (once the release feature
`login_policy` has opened; before that, logins proceed unbound, as on the
previous release).
After that, a login that name-matches the account through an entry with a
different id is refused with `PermissionDenied` and audited as
`auth.identity_mismatch`, whatever its password; and one entry is never bound
to two accounts of a realm, so a second name on the same entry (a second
`uid` value, another attribute) cannot log in as another account. The search
for the typed name must return exactly one entry, or the login is refused.
When the directory re-creates a user's entry (a new id), an admin clears the
binding with `lv user unbind <username> <realm>` (audited as
`user.identity_unbind`), and the next login binds to the entry it comes
through; a refused login's message names that command with its arguments.
Deleting the account clears its bindings too. For one spelling of a
case-duplicate pair, pass the exact stored name (`lv user delete --exact
<name>` lists them).

*Every id the entry carries counts.* An LDAP account bound under one id still
logs in when the directory starts returning another one first — 389 DS
enabling its `entryUUID` plugin, an ACL change that exposes `entryUUID` where
only `nsUniqueId` or the DN was readable: the binding holds when it equals
any of the entry's `entryUUID`, `objectGUID` and `nsUniqueId`, or its DN when
the binding itself was made by DN. A DN never stands in for an immutable id,
so an entry deleted and re-created at the same DN is still refused. These
attributes must be server-assigned (they are on OpenLDAP, Active Directory and
389 DS); a schema that lets users write them would let one entry claim
another's id. OIDC has no second id: changing the provider's issuer URL
changes every account's id, and each account then needs `lv user unbind
<name> oidc:<realm>` (or keep the old issuer URL).

*First binder wins.* A node that has not yet received an account's binding
(replication lag, a partition) binds the entry that logs in through it. That
binding is added beside the first rather than replacing it: every node
resolves the bindings the same way, and the earliest holds when every other
was made more than 5 s (`SessionCutoffSkewMargin`) after it. A login through
the binding that holds clears the later ones. Bindings closer together than
that cannot be ordered by clocks, so neither holds: the account's logins
through that realm are refused, naming `lv user unbind <name> <realm>`, until
an admin clears them. Every conflict is audited as `auth.identity_conflict`.
One entry bound to two accounts by two nodes is decided the same way. A
session minted through the later binding on the lagging node, before the
first binding reached it, ends when a login through the binding that holds
clears the later ones: that login also sets the account's session cut-off,
so every other session of the account from before it ends too (one logout
of the legitimate user's other sessions, once per conflict). Until that
login it lives, unless an admin revokes it (`lv session revoke`, or
`lv user disable`).

*Bindings are per realm.* An account bound in `ldap:corp` is still reachable
by a first login of the same name through any other external realm, which
binds it there: the name, not the realm, is the account (as on the previous
release, `EnsureUserShadow`). One person using two realms is legitimate, but
two external realms whose namespaces overlap and are governed differently hand
accounts across: a name created in the laxer directory logs in as the account
the stricter one's user owns. Configure such realms only with disjoint
namespaces.

## Path-based RBAC

Resources live under a tree:

```
/
├── hosts/<host-name>
├── projects/<project>
│   └── vms/<vm-name>
├── storage/<pool>
└── sdn/zones/<zone>            (planned)
```

Project paths are live — projects ship as a tenancy bucket; see
`docs/tenancy.md` for `lv project create`, hierarchical names like
`/projects/acme/team-foo`, and quota admission.

A role is a list of *verb wildcards*:

- `*` — every verb
- `vm.*` — every verb in the `vm` namespace (`vm.start`, `vm.read`, …)
- `*.read` — read on every namespace
- `vm.start` — exact verb

Built-in roles (seeded by `auth.SeedBuiltinRoles`):

| Role | Verbs |
|---|---|
| Admin | `*` |
| Operator | `vm.*`, `ct.*`, `network.{read,create,delete}`, `lb.*`, `image.{read,pull,import,push,build}`, `backup.*`, `snapshot.*`, `sg.read`, `audit.read`, `host.read`, `storage.pool.{read,write}`, `storage.content.{read,write}`, `resourcemap.{read,write}`, `cluster.lww.acknowledge` |
| VMOperator | `vm.{start,stop,restart,console,read,exec}` |
| Viewer | `*.read` |
| Auditor | `*.read`, `audit.export` |
| BackupOperator | `backup.*`, `snapshot.*`, `vm.read` |
| NetworkAdmin | `network.*`, `lb.*`, `sg.*` |
| ContainerRoot | `ct.exec`, `ctroot.exec` (exec in, and a compose image change of, a privileged or legacy-confined container; bind it on one container's path) |
| PermissionAdmin | `perm.modify` (delegated administration; see below) |
| NoAccess | (none): grants nothing and denies nothing (bindings are union-only); it keeps a principal bound, off its legacy-role fallback |

`--allow-overcommit` (CreateVM/StartVM/UpdateVM) additionally requires
`vm.overcommit`: bypassing the host capacity check is an operator-level
judgment call, so a binding granting only lifecycle verbs (e.g. VMOperator)
cannot invoke it. Wildcard grants (`vm.*`, `*`) carry it; clusters on the
legacy role model (no bindings) are unchanged — any operator may pass it.

`lv ct exec` in a **privileged or legacy-confined container**, and a compose
recreate that changes such a container's image, additionally require
`ctroot.exec` on the container (`/projects/<p>/containers/<name>`). It is
outside the `ct` namespace, so Operator's `ct.*` does not carry it: Admin holds
it through `*`, and an Admin grants it for one container with
`lv role grant ContainerRoot <principal> --path /projects/<p>/containers/<name>`.
No `*.<verb>` grant carries it (a role written as `*.exec` covers `vm.exec`
and `ct.exec` only); `ctroot.*` does. A delegated `PermissionAdmin` cannot
grant it without holding it. The container's own host checks a forwarded
exec against its own record of the container as well. Without
bindings the floor is `admin`. Exec in an unprivileged container with default
confinement needs `ct.exec` only, as before. See
[containers.md](containers.md).

A *binding* attaches a role to a principal at a path. With
`--propagate` the binding applies to that path and all descendants —
this is how the `Admin` role on `/` grants cluster-wide superuser
access.

### Cluster-global vs project-scoped verbs

Some resources are cluster-global, not project-scoped, and their RPCs are
checked at the root path `/` — so a token whose scope is limited to a project
(e.g. `/projects/acme`) cannot reach them, while an operator with a `/`-rooted
binding can:

- **Images** are a shared base-image library: `image.{pull,import,push,build}`
  are checked at `/`. (Override with project-scoped image namespaces if needed.)
- **Storage pools** (`storage.pool.*`, configure host mounts/sources) and their
  **contents** (`storage.content.*`, file upload/list/delete) are both checked at the
  pool's project path via `poolRBACPathFor`: `/storage_pools/<name>` for a global pool
  (top-level — effectively a root/global grant, matching their real-infra authority),
  `/projects/<p>/storage_pools/<name>` for a project-owned one. Intra-cluster content
  calls (an entry-node forward, cross-host replication, auto-promote) authenticate as a
  cluster host cert and bypass this tenant check — a deliberate peer-trust boundary:
  any known cluster host cert can reach pool contents via these RPCs.
- **Host filesystem paths in storage** (`storage.hostpath`) are checked at `/`.
  A pool or compose volume that names a directory or file on the host (a `dir`
  pool, a `--target`, a btrfs source, NFS mount options, a Ceph conf or
  keyring), any network-backed pool (`nfs`, `ceph`, `iscsi`), any pool on
  host block storage (`zfs`, `lvm-thin`), a compose
  `backup-repos:` path, a custom absolute `repo_path`, and any `target_path` on
  a restore or `ReplicateVolume` RPC (a bare name included), and an import's
  `--server-path` or `--disk-map` outside `<data_dir>/imports/staging` all need
  it, because the daemon reads and writes there as root (the legacy `admin`
  role keeps it too, as before). Only `Admin` holds it (through `*`): `Operator` holds
  `storage.pool.write` but not this, at any path. A custom role gets it by
  naming it or `storage.*`. Without bindings the floor is `admin`. Using a pool
  an admin created — disks on a `zfs` or `lvm-thin` pool included — needs only
  the project's ordinary VM and disk permissions. See
  [storage.md](storage.md#host-paths).
- **Installer ISOs** (`VMSpec.iso`) are a read of a host file by the guest, so a
  VM names one from a library as `pool/file.iso`. The global library `isos` is
  open to every VM and written only with `storage.library.write` at `/` (Admin);
  any other pool needs `storage.content.read` on it (and its project's VMs only),
  and is written with `storage.content.write`. A pool the host refuses offers
  no ISO. An absolute host path needs `storage.hostpath` at `/`, which only
  Admin holds, as does `lv iso pull --from-host-path`. See
  [storage.md](storage.md#installer-isos).
- **Security groups** (`sg.write`: `lv sg create/rm/rule-add/rule-rm`) are
  cluster-global, bound to NICs by name, and checked at `/`. Admin and
  NetworkAdmin hold `sg.write`; Operator holds only `sg.read`. Binding groups to
  a NIC (`lv sg bind`) is `network.update` on the VM's own path. Cluster and
  host rules, ip sets and default policies (`lv firewall cluster-rule`,
  `host-rule`, `ipset` and `default-deny`) are global too, and their writes
  need `sg.write` at `/` as well.
- **The firewall log** (`firewall.log.view`: `lv firewall log`) is checked at
  `/`. A record names any tenant's addresses and ports, so no built-in role but
  Admin holds the verb: `*.read` does not match it (Viewer, Auditor), nor does
  `sg.*` (NetworkAdmin). Grant it through a custom role holding
  `firewall.log.view`. With no role bindings the legacy fallback is admin.
- **Backup repository maintenance** (`backup.verify`, `backup.gc`,
  `backup.prune`, `backup.sync`, `backup.compression`) is checked at `/`. These are the
  `VerifyBackupRepo`, `GarbageCollectBackupRepo`, `PruneBackupRepo` and
  `SyncBackupRepo` RPCs, which the web UI's `/backups` actions call. A repo holds
  every project's backups, so a project-scoped grant cannot reach it. Operator
  and BackupOperator hold all four through `backup.*`. Viewer holds none:
  `backup.verify` is deliberately not a `*.read` verb, because a verify re-reads
  every chunk in the repo. Without bindings the floor is `operator`. See
  [backups.md](backups.md#repo-maintenance-rpcs).
- **Networks** (`network.create`, `network.delete`) and **resource mappings**
  (`resourcemap.*`, PCI/device pools) are cluster-global, checked at `/`.
- **Acknowledging a contested leader-lease term**
  (`cluster.lww.acknowledge`, `lv cluster acknowledge-lease-term`) is checked at
  `/`. It is the only `cluster.*` verb Operator holds, and deliberately not
  `cluster.update`: it clears one node's evidence tracking and elects no winner,
  so it is a day-to-day remedy rather than a cluster mutation. The RPC is
  node-local and refuses peer certs — see
  [operating-model.md](operating-model.md#clearing-the-condition-once-you-have-seen-it).

> **Content RBAC path:** storage-pool content ops are checked on the project-scoped path
> above, not on the flat path `/storage/pools/<name>`. An explicit `storage.content.*` grant
> on the flat path does not apply; issue it on the project-scoped path (admin / role-floor grants are unaffected).
> The check runs on the **entry** node a user authenticates to, so the isolation holds
> only where those nodes run this build — an entry node on an older build checks the flat path.

Interactive guest access — **console, VNC, and SPICE** — requires `vm.console`
on the specific VM's project path (`/projects/<project>/vms/<name>`), not just a
broad operator role.

```bash
lv role grant Admin    group:admin@local        --path /                --propagate
lv role grant Operator group:oidc:corp/eng      --path /projects/acme   --propagate
lv role grant Viewer   group:ldap:corp/cn=contractors,ou=groups,dc=corp,dc=example --path /projects/acme
```

`lv role ls` lists bindings (admins see all; non-admins see their own
only — server-side filtered). `lv role revoke <binding-id>` soft-deletes
a row by id.

Grants and revokes take effect **immediately**, without a daemon restart: a
grant reloads the engine synchronously, a revoke applies as an in-memory delta
(so it holds even if a subsequent reload fails, while the row tombstone keeps a
later reload from resurrecting it), and a ~30s backstop reload picks up bindings
mutated on a **peer** — the effective bound on a peer-side change is one
successful reload interval after it becomes locally visible. Deleting a user
tombstones that user's role bindings in the same transaction, so a deleted
account cannot retain access through a lingering binding.

### Delegated administration (`perm.modify`)

`GrantRole` and `RevokeRole` are open to a cluster admin, and to any caller
holding `perm.modify` at the binding's path (Proxmox: `Permissions.Modify`).
The grant has to name it — `perm.modify` or `perm.*` — so an `Admin` (`*`)
binding on a project means full control of what is under it, but not the
right to hand out roles there.
The built-in `PermissionAdmin` role carries it alone, so a project admin is two
bindings:

```bash
lv role grant Operator        user:pat@local --path /projects/acme --propagate
lv role grant PermissionAdmin user:pat@local --path /projects/acme --propagate
```

pat can now grant and revoke roles at `/projects/acme` and below. A delegated
grant or revoke is refused, and audited as `denied`, when:

- **the role carries more than the grantor holds there.** Every grant in the
  role must be covered by one the grantor holds at that path: `vm.*` covers
  `vm.start`, `*.read` covers `vm.read`, only `*` covers `*`. A list of
  specific reads does not cover `*.read`, so an Operator cannot hand out
  Viewer. Delegating delegation is allowed, because pat holds `perm.modify`.
- **it propagates and the grantor's own grant does not.** A propagating grant
  at a path reaches every path below it, so it is measured against the
  grantor's propagating bindings only.
- **the path is outside the grantor's reach,** including through a sibling
  prefix (`/projects/acme2`), a `.`/`..`/empty segment, or a scoped API token
  whose scope does not cover it.
- **it would be the principal's first binding.** A principal with no binding
  is authorized by its legacy role cluster-wide; its first binding ends that,
  which changes its access outside the delegated path, so only a cluster
  admin may.
- **it revokes a `NoAccess` sentinel** (below); only a cluster admin removes
  one.
- **the principal is not resolvable:** a delegated grant names an existing
  user with its realm (`user:<name>@<realm>`) or a group, never a bare
  `user:<name>`, an unknown user, or an undefined role.

A delegated revoke never empties a principal: in the same write it removes the
binding and binds `NoAccess` for the same principal at the same path. A
principal left with no binding at all would fall back to its legacy role
cluster-wide — a legacy operator pinned to one project would become a
cluster-wide operator again — and a "not the last binding" check could be beaten
by two revokes on two nodes before either saw the other. Each revoke leaves its
own sentinel, so that cannot happen in any order. Every delegated decision reads
the bindings from the node's database at that moment, not the engine's
periodically reloaded copy.

A delegated revoke of a binding outside the caller's reach answers exactly as
for a binding that does not exist. `lv role ls` shows a delegated admin its own
bindings and those at the paths it administers. Bindings carry no record of who
granted them: revoking a delegate's `PermissionAdmin` does not revoke what it
granted, and a delegate may delegate further within its subtree (as in
Proxmox). A cluster admin who later widens a custom role widens every binding of
it, delegated ones included; check `lv role ls --role <role>` before editing
one.

## Sessions

`Login` mints an opaque session id (32 random bytes hex-encoded, prefixed
with `lvs_` on the wire so the auth interceptor distinguishes them from
API tokens). The session is stored in the cluster's `sessions`
table with three lifecycle markers:

- **Hard expiry** — 7 days after issue. Cannot be extended.
- **Idle timeout** — 8 hours of inactivity. Each authenticated RPC
  touches `last_used_at`. Idle sessions are auto-revoked on the next
  request.
- **Revoke** — user-initiated (`lv logout`, `lv session revoke <id>`)
  or admin-initiated.

Each session records the client's address (`lv session ls` IP). For a
login through the web UI or the REST gateway, which reach the daemon over
loopback, that is the browser's address as the gateway sees it — the TCP peer,
or from a `trusted_proxies` peer the forwarded client ("OIDC sign-in", the
client address). It is not 127.0.0.1 unless the browser itself is on the node.

Failed logins are throttled per node, in memory:

- **Per account and address: 5 failures** in 15 minutes lock that pair for 15
  minutes. An IPv6 client counts by its /64. One browser's failures therefore
  never lock the account for other browsers.
- **Per account: 30 failures** in 15 minutes, from any mix of addresses, lock
  the account on that node for 15 minutes (audited as `locked out by the
  account throttle`). This bounds an attacker who rotates addresses — a botnet,
  a large address pool — and a success does not reset it. The cost is
  availability: 30 failures from at least 6 addresses lock the real user out
  of that node for the lockout.
- The address is the one above, so an **over-broad `trusted_proxies`** (one
  that covers the clients themselves, for example `0.0.0.0/0`) lets a client
  write its own `X-Forwarded-For` and choose its per-address key. The
  per-account ceiling still holds; list only your proxies.

A failure counts against exactly the account name the attempt gave
(normalized: trimmed and lower-cased) — for a password or LDAP login. An OIDC
login names no account the client can choose: a failed exchange counts in the
anonymous per-address bucket (which has no account ceiling), and a failed
second factor against the subject the IdP proved; a `username` sent with an
OIDC login is ignored. A WebAuthn finish counts only when a ceremony was in
flight (an assertion was actually checked). Failing as `admin|1` names another,
nonexistent account and never counts against `admin`; two OIDC subjects such
as `auth0|abc` and `auth0|xyz` have separate ceilings.

Both limits cover **every login path** to the account on that node: the web
UI, REST, a direct `lv login` (also over mTLS), the second-factor step
(including an OIDC login's) and WebAuthn. While an account is locked:

- its **existing sessions keep working**, and new logins are refused with
  `too many failed login attempts; retry in …`;
- **on-node root still works**: `lv` run as root on a node presents the host
  certificate and needs no login (`lv user reset-admin` too);
- other nodes are unaffected: the state is per node.

To clear it early, restart the daemon on that node (the state is in memory);
otherwise it ends by itself after the 15-minute lockout.

Both timeouts are configurable in the daemon config under
`auth.session_idle_timeout` and `auth.session_hard_expiry` (Go duration
strings, e.g. `8h`, `168h`); the defaults above apply when unset.

Why not JWT? JWTs cannot be revoked before their `exp`. Real-world
incidents (lost laptop, leaked CI token) demand immediate kill. The
sessions table is small (one row per active login) and reads are an
indexed primary-key lookup, so the cost is in noise.

`lv session ls` shows your active sessions; `--user <name>` lists
another user's (admin only). `*` marks the session the command ran with. The
ID column is a 12-character **handle**, the start of the session id: the whole
id is the session's bearer secret, so neither the API (`ListSessions`, `GET
/api/v1/sessions`) nor the CLI ever returns it. The daemon sets `current` on
the caller's own session, so a client never needs to compare its token with a
listed id (a REST client that did so must use `current` instead).
`lv session revoke` accepts that short form, or any unambiguous prefix of at
least 8 characters. A prefix resolves only among the sessions the caller may
revoke — its own, or anyone's for an admin — so a non-admin's prefix never
reaches, or reveals, another user's session; a prefix matching more than one
is refused and the matches are listed.

## API tokens

API tokens are long-lived bearer credentials for automation. They are
distinct from sessions:

- Stored as bcrypt(token) — verifiable but not recoverable.
- No idle timeout; an explicit `expires` (RFC3339) is the only bound.
- May carry **scope paths** that further restrict what the token can do.

```bash
lv user token-create alice ci-runner --expires 2026-12-31T00:00:00Z
lv user token-create alice deploy-acme \
    --scope-path /projects/acme \
    --scope-path /storage/main
```

A scoped token's effective permissions are
`intersection(user's role bindings, token scopes)`. Even if the bound
user is `Admin`, a token scoped to `/projects/acme` cannot touch
`/projects/other`.

## Two-factor authentication

Two factors are shipped:

- **TOTP** (RFC 6238 SHA-1 / 6 digits / 30s period) — works in the CLI
  and any authenticator app. Enroll with `lv 2fa enroll-totp`.
- **WebAuthn** (FIDO2 / passkeys) — browser-only because the protocol
  requires a resident authenticator. Enroll at `/account/2fa` in the
  web UI (requires `webauthn:` daemon config — see
  `docs/configuration.md`).

To enroll TOTP:

```bash
lv 2fa enroll-totp --label phone
```

The command prints:

- An `otpauth://` provisioning URL (paste into Google Authenticator /
  Authy / 1Password / etc., or render a QR in the UI).
- The base32 secret for manual entry.
- 10 single-use recovery codes — *save them now*; they are not stored
  in plaintext and cannot be re-shown.

After enrollment, `lv login` runs in two stages: it accepts the password,
the server returns `Requires_2Fa=true` with no token, and the CLI prompts
for the second factor. Recovery codes work in the same prompt — each
code is consumed on use.

For WebAuthn enrollment, open `/account/2fa` in the UI and click
"Register security key". The browser drives `navigator.credentials.create`
against the daemon; the resulting credential lands in the same
`user_2fa` table TOTP uses.

To disable a factor: `lv 2fa disable --method totp --label phone`.

### Mandatory second factor (`lv 2fa policy`)

A cluster-wide policy decides which realms must present a second factor:

```bash
lv 2fa policy                                   # show it
lv 2fa policy all                               # every realm
lv 2fa policy local,ldap:corp                   # only these realms
lv 2fa policy off                               # the default
lv 2fa policy all --allow-self-enroll --enroll-by 2026-11-01T00:00:00Z
lv 2fa enroll-code bob [--ttl 1h]               # admin: bob's first-enrollment code
lv 2fa enroll-totp --code <code>                # bob, from an enrollment-only session
```

It is a replicated row (the `login_2fa_required` key of `cluster_policies`),
so every node enforces the same rule. Setting it is admin only, and refused
until the cluster upgrade has finished (the release feature `login_policy`). A realm the answering node
does not have configured is set anyway and reported as a warning (a typo such
as `ldap:crop` covers nothing).

- **A session is full only if its login presented a second factor.** That is
  recorded when the session is minted (`session_factors`) and read back for
  the session's whole life; it is never re-derived from the account's factors
  now. A password-only session stays confined even after a factor is enrolled
  for the account — by its holder in another session, by an admin, or after a
  lost-device reset — so whoever held only the password never inherits a full
  session. A session opened on a node the policy had not reached yet is
  confined as soon as it arrives.
- **A covered user with a factor** must present it at every login, through
  every covered realm. The local realm always did this; the policy extends
  it to LDAP and OIDC. An OIDC code is single-use, so through an OIDC realm
  the factor is sent either with the code or, after a `requires_2fa` answer,
  with the `oidc_pending` handle it carries ("OIDC sign-in" above); the web UI
  and `lv login --realm oidc:<name>` do the second. WebAuthn login is itself a
  second factor.
- **A login that presents no factor** gets an enrollment-only session
  (`requires_2fa_enrollment`, no role): it can call `Whoami`, `Logout` and
  `GetLoginPolicy`, list its own factors and, if the account has NO factor
  yet, enroll one for itself (`lv 2fa enroll-totp`, or a security key at
  `/account/2fa`); every other call, and every stream, is refused. The web UI
  keeps such a session on `/account/2fa`. An account that already has a
  factor cannot add one from such a session: log in again presenting it.
- **The first factor needs an admin-issued code by default.** Anyone holding
  only the password of an account with no factor could otherwise enroll their
  own factor and lock the real user out. `lv 2fa enroll-code <user>` mints a
  single-use code (shown once, stored as a SHA-256, valid for `--ttl`, at most
  24 hours; issuing another replaces it), handed over out of band. The code is
  **bound to the node that issued it**: it is checked and spent there alone, in
  one guarded write, so it is single-use cluster-wide even across a partition.
  Used on any other node it is refused with a message naming the issuing node
  — log in through that node, or have an admin issue a new code where you are.
  `lv 2fa enroll-code` (and `lv user reset-admin --clear-2fa`) prints that
  node with the code, so hand both over together. A disable, a delete or a
  re-create of the account, or an admin enrolling a factor for it (TOTP or a
  security key), voids an outstanding code. Each of those is a replicated
  write: it voids the code on the issuing node once it has replicated there,
  so a code used on that node within replication lag of a disable made on
  another one can still be spent — the enrollment-only session it ends in is
  then refused by the disable as soon as that arrives. A WebAuthn enrollment verifies the
  attestation before it spends the code or ends the session, so a failed
  ceremony leaves both. The policy
  can instead allow self-enrollment until a deadline (`--allow-self-enroll
  --enroll-by <RFC3339>`); after the deadline a code is needed again, and
  setting the policy without the flag closes the window. Enrolling ends the
  enrollment-only session first — if it cannot be ended, nothing is enrolled —
  and the next login presents the new factor. Every first-factor enrollment
  from such a session is audited, published and sent as the
  `auth.first_factor_enrolled` notification, so a claimed account is seen.
- **It holds from the moment it is set.** Setting it ends every live session
  in a realm it newly covers, the caller's own included, and open streams end
  with them.
- **API tokens are not subject to it.** They are administrator-issued
  automation with no interactive holder; scope them, give them an expiry,
  and revoke them with `lv user token-revoke`.
- **The distributable `lv-cli` client certificate is not subject to it
  either**: it authenticates as the cluster admin with no user behind it.
  Turn on `auth.strict_mtls_identity` (below) so every operator must log in.

A stored value this build does not understand (a later release's) is enforced
as `all`. A node that cannot read the policy, a session's recorded factor, or
a user's factors — including one whose credential tables a reseed has not
repopulated yet — refuses the login, request or enrollment rather than guess.

**Recovery.** The policy never locks an account out; it asks it to enroll,
with a code. A user who lost their factor: an admin removes it (`lv 2fa
disable --user <name> --method totp`) and issues a code (`lv 2fa enroll-code
<name>`). The **only** admin who lost their factor and recovery codes: as root
on a node that is not in WAL quarantine (a quarantined node accepts local root
but refuses every replicated write, so no account change can be made on it),
`lv user reset-admin --clear-2fa` (with litevirtd running: it is a login rule,
and the daemon-down path refuses it) removes the `admin` account's
factors and recovery codes, gives it a new password, and prints an enrollment
code; log in, `lv 2fa enroll-totp --code <code>`, and log in again with the
new factor. As root on a node, `lv` with no stored session reaches the local
daemon as local-root, which is admin: `sudo lv 2fa enroll-code admin`, `sudo
lv user enable <admin>` and `sudo lv 2fa disable --user <admin> --method totp`
all work there. Move `~/.config/litevirt/credentials.json` (root's) aside
first, so the call is not made as a stale or disabled session.

## Account lifecycle (`lv user disable`, `lv user expire`)

```bash
lv user disable bob                          # refuse every credential of bob's
lv user enable bob                           # undo it
lv user expire contractor 2026-12-31T00:00:00Z
lv user expire contractor never              # clear the expiry
lv user ls                                   # STATUS and EXPIRES columns
```

Names are compared ignoring ASCII case and surrounding spaces at every
lookup (`ALICE`, `alice ` and `alice` are one account), including the subject
an LDAP or OIDC login maps to, so a disabled account is not reachable through
a variant spelling. Two existing accounts that differ only that way are never
merged: every lookup of either refuses, naming both, until one is renamed or
deleted. New names are stored trimmed.

A disabled account, or one past its expiry, cannot authenticate by any path:
password and WebAuthn login through any realm (an LDAP or OIDC user is refused
like a local one), its sessions, its API tokens, and either one relayed by a
peer as a forwarded identity. The check runs on every request against the
node's replica, so a disable takes effect on each node as soon as it has
replicated there, and an expiry needs no timer. Any lifecycle change — a disable, a re-enable, an expiry set, changed or
cleared, a re-create, `lv user reset-admin` re-enabling the admin — logs the
account out everywhere: it records a cut-off before which no session is
honoured (below), so re-enabling does not revive ended sessions. Its API
tokens work again on re-enable. A wrong password for a disabled
account is still just a wrong password: the disabled state is told only to
someone who presents the account's credentials.

Each attribute is its own replicated row (`user_lifecycle`), so a disable and
an expiry change made on two nodes never undo each other. A value a node
cannot read is treated as disabled. A disable or an expiry also records the
instant before which no session of the account is honoured again — and so
does every later lifecycle change: a re-enable, an expiry set, changed or
cleared, a re-create. The comparison allows for clock skew in the refusing
direction (`SessionCutoffSkewMargin`, 5 s, the failover coordinator's skew
margin): a session created up to 5 s after a change is refused too, and a
login in those 5 s is told to retry. So a session minted before a disable —
on another node, by a clock up to 5 s ahead, or on a node the disable had not
reached yet — stays dead after the re-enable, and an expiry that passed and is
then extended revives nothing. A clock more than 5 s off is the LWW skew
guard's to report; such a node can still mint a session that survives a
re-enable. Deleting a user keeps its disable:
the admin floor never brings back a disabled admin, and a directory login that
re-creates a deleted, disabled LDAP or OIDC user's account finds it still
disabled. An explicit `lv user create` starts the name afresh (enabled, and
none of a former namesake's sessions or API tokens honoured).

**Deleting a user** revokes its sessions and API tokens in the same write as
the delete, voids its enrollment code and clears its directory bindings, and
records durable session and API-token cut-offs (`user_lifecycle`). So a
session or token the deleting node never held — minted elsewhere, its revoke
lost — is refused anyway once the cut-offs replicate, and stays refused when
the name is re-created or the admin floor reinstates it. A session or token
is also bound to the exact stored name it was issued for: once that spelling
is deleted, it does not authenticate as another spelling of the name that
survives, on any path (direct, forwarded by a peer, or an open stream). The
token cut-off allows for skew the way the session one does: a token stamped up
to 5 s after it is refused, so a namesake's token minted by a node whose clock
runs ahead does not survive a re-create. Re-creating a name the node knows
had an account (a deleted row, or a token issued under it) puts the token
cut-off at the create, and `lv user token-create` for it in the next 5 s is
refused with a retry message rather than minting a token that would never
work; for a name new to the node, and for sessions, the cut-off is set back
by the margin and a second, so a login or token right after `lv user create`
works at once (even just after a delete, as before). A token minted through
another node within those 5 s, before the re-create reached that node, is
refused once the cut-off arrives and never works; its refusal says so. Create
the token through the node the name was re-created on, or wait 5 s. No other lifecycle
write moves a cut-off backwards: a re-enable, an expiry change or
`lv user reset-admin` just after a disable, or from a node whose clock is
behind, keeps the later cut-off, and a login in its margin is told to retry,
and when. The one exception is a cut-off dated more than 5 s in the future,
written by a node whose clock ran ahead: it refuses every login (or new API
token) of the account until that time, and the refusal names the time.
`lv user reset-admin` (as root, with litevirtd running) replaces such a
cut-off on the admin account it resets, `--user <name>` for another admin,
and logs that it did. Correcting it needs the release feature `login_policy`,
and reset-admin waits for that at most 3 s: with the daemon down, or with the
feature unable to open in time (the cluster upgrade unfinished, a first use
not yet acknowledged by an unreachable host), it still resets the password at
once, leaves the cut-off, and prints that it did and what clears it (run it
again once the feature opens, or wait).

**Where and when it holds.** Each node judges against its own replica and its
own clock. A change takes effect on a node when its row arrives there: on the
node where it was made at once, elsewhere within replication lag — and a node
cut off from the cluster keeps accepting the account for as long as it is cut
off. Expiry is compared with each node's wall clock, so a node whose clock runs
S seconds slow accepts an expired account for S seconds (the LWW skew guard
bounds how far a clock may drift); `lv user ls` STATUS is the answering
daemon's verdict by its clock. **Open streams** — serial consoles, VNC, log
follows, event watches, and the web UI websockets and REST SSE built on them —
are re-checked while open: one authenticated by a session or API token ends
within 5 seconds of a disable, an expiry, a delete, a session or token revoke,
or a policy change reaching the node, and at once on the node where the change
was made. A recheck runs every 2 s, each allowed 1.5 s. One that fails or does
not finish in time (a replica stall, a reseed) is retried at once instead of
ending the stream; the stream ends only when no recheck has succeeded for 5 s,
so its credential is still unknown at the bound. At the cut, what a handler
holds for the caller — the console's PTY, the VNC socket, a followed log file —
is closed at once, whether or not the handler is watching; any handler still
blocked 2 s after the cut has its RPC ended. Every streaming RPC is listed,
with what it holds, in `streamHandlerAudit` (internal/grpcapi), and a test
fails when one is added without an entry. Exec (`lv exec`, the UI exec page)
is one RPC per command, each authenticated on its own.

**SPICE through litevirt is cut; SPICE through an SSH tunnel is not.** `lv
spice --launch` and `lv spice --listen` carry each SPICE channel over
`ProxySpice`, which holds the socket to the VM's SPICE listener for its
caller and is closed at the cut like a VNC console. A client that reaches the
listener directly instead (on the VM's host, or through an SSH tunnel to its
`127.0.0.1`, which the UI's `.vv` file is for) never passes through the
daemon, so that session lives as long as the tunnel, whatever happens to the
account. To end one when disabling a user, revoke the user's SSH access to
the host and kill their SSH session there (`pkill -u <ssh-user> sshd`), which
ends the tunnel and the SPICE connection in it; restarting the VM also ends
it. The console's password (ui.md "Console passwords") rotates at the VM's
next define, so a disabled user who kept a `.vv` file or a printed password
can use it only until the VM is next defined and restarted.

Admin only, audited as `user.account`. Refused for the cluster's last admin
that can log in, enabled with no expiry — `lv user delete` applies the same rule — and
until the cluster upgrade has finished (the release feature `login_policy`). Two admins restricting each
other on two nodes at once can still race past that guard; every node then
raises the `no_unrestricted_admin` health condition (critical), and the floor
does NOT re-enable either admin itself. Recovery, as root on a node that is
not in WAL quarantine: `lv user reset-admin` re-enables the `admin` account;
for an admin with another name, `sudo lv user enable <name>` with root's
credentials.json moved aside. In a whole-fleet rollback below a latched token
every node is quarantined, and no account change is possible anywhere until
the fleet is upgraded again; local root still reaches every running daemon.

**Duplicate spellings.** Two accounts whose names differ only in case or
surrounding spaces (left over from before names were normalized, or created
on two nodes at once) are never merged: every lookup of either — a login, a
session, an API token, `lv user`, reset-admin — refuses, naming both. To
remove one, `lv user delete --exact <name>` lists every account named like it
— id, exact stored name, creation time, role, realm, last login seen by the
answering node, factors and tokens — and deletes nothing; then
`lv user delete --exact <name> --id <id>` deletes the one chosen (admin,
audited as an exact delete). The id alone chooses: typed as either spelling,
it deletes the account the id names. An admin that is one of such a pair
cannot log in, so it never counts as the admin that remains when the
last-admin guard decides — except the spelling that survives the delete being
decided: when a pair are the cluster's only admins, deleting one spelling by
its id is allowed, and leaves the other usable. The admin floor, on the other
hand, counts such a pair as admins present, so it never reinstates a deleted
admin beside them; `no_unrestricted_admin` names the pair and the command
instead, which root runs with credentials.json moved aside. A deleted
account under a variant spelling is brought back under its own name by a
directory login, so it keeps its disable. Every last-admin refusal names, with
its arguments, what the refused admin can do instead: create an admin, enable
one or lift its expiry, resolve a pair, or give an admin the floor reinstated
with no credential one (`lv user reset-admin --user <name>`, as root).

**Held second factors.** A second factor that a node on the previous
release enrolled for an account deleted and re-created during the upgrade is
held (docs/upgrades.md): kept, never accepted, and the account's login is
refused, even with the right password, until an admin removes it with
`lv 2fa disable --user <name> --method <method> --label <label>` (`totp`
or `webauthn`, the factor's own) and issues an enrollment code with
`lv 2fa enroll-code <name>`. `lv 2fa ls --user <name>` marks it `(held)`,
and every node raises the `held_second_factor` health condition (warning)
naming the account and the commands for each held factor. An admin whose only factors are
held cannot log in, so it does not count for `no_unrestricted_admin`, whose
recovery then names those two commands, run by another admin, or
`lv user reset-admin --user <name> --clear-2fa` as root on a node.
Once a credentials clear may have happened (`credentials_clear_v1` has latched
on the answering node, or a peer's cleared rows have reached it), the guard
fails closed on an admin whose credential that node cannot judge yet: a users
row with no password and no credential row, which is then either a directory
admin whose evidence has not replicated or a local admin — such as one the
floor reinstated — whose credential row has not. Such an admin does not count,
and when it is the only one that might, the change is refused as
`Unavailable`, naming it, to be retried once the row has replicated (or made
on another node); for a directory admin, `lv user mark-external <name>`
records what it is. Before any clear, a users row with no password can only be
a directory admin's, and it counts, as it always did.

**The one credential a disable cannot reach** is the distributable `lv-cli`
client certificate: it authenticates as the cluster admin with no user behind
it. Turn on `auth.strict_mtls_identity` (below) so that a disabled operator
cannot keep acting through it.

### Rolling upgrade, and hosts below the latch

The login rules are the release feature `login_policy` of the release token
`release_2026_11_v1`, which is mandatory and replication-gated: every build
that has the `user_lifecycle` table advertises it, and it latches only once
every host the cluster replicates to does. Until then `lv user
disable|enable|expire|unbind`, `lv 2fa enroll-code` and setting `lv 2fa policy`
are refused (`the cluster upgrade must finish first (login_policy needs
release_2026_11_v1)`), and nothing is written; logins, `lv user create` and
`lv user delete` work as on the previous release, without the login rules'
data. Before the first write, the cluster records that the feature is used
(docs/upgrades.md, "Rolling back after a release token latched"), so a
rollback below the release quarantines once any of it exists. A previous-release host therefore never receives a statement it
cannot decode, never holds an account state it would not enforce, and —
having no statement that names the table — cannot re-enable an account.

What a host **below** the latch does and does not enforce, exactly:

- A host on an older build (one admitted after the latch, or one rolled back
  below it) does not read `user_lifecycle`, `session_factors` or the
  second-factor policy at all. It does **not** refuse a disabled or expired
  account's sessions or API tokens, does not confine password-only sessions,
  and does not cut open streams. The post-latch `unsupported_member` health
  condition is the signal. Keep such a host out of the client path, or revoke
  the account's API tokens and sessions, until it is upgraded.
- A host whose binary is below a token it already latched is in WAL
  quarantine and writes nothing. From this release on, a quarantined host
  also **refuses every user credential** — logins, sessions and API tokens,
  direct or forwarded — and still serves local-root and peer mTLS, which are
  how it is repaired. A binary older than this release does not have that
  refusal: it is the case above.

## Migration from the legacy admin/operator/viewer roles

`users.role` holds a flat `admin > operator > viewer` ladder. The RBAC
engine respects these rows for backward
compatibility:

- Each legacy role appears as a synthetic group `group:<role>@local`.
- `RequirePerm` falls back to the legacy ladder ONLY when the engine
  has no bindings at all for the caller's principal set.
- One root binding migrates an entire team at once:

  ```bash
  lv role grant Admin    group:admin@local    --path / --propagate
  lv role grant Operator group:operator@local --path / --propagate
  lv role grant Viewer   group:viewer@local   --path / --propagate
  ```

Once those bindings exist, the legacy fallback never fires; the engine
is the only authority.

## Wire format quick reference

| Bearer prefix | Lookup table | Rejected on |
|---|---|---|
| `lvs_<hex>` | `sessions` | revoked, hard-expired, idle-timeout, account disabled/expired |
| `<hex>` (no prefix) | `tokens` (bcrypt match) | `deleted_at`, `expires_at`, account disabled/expired |
| (no Authorization header) | mTLS client cert → classified (see below) | invalid/expired peer cert |

## mTLS principal model

A bearerless mTLS caller (no `Authorization` bearer) is classified by its
certificate, not blanket-trusted as `admin`:

| kind | condition | authority |
|---|---|---|
| **local-root** | connection is loopback **and** the cert CN is a trusted cluster host | `admin` (on-node root — running `lv` on a node is already root-equivalent) |
| **peer** | non-loopback **and** the cert CN is a trusted cluster host | `admin` (a trusted cluster node: peer RPCs + relaying an already-authorized user forward) |
| **client** | any other cert — the distributable CLI client cert, an unknown/empty CN, or a **removed** host's CN | must present a session bearer (`lv login`); denied once strict mode is enforced |

A bearer, when present, always wins and yields the real user (role/scope).

"Trusted cluster host" is decided from the `hosts` row, and the three cases are
distinct:

- a **tombstoned** row (a removed host) is refused outright;
- a **live** row is trusted, in any operational state — draining, fenced,
  upgrading and maintenance all stay trusted, because a recovering node needs its
  own rejoin RPCs accepted. The removal boundary is `deleted_at`, not state;
- **no row at all** falls back to the certificate, and is trusted only if it
  carries `ServerAuth`. That is what `lv host init`/`lv host add` issue for a host
  and what the distributable `lv-cli` certificate deliberately does not, so the CLI
  cert is never a peer.

That last case exists because hosts learn about each other by replication, and
replication is what this gates: requiring a live row meant a freshly provisioned
cluster — where every node holds only its own row — could never converge. An
unreadable row is **not** the same as an absent one and is refused, because an
error cannot rule out a removal.

**Removing a host revokes its certificate.** `lv host rm` appends the host's
certificate serial to the cluster CRL, so removal does not rest solely on the
tombstone reaching every node. It needs the CA private key, so run it from the
machine that ran `lv host init`; if it cannot, the command says so rather than
skipping revocation silently.

The CRL is then **replicated**, not copied around by hand. `lv host rm` publishes
the revocation before tombstoning the host, every node installs it within about
half a minute, and each
daemon reloads `crl.pem` when the file changes. Two things make that safe to send
over a channel any peer can write to: a CRL is signed by the cluster CA, and every
node verifies that signature against its own `ca.crt` before the file is touched —
so a host publishing a CRL that omits its own serial is refused rather than
believed. Nodes enforce the union of every verified CRL they know, so equal-number
lists or a later list minted from stale state cannot un-revoke either branch. The
table is append-only and keyed by both the CRL hash and its signed bytes, so a
garbage row occupying a public hash cannot displace or bury the genuine row.
`lv health` warns for as long as any peer's CRL version is behind another's.

If minting or publishing fails — the cluster was unreachable, the daemon was
restarting — `lv host rm` refuses to tombstone the host, preserving the serial and
making the whole operation safe to retry. When a CRL was minted but publication
failed, `lv host publish-crl` can publish it directly; then rerun `lv host rm`.

Distribution deliberately does **not** go over SSH. SSH is the bootstrap channel —
`host init`, `host add`, `rotate-audit-key` — for reaching a machine that is not
yet a cluster member. A revocation goes to nodes that are already mutually
authenticated peers with a replicated store built for exactly this, where an SSH
fan-out would be best-effort with a list of hosts it failed to reach.

**Threat model.** The daemon runs as root against the local libvirt socket and a
replicated state DB, so root on a node is already full local + cluster power —
RBAC does not (and cannot) constrain it, and a host cert is a legitimately
root-obtained *node* identity. What this model closes is that a **distributable**
credential (the shared CLI client cert) does not equal admin: hand someone CLI
reach and they still need to `lv login` to act.

### Renewing a host certificate (`lv host renew-cert`)

A host's cluster certificate — the identity behind every peer and on-node mTLS
call — is valid for five years. Each daemon exports its expiry as
`litevirt_certificate_expiry_timestamp_seconds{cert="host"}` and sends a
`certificate.expiring` notification from 30 days out (error severity inside 7
days), then `certificate.expired`, repeating daily while it stands. Renew it from
the machine that holds the cluster CA key:

```bash
lv host renew-cert host-b
lv host renew-cert host-b --ssh root@10.0.50.11   # name isn't the address
```

The host keeps running throughout — no restart, no partition, nothing a peer
could read as a failure:

1. **The key is generated on the host.** The host (its own `litevirt` binary,
   over SSH) creates the new key and sends back only a certificate request; the
   CA machine signs the request and sends back only a certificate. The private
   key never crosses SSH and never exists on the CA machine.
2. The certificate is a **successor**: same name and addresses, a fresh
   five-year validity, and — signed by the CA — the serial of the certificate it
   replaces. Peers pin each host's recorded serial (that pin is what keeps a
   re-admitted name's old certificate out), and a peer whose record still names
   the predecessor accepts its successor immediately. The pin is not relaxed:
   only one hop is honoured, and an older certificate cannot name a serial
   recorded after it was minted.
3. **One atomic switch.** The host keeps each identity as a complete pair under
   `pki_dir/host.d/<serial>/`, with `host.crt` and `host.key` resolving through
   one `host.d/current` link, and the install is a single rename of that link.
   A crash or a dropped connection at any point leaves a pair the daemon starts
   with, and a daemon that finds its identity unloadable at start repairs it from
   the newest complete pair under `host.d`.
4. The daemon serves the new pair from the next handshake — its gRPC listener,
   its peer probes and its loopback clients read the identity at handshake time,
   and its recovery-claim votes are signed with it too. A replacement that does
   not chain to the cluster CA, names another host or does not match its key is
   refused, as is a renewed key not held safely. The identity a node already
   has is never refused over how its key file is held: a `host.key` outside the
   PKI directory, owned by another user, or with a mode that cannot be tightened
   is still served, logged as a WARN and raised as a degraded
   `certificate/key_file_unsafe` condition naming the file and the fix (move,
   `chown` or `chmod 600`); a key readable by others is tightened.
   **Established connections** are judged on every RPC, not only at the
   handshake. A connection made with a certificate the CA has **replaced** —
   see "Superseded certificates" below — starts no new RPC: the next one is
   refused with `Unavailable`, and the client reconnects and presents its
   renewed certificate. Only the RPCs already in flight on it — a cold-disk
   migration stream, a backup push — are left to finish, and the connection
   is closed when the last one ends, or after 15 minutes; one cut by that
   bound fails and must be re-run (cold-disk migration and peer backup streams
   do not resume), so renew outside long transfers. That holds once the
   replaced certificate is REVOKED too, as step 7 does at once: a revoked
   certificate with a standing CA-issued successor was revoked because it was
   renewed, and its connections drain the same way. A cold-disk migration
   opens a fresh connection for each disk, so one renewed mid-copy finishes
   the disk in flight and copies the rest with the renewed certificate; a
   container migrate or failover relocate likewise drives the target's
   restore over a fresh connection once its rootfs push has finished.
   A certificate revoked with **no** successor — `lv host rm`, `lv host
   revoke-cert` of a live identity — is the emergency path: a connection made
   with it (or on which the host served it) refuses its next RPC and is closed
   at once, streams in flight included. If you renewed because a key was
   stolen, a connection the thief opened before the renewal is not cut at
   once but drained: it starts nothing new, and what it had in flight runs out
   within 15 minutes; restart the daemons to cut it sooner. A host's own UI
   and REST clients reconnect by themselves when the host's certificate
   changes: the next request goes over a new connection with the renewed
   certificate, while a console or event stream already open on the old one
   runs on until it ends (or 15 minutes pass).
5. The command dials the host and **confirms** it presents the new certificate.
   It switches back only when the host demonstrably still presents the old one
   and the cluster does not record the new one; a probe that merely fails proves
   nothing, so nothing is undone on it. A successor that was signed but never
   used is revoked.
6. The daemon re-records its own serial within a minute, so the record moves on
   and the old certificate stops being accepted as that host. A certificate
   reissued any other way is re-recorded only under the conditions in
   "Superseded certificates".
7. Then the replaced certificate is **revoked, at once**. Every node on this
   build already refuses it — as a voter, as a claim signer and on every RPC
   (see "Superseded certificates") — so revoking it costs a pinning node
   nothing. The revocation is held only while the cluster has a node that does
   **not** pin: a live host on a different build (`--force`), or one running
   with `auth.trust_rotated_peer_certs` (each node reports that switch as its
   own `certificate/trust_rotated_peer_certs` condition, which is how the others
   know). For such a node the newest voter generation, if it needed the replaced
   certificate's accept, would stop verifying after the revocation
   ([recovery-claims.md §4.1](design/recovery-claims.md)); so while one exists,
   and only if the newest generation does need that accept, the revocation is
   **owed**: the CA-signed CRL is stored in a replicated
   `certificate/revocation_owed` health condition (a degraded reason in
   `lv health`), the host notifies `certificate.revocation_owed` daily, and the
   cluster publishes the CRL by itself as soon as no such node is left, or a
   newer voter generation no longer needs the accept. `--revoke-old` revokes at
   once regardless; `--keep-old` not at all.

   The revocation is also **owed** while the host's managed fence SSH row is
   still signed by the replaced certificate
   ([migration-failover.md](migration-failover.md#managed-fence-ssh)): every
   peer refuses to fence a host whose row does not verify, so it waits until the
   host's daemon re-signs the row with the renewed certificate, which it does
   within a minute, and is then published by itself. `lv host revoke-cert`
   revokes at once regardless, and so does `--revoke-old`: for up to about a
   minute after either, until the host re-signs its row, its peers refuse to
   fence it.

   An owed revocation is published only by a node that can trust its own view:
   its replica has caught up, it has adopted the newest voter generation it
   holds, and a majority of that generation's members answer it now, each
   having adopted it and none holding anything newer. A node on the minority
   side of a partition, or one still mid-exchange after a heal, holds.

#### Superseded certificates

A successor is the CA's own statement that the certificate it names is no
longer the host's identity. Every node collects that statement wherever it sees
a successor — a TLS handshake in either direction, an accept carried in a claim
or voter certificate, its own renewed identity — and keeps it node-locally in
`pki_dir/superseded.pem` (re-verified against the CA on load, never replicated,
only ever added to). A certificate a node holds a standing successor of is
refused there:

- its accepts do not count — in workload claim certificates or in a voter
  generation the node has not yet adopted;
- every new RPC on a connection made with it is refused, and the connection
  drains as above;
- it is never the host for peer trust, whatever the host's row says.

None of this reads `hosts.cert_serial`. That column is replicated data any peer
can write — a compromised host could write a renewed voter's record back to its
replaced serial — so it decides nothing here; a host recorded with a serial
whose revocation is owed is reported as `certificate/serial_regressed` (a pki
directory restored from before a renewal, or a peer rewriting the row) and the
revocation is published regardless. Only the CA can take a successor back: a
successor it revokes unused (an abandoned renewal) hands the identity back to
its predecessor; one revoked because it was renewed in turn does not.

The record is fail-closed against loss: a `superseded.pem` the node cannot
read (unreadable, not a regular file, over 16 MiB) is left exactly as it is
and never written over, what the node learns meanwhile is kept in memory, and
the read is retried; once it succeeds, both are merged and saved. If the
installed CRL cannot be parsed, the node treats nothing in it as revoked — the
CRL's fail-open rule — so an abandoned (revoked unused) successor looks
standing there, and the predecessor it would hand back is refused on that node
until the CRL is readable again; `certificate/crl_install_failed` reports that
node.

A node that holds no successor for a certificate does not refuse it on that
ground; revocation is what ends it everywhere. Until it is revoked — while it is
owed, or after `--keep-old` — the replaced certificate still authenticates as a
**bearerless client** (`admin` unless `auth.strict_mtls_identity` is on) to a
node that has not yet seen its successor, and as a TLS server to anything that
dials it. Under `auth.trust_rotated_peer_certs` the supersession checks are off
on that node — its serial pins and the stale-connection judge with them — so
while that recovery switch is on, a replaced key's accepts DO count there.

The recovery converges only on hosts that re-record their own serial, and a
host re-records a certificate that is not a renewal of the recorded one only
under conditions ([diagnostics.md](diagnostics.md), `own_row_held`):

- over a row at incarnation 0, after its own-row writes have been held for ten
  minutes from startup (reason `at_start`);
- over a row at incarnation 1 or higher, only when the row is the admission
  recorded in `<pki_dir>/own-admission.json`. A host without that record, or
  with another admission's, is held and never re-records; it needs
  `lv host rm` then `lv host add`;
- a certificate swapped while the daemon runs is held until the daemon
  restarts, and then as above; `certificate/cert_swapped_at_runtime` names it
  meanwhile, on that host only (peers refuse its writes): query that host
  (`LV_HOST=<its address> lv health`).

Turn the switch off only once every host has re-recorded, or been re-added.

#### Renewing a voter

A node that adopts a voter generation decided BEFORE one of its signers renewed
cannot count that signer's pre-renewal accept as it stands (§4.1's cost): the
pin refuses it, and once the renewal has revoked the replaced certificate, so
does revocation. Most of the time this is invisible: every node adopts within
seconds. A node that was offline, whose import was retrying, or that was
admitted later can be left one generation short.

Such a node asks the renewed voter to **re-attest** its accept: the voter
re-signs, with its current certificate, the accept it recorded in its own
durable claim state when it voted — the same key, generation, ballot and
value, never anything taken from the row or the caller — and the node adopts
the generation with that accept counted. Nothing is relaxed: the re-signed
accept is checked like any other, the replaced certificate counts for nothing,
and a voter asked about a generation it never accepted has nothing to give, so
a forged generation gets nothing. This works however many members are stuck,
including a MAJORITY of the newest generation, where no voter change could be
decided (a voter answers only at its adopted generation) and
`auth.trust_rotated_peer_certs` would not help (it relaxes the pin, never
revocation).

While the renewed voter cannot re-attest — unreachable, or on an older build
— the node raises `certificate/voter_generation_stuck`, naming the generation,
the voter it is waiting on, and the fixes: bring that host back on this build,
or **decide one more voter change** from a node that has adopted the newest
generation — `lv cluster voter add <host>`, or `lv cluster voter rm <host>`
and then add it back. Its accepts carry current certificates, it becomes the
stuck node's anchor, and the node adopts through it; the condition clears. A
voter change needs a majority of the newest generation, so when a majority is
stuck, re-attestation is the way out. To avoid all of this, renew voters only
when `lv cluster voter ls` shows every node on the newest generation.

The renewal deletes the replaced key from the host's PKI directory and the copy
`lv host init`/`lv host add` left on the CA machine (`<host>.key`, when it is
that key, together with `<host>.crt`, when it is the replaced certificate). A legacy `host.key` that resolved OUTSIDE the PKI directory is no
longer used but is not deleted (the renewal cannot know what else uses that
file); the command names it. Any other copy taken earlier is what `lv host
revoke-cert` closes, at any time.

An owed revocation is not a row a peer can quietly drop. It counts as done only
when its serial is in the CRL the node installed from CA-verified rows: a row
marked resolved or tombstoned without that is restored to owed, and a row whose
evidence no longer carries a CA-signed CRL listing its serial raises the
critical `certificate/revocation_owed_tampered` condition (and
`certificate.revocation_owed_tampered`), telling the operator to publish it with
`lv host revoke-cert`. Only a node that can trust its view judges this (the
same test as for publishing), after installing the cluster CRL that tick, and
only once the row has looked dropped there for three minutes — the row and the
CRL that justifies a legitimate resolve replicate independently, and a node
holding the first without the second accuses no one. A node that cannot install
the cluster CRL raises `certificate/crl_install_failed` once and judges nothing
until it can. A row deleted outright leaves the CA machine's
`pki/renewals.json` as the record.

A recovery whose claim certificate was signed with the replaced key before the
revocation lands is refused at execution (`recovery_claim_unproven`) and
re-certified at the coordinator's next attempt with the new certificate; it is
delayed, never run twice.

The command refuses, touching nothing, when the cluster's recorded serial and the
installed certificate disagree, and while hosts run different builds (`--force`
overrides): a peer on an older release does not recognise the successor and
refuses the renewed host until its re-recorded serial reaches it by anti-entropy
(`anti_entropy_interval_sec`, 60 s by default). A re-added host's audit admission
record, bound to its certificate serial, is re-signed for the new one. libvirt's
TLS listener (`qemu+tls://` migration) is asked to reload; if it cannot, it keeps
the old certificate until libvirt restarts, which is harmless because libvirt
does not read the cluster CRL. The migration-TLS certificates under
`pki_dir/migration` come from a separate CA and are not renewed by this command.

`lv host revoke-cert <host> --serial <hex>` is the manual path. It accepts only a
serial known to be the host's — one the CA machine's renewal log
(`pki/renewals.json`) records for it, or the predecessor named by the certificate
the host presents — and refuses a serial any other host is recorded with. The
host's own live or presented certificate needs `--force`, because revoking it
cuts the host off and gets it fenced (that is what `lv host rm` is for); and when
the host's presented certificate cannot be read, it refuses unless `--force`.

### Recovering the admin account (`lv user reset-admin`)

`lv user reset-admin` is for the cluster nobody can log in to, so it takes no
credential. It runs as root on a node and gives the existing `admin` account a
new random password, written to `/etc/litevirt/admin-password` (mode 0600). It
never creates an admin: on a node with no live admin it refuses, because a
joining node's credential replicates in and a deleted admin stays deleted.
`--user <name>` resets another admin-role account instead (refused for an
account whose role is not admin); the reset prints the account it reset.
Before sending `--user`, the CLI asks the running litevirtd its build's schema
version (`Ping`): a daemon from before `--user` would reset `admin`
whatever was named, so it is refused with nothing changed, and the CLI says
to restart litevirtd with the installed binary. (A daemon that cannot be
asked is sent the request; if it reset `admin` instead, the CLI says so and
keeps that new password in the file.) If
the `admin` account is disabled or has an expiry, the reset also clears both,
so it recovers an account locked out by `lv user disable` or `lv user expire`
too (with litevirtd running, once the cluster upgrade has finished; with the
daemon down, or before then, it refuses and changes nothing).

**The admin floor reinstates an account, never its credentials.** When admins
are deleted on two nodes at once and no admin is left, every node's floor
brings back the most recently deleted admin's account (`user.admin_reinstated`)
— but with no password anyone knows, every session and API token revoked
(durable cut-offs once the release feature `login_policy` has opened), its second factors and
enrollment code cleared. That holds for an admin deleted by a release before
the login rules too, whose delete revoked nothing: its API tokens do not come
back. Nobody can log in as the account until root, on a node, runs
`lv user reset-admin --user <name>`; the `no_unrestricted_admin` condition
names the account and the command until then. An external (LDAP or OIDC)
admin stays external: it gets no local password, the directory bindings its
delete cleared are restored, and it logs in through its realm as before (an
admin deleted by an earlier release had no binding, and binds at its next
login). Its old sessions, API tokens and second factors do not come back
either. If its directory entry is gone (people leave), it cannot log in, yet
counts as an admin who can: give it a local password with
`lv user reset-admin --user <name>`, as root on a node. Until root gives a
LOCAL reinstated admin a credential it is no admin anyone can log in as, so
the last-admin guard does not count it: the one admin who can log in is not
allowed to delete, disable or expire itself beside it, and the refusal names
`lv user reset-admin --user <name>`. Before the release feature `login_policy`
has opened (mid-upgrade), the floor revokes only the sessions held by the
node that reinstated the account; a session of a pre-upgrade delete that
never reached that node authenticates on the node that holds it until it
expires or an admin revokes it (`lv session revoke`), and a node does not
re-run the floor once the reinstatement reaches it. Once the feature has
opened, the durable cut-offs cover every node. A previous-release host still
runs the old floor, which restores the old password: finish the roll before
deleting admins.

Every reset is audited as `user.reset-admin`, attributed to `root@<host>`, with
the reset account as target and a detail of `via=<channel> os_user=<who>`. `os_user` is
`SUDO_USER` when set, otherwise the login name. The CLI reports it and the daemon
records it as a claim, not as an authenticated identity. No password and no hash
is ever written to the row. The CLI mints the password, keeps it, and sends only
its bcrypt hash.

**With the daemon running**, the command calls the `ResetAdminPassword` RPC over
the host's local root channel. It dials `127.0.0.1` on the daemon's gRPC port and
presents this host's own certificate from `pki_dir`, with no bearer. It ignores
`LV_HOST`, `LV_TOKEN`, a stored `lv login` session and a CLI client bundle, since
any of those would make the call arrive as someone else. The daemon accepts the
call only from a **local-root** principal whose certificate CN is its own host
name. A peer's certificate (even over loopback), an admin session, an API token
and the distributable `lv-cli` certificate are all refused with
`PermissionDenied`. Holding a session is not the same as being root on the node.
The daemon also refuses a hash that is not bcrypt or is below the cluster's cost.
It writes the reset and the audit row itself, as `via=local-root`.

**With the daemon down**, the command falls back to writing the reset straight
into the local database. It records the audit entry in the host-local
pending-audit journal (`<data_dir>/pending-audit/`), and the daemon folds the
entry into the audit log once it is running. The row is signed (whenever the
host signs, which is the default) and carries the
time the reset actually happened, with `via=journal`. The journal entry is
written before the reset and updated with the outcome after, all under the
journal's lock. A reset that cannot be journalled is not made. A command that
died in between leaves the result `interrupted`. The mechanism is described in
[audit-log.md](audit-log.md#actions-taken-while-the-daemon-is-down).

The fallback is taken only when the daemon cannot be reached (`Unavailable`) or
is too old to have the RPC (`Unimplemented`). Any other answer, a refusal
included, is returned as it is. A timeout is returned too, not retried locally,
because the daemon may already have applied the reset and a second one would
leave the password file and the database disagreeing. Why the CLI may not simply
write its own audit row is in [audit-log.md](audit-log.md#actions-taken-while-the-daemon-is-down).

### Enforcement (`auth.strict_mtls_identity`)

Denial of bearerless `client` certs is off by default and gated by both the
`auth.strict_mtls_identity` config flag **and** the `strict_mtls_identity_v1`
capability being active cluster-wide. The config flag is the enforcement switch
**and** kill switch (set it false to disable regardless of any latch), and the
loopback local-root path is never gated — so a mis-flip is reversible and can
never lock out an on-node operator. Because peer/forwarded traffic uses host
certs (which stay `admin`), enabling it changes **no** node-to-node behavior; the
only operator-visible change is that a **remote** CLI must `lv login` first
(on-node `lv` over loopback is unaffected).

**The token is advertised by this build; enforcement remains default-off.**
`strict_mtls_identity_v1` is in `capabilities.supported`, so deploying this build
lets the capability activate + latch cluster-wide — but that is behavior-neutral,
because enforcement is `auth.strict_mtls_identity` (default false) **AND** the
latch. Deploying does NOT change auth. HA-degraded does NOT fire for an
advertised-but-disabled token (degraded tracks configured-to-enforce, not merely
advertised). Enabling is a single config step: set `auth.strict_mtls_identity:
true` on every node; the HA monitor drives the latch while the cluster is healthy,
and the config flag stays the reversible kill switch (set it false + restart to
stand down, regardless of the latch marker). Validate on an ephemeral cluster
before enabling.

### Realm-aware role bindings (`auth.rbac_realm`)

Role bindings enforce against **realm-qualified** principals
(`user:<name>@<realm>`), so a legacy **bare** grant (`user:<name>`) never matches
and is inert. `auth.rbac_realm` opts a node into realm-aware grant grammar so it
stops minting new inert bindings. Like `auth.strict_mtls_identity`, it is gated by
the config flag **and** the `rbac_realm_v1` capability latched cluster-wide, and
the flag is the reversible kill switch (default false):

- **Flag off (default):** a bare grant is stored verbatim — legacy behavior,
  mixed-version-safe.
- **Flag on, not yet latched:** a bare `user:<name>` grant is **rejected**
  (`FailedPrecondition`) — specify an explicit realm. This is the safe
  pre-uniformity state: while any peer might still mint bare bindings, we refuse
  rather than canonicalize.
- **Flag on and latched fleet-wide:** a bare grant for a **known local user** is
  **resolved** to `user:<name>@local` and stored canonically; one that names no
  known local user is rejected (spell out the realm).

The grammar treats a principal as realm-qualified only when the part after the
last `@` names a realm (`local`, `oidc:*`, `ldap:*`) — so `user:alice@example.com`
is a bare username (an email), while `user:alice@oidc:corp` is realm-qualified.

`lv role grant` and the web UI's grant form ask the daemon to **refuse** a
grant that would be stored bare (`refuse_inert_principal`), whatever the flag:
with it off they get `FailedPrecondition` naming the qualified form instead of
an inert row, and with it on the grammar above applies unchanged (a latched
cluster still resolves a known local user). Against an older daemon that stores
the bare row anyway, `lv role grant` prints a warning with the `lv role revoke`
to remove it.

Existing bare bindings created before enabling this remain **inert** (they never
granted access) until rewritten. Once the capability has latched fleet-wide, run
the one-time idempotent migration `lv role normalize` (supports `--dry-run`) to
rewrite resolvable legacy bare rows to canonical form; a bare binding whose realm
can't be resolved is left in place and reported as skipped. External OIDC/LDAP
**group** bindings apply per session ("Directory group bindings" above).

### Forwarded identity (`auth.forwarded_identity`)

Cross-node requests are authorized on the **entry** node against the real user,
then forwarded to the owning node. The entry node relays the user's bearer to the
owner in `x-litevirt-fwd-bearer` (send-side is always on and ignored by nodes
that don't enforce it). When `auth.forwarded_identity` + the
`forwarded_identity_v1` capability are active, the owner re-authenticates that
bearer and runs RBAC + audit as the **real user** instead of `admin`; a forward
with no bearer (a background/system continuation — failover, reconcilers,
rebalancer, LB refresh, self-upgrade, replication) stays `admin` and audits as
`system`. Owner-side validation is fail-closed and never falls back to admin: a
session/user not yet replicated to the owner returns a **retryable** `Unavailable`
("forwarded identity not yet visible on owner; retry"), an
expired/revoked/malformed bearer returns `Unauthenticated`, and a resolvable user
that RBAC denies returns `PermissionDenied` — so an action taken immediately after
login or a role grant may briefly need a retry until replication catches up. The
forwarded bearer is only honored from a **peer** principal; a client cannot inject
it to impersonate a user.

> Peer-only RPC set (for a future flip that would stop accepting host certs on
> user-facing RPCs entirely): the replication/anti-entropy lane
> (`PushMutations`/`AckMutations`/state digest+dump/sensitive dumps), backup/
> restore transfer (`HasChunks`/`PushBackup`), failover probes
> (`GetRuntimeInventory`/`CheckVIPParticipant`/`CheckLBPresent`),
> `FetchBinary`, `GetVMIPRemote`, proof-bearing `PromoteReplica`/`ApplyLB`, and the
> peer-gated `ProvisionNetwork`/`SyncVTEP`/`UpdateFDB`/`RefreshLB`/
> `AnnounceMigratedGuest`/`PushReplicaIncrement`. Not enforced today. (`ListReplicas`, `PruneReplicas`
> and `PushReplica` ARE peer-only, enforced: a replica's record is written and
> read only by cluster hosts. `UploadStoragePoolContent` refuses a header with
> any field the receiver does not know, so no replica rides on an upload.)

### Who can read the state dump

`GetStateDump` and `StreamStateDump` return the full replication dump, the
representation anti-entropy repair merges, and `StreamTableDump` returns the
same representation restricted to named tables. It is unredacted, so it carries
the secret columns of replicated tables: `hosts.ipmi_pass`,
`users.password_hash` and `tokens.token_hash`. Once every host runs a build
carrying the `credentials_split_v1` capability, each host also writes those
secrets to `host_fence_credentials`, `user_credentials` and
`token_credentials`, which only the sensitive lane below carries. This release
keeps writing the three old columns too, so a host still reading only those
columns (one on the previous release, including one rolled back and under WAL
quarantine) reads current secrets, and the state dump **still carries the
secrets**. Once every host runs a build carrying `credentials_clear_v1` as
well, the old columns are emptied and the dump carries none (see
[upgrades.md](upgrades.md#the-old-secret-columns-are-emptied) and
[design/credentials-clear.md](design/credentials-clear.md)).
A host's Redfish BMC settings and password (`fence_strategy` `redfish`) were
never on a public table: they live only in `host_fence_redfish`, on the
sensitive lane, so no state dump carries them.
All three RPCs stay peer-only regardless: only a **peer** or **local-root**
caller (a cluster host certificate) can read them. An operator or admin bearer,
a session, and the `lv-cli` client certificate are all refused with
`PermissionDenied`, whatever their role. `StreamTableDump` never serves a table
of the sensitive lane below; naming one is refused with `InvalidArgument`.
The secret-bearing tables (`StreamSensitiveStateDump`, `GetSensitiveStateDigest`)
are narrower still: peer only, and the certificate must name the sender.
`GetTableBucketDigests`, which returns per-bucket counts and hashes for public
and sensitive tables alike so anti-entropy can pull only the buckets that
differ, has the same rule, as does `StreamSensitiveTableRows`, the paged form
of the sensitive dump. `StreamTableRows`, the paged form of
`StreamTableDump`, is peer-only and refuses a sensitive table exactly as that
RPC does.

Operators see convergence without row contents. `GetStateDigest` and
`GetClusterStateDigest` return per-table counts and hashes to an `operator`
bearer; `lv cluster converge` and the UI's **Force Sync** button call
`TriggerAntiEntropy`, which schedules a repair pass between the peers and returns
no state. `lv doctor divergence` (admin) has the connected node fetch each peer's
dump with its own host certificate, and returns only table names, primary keys
and row hashes — keyed HMAC labels for the secret-bearing tables.

## Gossip encryption

Everything above rides mTLS gRPC. Gossip does not: memberlist (`gossip_port`,
7946, TCP and UDP) speaks its own protocol, and it carries the membership that
relay election, replication targets, anti-entropy and capability activation all
count. [Admission](operating-model.md#gossip-admits-only-known-hosts-and-is-authenticated-only-when-encrypted)
refuses names that are not in the `hosts` table, but names and addresses are not
secrets. What authenticates gossip is a cluster-wide AES-256 key:
memberlist encrypts every packet and stream with it (AES-GCM), and a node that
enforces it drops anything unencrypted or under a key it does not hold.

**An unauthenticated gossip segment is not supported.** Until every host runs
`enforcement.gossip_encryption: true`, anyone who can reach `gossip_port` can
read the membership, announce a real host's name from its address, or disturb
failure detection. Keep the port on a network only cluster hosts can reach until
the rollout below is finished, and firewalled after it: the key is one shared
secret, so every host holding it can speak for any member, and a removed host
keeps what it knew until the key is rotated.

### The key file

`/etc/litevirt/pki/gossip.key` (`<pki_dir>/gossip.key`) on every host, mode
0600, beside `ca.crt`. One base64 32-byte key per line; the **first** encrypts,
**every** key decrypts; `#` lines are comments. The daemon refuses a file that
group or other can read, a key that is not 32 bytes, and a duplicate.

It is distributed exactly as the CA certificate is — pushed over SSH from the
machine that holds the CA, which keeps the canonical copy in its CLI PKI
directory (`~/.config/litevirt/pki/gossip.key`):

- `lv host init` mints it next to the CA and pushes it; `lv host add` pushes it
  alongside `ca.crt`, and refuses to add a host to a cluster whose enforcement
  block keys gossip when this machine has no key to give it;
- `lv host install-gossip-key` gives an existing cluster one;
- `lv host rotate-gossip-key` replaces it.

The key is never written to `config.yaml`, the replicated database (and so never
to a state dump) or a log. Logs, the CLI and the state file below name keys by a
16-hex-digit ID, a truncated domain-separated SHA-256 that cannot be reversed.
If the CA machine loses its copy, copy any host's `gossip.key` back, mode 0600.

The daemon re-reads `gossip.key` every 5 seconds and applies a changed keyring
**without a restart**. A missing, loose or unparseable file is logged and
ignored — the keys in use are kept, because an empty keyring would mean
plaintext. It reports what it is USING to
`/etc/litevirt/pki/gossip-keyring.state`:

```
mode=enforced
primary=3f1c9e0a7b2d4c61
keys=3f1c9e0a7b2d4c61
rejected=0
```

`primary` is the keyring's first key, and `keys` every key it decrypts with,
primary first. The order of the keys after the primary is the daemon's, not
the file's, and means nothing: a host whose `primary` and set of `keys` match
the file has loaded it. `primary` is set at every stage but `false` — `install` too, where
the host holds the key but still **sends plaintext** — so it says which key the
host encrypts with *once its stage sends encrypted*, not that it is encrypting;
`mode` says that. `lv host install-gossip-key` reports each host from both:

| `mode` | Reported as |
|---|---|
| `off` | `off (gossip plaintext; key file ignored)` |
| `install` | `install, sending plaintext, accepting plaintext and <keys>` |
| `staged` | `staged, encrypting with <primary>, accepting plaintext and <keys>` |
| `enforced` | `enforced, encrypting with <primary>, accepting only <keys>` |

`rejected` counts gossip this node dropped since it started for being
unencrypted or under a key it does not hold. It should stay flat through every
step below; a rising count is a peer this node cannot hear.

### The flag

`enforcement.gossip_encryption` defaults to `false`. Its values are four stages:

| Stage | Keyring | Sends | Accepts |
|---|---|---|---|
| `false` | none (the file is not read) | plaintext | plaintext |
| `install` | loaded | plaintext | plaintext and encrypted |
| `staged` | loaded | encrypted | plaintext and encrypted |
| `true` | loaded | encrypted | encrypted only |

Two nodes gossip with each other exactly when their stages are **adjacent** in
this table. Two apart cannot: a `staged` node is unreadable to a `false` one, and
a `true` node is deaf to an `install` one. That is the whole rollout rule — each
rolling restart moves every host one stage, and each finishes on **every** host
before the next begins. `install` is the stage it is tempting to skip; skipping
it makes the first `staged` host unreadable to every host with no keyring yet.

Every value but `false` refuses to start without a usable `gossip.key`, rather
than come up in plaintext under a flag that says otherwise. The stage is read
once at startup (memberlist fixes it for the life of the process); the keys are
not. A new cluster's enforcement block from `lv host init` sets it to `true`:
there is no plaintext host to stay compatible with.

There is no capability token for this flag, deliberately. The guarantee is
enforced by the **receiver**, locally: a `true` node drops what it cannot
authenticate, whatever its peers believe, so no node relies on a peer honouring
anything. A mis-staged pair loses gossip between the two of them — an
availability problem, visible in `rejected` and in membership — never a data
problem, since replication rides mTLS gRPC. A latch could not drive the rollout
either: memberlist cannot change stage under a running process, so it would take
effect at the next restart, which is the rolling restart the sequence already is.

### Turning it on in an existing cluster

Every host must first run a build that has this flag: a host on an older build
ignores the key and stays plaintext, so the `staged` roll would cut it off.

1. From the machine that holds the CA, install the key everywhere. Nothing
   changes on the wire yet:

   ```bash
   lv host install-gossip-key
   ```

2. On each host in turn, set the stage and restart, waiting for the host to be
   back before moving on:

   ```bash
   # /etc/litevirt/config.yaml
   enforcement:
     gossip_encryption: install
   ```

   ```bash
   systemctl restart litevirt
   lv host ls                            # the host is back and active
   cat /etc/litevirt/pki/gossip-keyring.state   # mode=install
   ```

   When **every** host is done, `lv host install-gossip-key` again: it writes
   nothing and lists every host's stage. All must read `install`.

3. The same roll with `gossip_encryption: staged`. All must read `staged`, and
   `rejected` must be flat on every host.

4. The same roll with `gossip_encryption: true`. All must read `enforced`, with
   `rejected` still flat. Gossip is now authenticated.

Do not add hosts in the middle of a roll: `lv host add` copies the enforcement
block of the node it reads, and a host more than one stage from any peer cannot
gossip with it. Rolling back is the same walk in reverse — `staged`, then
`install`, then `false`, each on every host — never a jump of two.

### Rotation

```bash
lv host rotate-gossip-key               # --grace 30s --timeout 2m
```

Run from the machine that holds the cluster's gossip key, with every host
reachable over SSH and its daemon running. No restart. memberlist encrypts with
the primary and decrypts with any installed key, so a new key must be on every
host before any host encrypts with it, and every host must stop encrypting with
the old one before any host drops it. The command does it in three phases, and
each waits for every host's state file to report the phase **loaded** — not just
the file written — before the next:

1. `[old, new]` — the new key is accepted everywhere; the old one still encrypts;
2. `[new, old]` — the new key encrypts; the old one is still accepted, for `--grace`;
3. `[new]` — the old key is removed.

"Add the new key as primary, then remove the old" in two steps is the tempting
shortcut, and it cuts off every host that has not loaded the new key yet for as
long as that takes.

If the rotation stops part-way — a host down, a phase that times out, Ctrl-C —
the cluster is safe as it stands, and the error names the host. Fix it and run
the command again: finding hosts on different keyrings, it puts them all back on
this machine's copy and then settles on that copy's primary alone (the new key
if phase 2 had started, the old one otherwise), and stops. Run it once more to
rotate. A host that is `false` takes the new file without being waited on; it
loads whatever is current when its stage changes.

Rotate after removing a host you no longer trust, after any suspected exposure
of a `gossip.key`, and periodically.
