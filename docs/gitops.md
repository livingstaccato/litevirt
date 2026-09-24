# GitOps controller

`litevirt gitops` is a subcommand of the single `litevirt` binary that
reconciles a Git repository of compose YAMLs into a litevirt cluster.
Point it at a repo, and every push (or `--poll` tick) triggers a diff
against current cluster state and a deploy for each compose file
whose content changed.

The command lives in `cmd/litevirt/gitops.go` (entry point) and
`internal/gitops/` (reconciler engine); it's part of the single
`bin/litevirt` produced by `make build` — there is no separate binary.

## Quick start

```bash
LV_HOST=root@host-01 litevirt gitops \
    --repo  https://github.com/acme/litevirt-stacks.git \
    --branch main \
    --poll  30s
```

The controller:

1. Clones the repo to `--local-dir` (default `/var/lib/litevirt-gitops/repo`).
2. Walks the working tree for compose files matching `--compose-glob`
   (default `**/compose.yaml`).
3. For each file, calls `DiffStack` against the daemon. If the diff
   reports zero mutation-bearing entries, skips the deploy entirely —
   a whitespace-only repo bump doesn't redeploy.
4. For files with non-empty diffs, calls `DeployStack` and reads its
   progress stream to the end. A deploy reports each failed VM action
   in-band and carries on with the rest of the plan, so the controller
   collects every failure and marks the file failed with all of them
   (`deploy: 2 failure(s): web-1: ...; web-3: ...`), rather than stopping
   at the first. It never stops reading early: a client that walks away
   from the stream cancels the server-side deploy, abandoning every action
   planned after the failure and leaving the stack record unwritten.
5. On completion, posts a markdown comment back to the commit via
   `gh api repos/<owner>/<repo>/commits/<sha>/comments` if `gh` is
   installed on the controller's host. Falls back to a `slog.Info`
   summary otherwise.

## Flags

| Flag | Default | What |
|---|---|---|
| `--repo` | required | Git remote URL |
| `--branch` | `main` | Branch to track |
| `--local-dir` | `/var/lib/litevirt-gitops/repo` | Working tree |
| `--compose-glob` | `**/compose.yaml` | Path glob inside the repo |
| `--poll` | `60s` | Polling interval (`0s` disables polling) |
| `--webhook-bind` | `127.0.0.1:7700` | HTTP listener for instant reconcile (empty disables) |

Auth to the daemon uses the same gRPC dialer as the `lv` CLI — set
`LV_HOST` and `LV_TOKEN` in the controller's environment, or rely on
the system's CLI cert.

## Webhook

The webhook listener accepts any POST to `/` (no body parsing) and
triggers an immediate reconcile of every compose file in the tree.
Wire it up to your SCM's push-event webhook, behind a TLS-terminating
reverse proxy:

```
GitHub / GitLab push event
  → reverse-proxy.acme.corp
    → 127.0.0.1:7700  (the litevirt gitops webhook)
      → reconcile()
```

Webhook reconciles AND poll-tick reconciles share state, so an
instant webhook trigger and a slow `--poll` are complementary rather
than conflicting.

## Repo layout

The controller doesn't care how the repo is organised, only that
compose files match `--compose-glob`. Conventional layouts:

```
stacks/
├── prod/
│   ├── web/compose.yaml
│   ├── db/compose.yaml
│   └── batch/compose.yaml
└── staging/
    ├── web/compose.yaml
    └── db/compose.yaml
```

Run two controllers if you want strict prod/staging separation —
each gets its own clone, poll interval, daemon target, and webhook.

## Commit feedback

When `gh` is available, the controller posts a markdown comment
shaped like:

```
**litevirt-gitops** — reconcile complete

| Stack | Result |
|---|---|
| prod/web | ✅ OK (3 mutations) |
| prod/db | ✅ OK (1 mutation) |
| prod/batch | ⚠️ Failed: image pull timeout |
| staging/web | 🛑 Skipped (no changes) |
```

The `gh` invocation pulls owner/repo/SHA from the Git remote and the
current HEAD; no extra config beyond `gh auth login` on the
controller's host.

## When NOT to use it

- For interactive iteration on a single VM, `lv compose up` is
  faster — no commit/push round trip.
- For dry-run validation, use `lv compose diff` directly; the
  controller's `DiffStack` short-circuit is opinionated and doesn't
  surface the diff to the operator without a deploy.
- For approval workflows ("this stack needs a code review before
  deploy"), branch protection in the SCM does the right thing — the
  controller only ever reconciles what's on the tracked branch.

## What's still in flight

- Multi-tenant operation (one controller per project). Today one
  binary points at one daemon; projects get isolation via per-stack
  RBAC + the controller's CLI cert scope.
- Hierarchical config (e.g. `clusters/<name>/...` driving multiple
  daemons from one binary). Workaround: run N controllers.
- Failure-replay buffer. A controller crash mid-reconcile leaves
  the daemon in whatever state the partial run achieved; the next
  poll picks up the rest. Most users find this acceptable; if not,
  set `--poll` short and add health checks.
