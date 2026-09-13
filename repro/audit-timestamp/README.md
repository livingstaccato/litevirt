# Audit-timestamp ordering fix — reproduction

This branch (`repro/audit-timestamp-order`) is the fix branch
`fix/audit-timestamp-order` plus this directory. Nothing here is part of the
upstream pull request; the Go changes are identical to the fix branch.

- `run.sh` — reproduces the reported bug on the unfixed base and checks the fix
- `PR.md` — the draft pull request description, and the fuller account
- `PROMPT.md` — a prompt for an agent that clones this branch and runs it

## What this script proves, and what it does not

The script was written for the **reported** bug: `TestAuditChain_IntactAcrossInserts`
failing intermittently because `time.RFC3339Nano` trims trailing zeros, so audit
stamps vary in width and `…00.12Z` sorts after the later `…00.125Z`.

Investigating that turned up a deeper one. Fixed-width stamps make text order
match *clock* order; they do not make clock order match *append* order, and the
chain links are built in append order. `InsertAuditLog` read the clock before
taking the chain mutex, so concurrent writers on one host could stamp in one
order and chain in the other — and a backward clock step does the same under a
single writer. The fix branch therefore orders each host's sub-chain by `seq`,
and the stamp width is now a display and cross-host concern rather than the
thing correctness rests on.

**This script still only exercises the first bug.** It is kept because that is
what the flake report was about and a reviewer may want to watch it fail. The
`seq` ordering, the arrival-order event cursor, the export and its pagination,
and the `vm_events` stamp are covered by the twenty-four tests listed in `PR.md`,
each written before its fix and confirmed to fail without it — not by anything
here.

## Requirements

Go 1.26+ (go.mod), git, make, network access to github.com. No cgo and no
root: the SQLite driver is pure Go and every test here is in-process.

## Running

```bash
bash repro/audit-timestamp/run.sh
RUNS=200 bash repro/audit-timestamp/run.sh   # quicker, weaker statistics
```

The script adds `https://github.com/colonelpanik/litevirt.git` as remote
`upstream` if it is missing, creates the unfixed base as a worktree in a temp
directory (never inside the checkout), writes every log there, and prints a
`RESULT` line per check. Exit code 1 means at least one `RESULT FAIL`.

## Steps and what counts as a pass

| Step | What it runs | Pass |
|---|---|---|
| 1 | flaky test ×RUNS on the base | informational — shows the flake rate on this host's clock |
| 2 | flaky test ×RUNS on the fix | 0 failures |
| 3 | cause probe ×RUNS on the base: on every break, print the stored stamps | every break has stamps of unequal width stored out of insert order |
| 3 | fixed-stamp probe on the base | `.12Z`→`.125Z` and `00Z`→`00.5Z` break at `row-b`; padded stamps do not |
| 4 | one audit and one stream test on the fix, 5× each (stream under `-race`) | 5/5 pass, no data race, **no skips** |
| 5 | the new audit test copied onto the base | fails |
| 6 | `go build`, `go vet`, `go test ./...`, `make ci-guards` against `upstream/main` | build/vet/ci-guards pass |

A skip in step 4 is a failure, not an excuse. The stream test it runs used to
open the stream just after a whole second and skip itself if the handshake ran
long — going green having tested nothing, on exactly the loaded machines most
likely to break it. Its replacement inserts a row stamped an hour in the past,
which is strictly harder and needs no clock alignment.

## Clock resolution decides step 1 and step 3

macOS reports microseconds, so nearly every stamp is trimmed and the flake rate
is high. Linux reports nanoseconds, so trimming is rare and both steps can come
back clean — that is the clock, not the absence of the bug. Steps 2, 3
(fixed stamps), 4, 5 and 6 do not depend on it.

Measured:

| | macOS (arm64, Go 1.27.1) | Linux (amd64, Go 1.26.0) |
|---|---|---|
| step 1, failures on base | 20/1000 | 0/1000 |
| step 3, chain breaks on base | 20/1000, all unequal-width and out of insert order | 0/1000 |
| step 2, failures on fix | 0/1000 | 0/1000 |
| `TestSIGPIPEDoesNotKillTheProcess` | fails, including on unfixed `main` | passes |

Step 6 on Linux reports one unrelated failure: `TestFleet_FederationAndAnycast`,
which fails identically on unmodified `upstream/main` and is fixed by the open
upstream #168. Its DNS readiness probe asked a root-level name, which the mux
forwards, and `resolvConfUpstream()` skips loopback nameservers — so on any
systemd-resolved host it queries 8.8.8.8 and the round trip outruns the probe's
budget.

## Not proven by any of this

- Behaviour on a real cluster. Everything here is in-process.
- Cross-host display order during a rolling upgrade, where old and new hosts
  write different stamp widths.
- A chain that **already** contains a backward stamp step keeps whatever order
  it was written with. Nothing repairs that without rewriting signed hashes,
  which is the one thing reseal must never do.
