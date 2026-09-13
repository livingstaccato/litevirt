Title: fix(corrosion,grpcapi): order the audit chain and the event feed by values that order

---

`TestAuditChain_IntactAcrossInserts` fails intermittently on `main` with `chain broken at "row-c"` — 20 of 1000 runs on macOS, 0 of 1000 on Linux, because the rate depends on how many trailing zeros the clock happens to produce.

The chain is not broken. The verifier walks it in the wrong order, and chasing that turned up the same mistake in five more places. The through-line:

> **Every walk over the audit log was ordered by a value the writer chooses and the reader cannot trust.**

## The reported bug

Audit rows were stamped with `time.RFC3339Nano`, which trims trailing zeros, so stamps vary in width and don't sort in time order as TEXT:

| Earlier | Later | Text order |
|---|---|---|
| `…00.12Z` (120 ms) | `…00.125Z` | later first — `Z` sorts after `5` |
| `…01Z` | `…01.5Z` | later first — `.` sorts before `Z` |

## The bug underneath it

Fixed width makes text order match **clock** order. The chain links are built in **append** order, which is a different thing.

`InsertAuditLog` read the clock *before* taking the chain mutex. Two goroutines on one host could stamp in one order and chain in the other — every gRPC handler audits on its own goroutine under the same `HostName` — and a backward clock step does the same under a single writer: NTP correcting a drift, a restored snapshot, an operator setting the date.

Either way the verifier checks a row against the wrong `prev_hash` and prints `AUDIT CHAIN TAMPERED` over a log nothing touched. Permanently: the rows are signed, and `ResealAuditChain` refuses to rewrite them. That is the unclearable false alarm the comment above `VerifyAuditChain` says must never happen.

## The fix

**Order by `seq`.** It's assigned inside the chain mutex, alongside `prev_hash`, so it *is* the append order the stamp only approximates. `VerifyAuditChain`, `loadHostTail` and `resealHostChainLocked` all lead with it.

Reseal was the sharpest of the three: it **writes** the chain it computes and that write replicates, so walking it in an order the verifier didn't share wasn't a repair — it rewrote a correct chain into one every peer then reported as broken.

**`seq 0` became a finding rather than a position.** `InsertAuditLog` assigns `seq >= 1` to everything it writes, so a row carrying 0 went straight into the table. The contract check now reports it instead of placing it by what precedes it in the walk — an ordering an attacker can influence is not a foundation for a security finding.

<details>
<summary>Two designs tried and rejected — please read before suggesting either</summary>

**`ORDER BY seq ASC` alone.** Breaks `TestEnforcement_UnsignedAfterSignedIsTampering` and `TestEnforcement_HistoryBeforeTheContractIsNotTampering`: `seq 0` sorts to the front of a host's history, below any contract start, and a forger picks their own `seq`. The second test says it outright — *"giving the contract a start must not give an attacker one too."*

**Pinning `seq 0` rows to their `(timestamp, id)` slot** and permuting only the numbered rows among the slots they occupy. Preserves the enforcement tests, but with a legacy row present and a stamp regressing past it the walk still comes out wrong.

Treating `seq 0` as illegitimate dissolves the conflict instead of balancing it, and it's the honest end-state rule: there is no pre-`seq` population to protect.
</details>

**Generated stamps are clamped** to the host's tail, as `client.go`'s `NowTS` already clamps replication keys. Correctness no longer rests on it, but a regressed stamp still misorders `lv audit ls`. The clamp only ever raises, so two things that could push its ceiling forward are blocked: only stamps this node generated raise it, and a ceiling more than `maxClampSkew` ahead of the clock is ignored.

## The event feed, ordered by the same wrong thing

`audit_log` and `vm_events` reach a node only by CRDT replication — asynchronous and per-peer — so the order rows are written in across the cluster is not the order they land in locally. Both stream cursors were high-waters over the authoring stamp, which drops every row arriving after a newer-stamped one has advanced them. A host partitioned for two minutes rejoins, its whole backlog is older than the cursor, and none of it is ever sent, on a stream that stays open and returns no error.

Both cursors are now `rowid`, assigned when a row is inserted into *this* node's database. It's local and never travels between nodes. It is also not allocated forever-upward — SQLite hands out `max(rowid)+1`, so deleting the highest row frees that number, and `vm_events` is pruned in three places. So the cursor names the row that occupied the position as well as the position, and follows the table down when a prune frees a *run* of numbers off the top.

Four more faults in that one loop:

- the cursor advanced only for rows passing the event-type filter, so one full batch of filtered rows wedged it permanently;
- a backlog drained at one batch per tick — ten rows a second at the default interval, for the very case the cursor exists to handle;
- a failed query was a bare `continue` that logged nothing and also skipped the `vm_events` poll below it;
- draining held the `select` while the local event bus went unread — and `events.Bus` *drops* on a full subscriber channel, so a backlog silently cost local events.

## The export could not re-verify anything

`docs/audit-log.md` tells operators to ship `lv audit export` to WORM storage so an external system can re-verify without the daemon. It couldn't: it ordered by `(timestamp, id)`, carried no `seq`, and carried none of the state `verify` reasons over.

It now matches the verifier's order and projection, and ships `chain_heads`, `signing_keys`, `key_lifecycle` and the cluster CA alongside the rows. Without the heads a truncated chain replays clean — a backward-linked chain has nothing pointing forward. Without the contracts an unsigned row can't be told from one written before its host committed to signing. Without the CA a certificate can be read but not attributed to this cluster.

**Those tables are exported including rows marked deleted**, matching the verifier, which doesn't filter `deleted_at` on them either. Deleting a chain head is the efficient attack on truncation detection, so a tombstone has to be inert in both places — `TestAuditEvidence_ATombstoneIsInert` pins the daemon's half.

**The RPC is now paginated.** The response is one unary message against the daemon's 64 MiB send cap, so a chain worth attesting to didn't fit, and the only workaround was a `--since`/`--until` window — which produces exactly the fragment that can't be re-verified. The request carries a cursor and a limit, the response the next cursor. This adds three proto fields; no RPC signature changes.

Paging moves the problem to the caller, where getting it wrong is *silent*: a consumer that stops at page one returns a well-formed document that looks complete and isn't — for an artifact whose whole purpose is attestation, worse than the size failure it replaces. So the walk isn't written at each call site. `internal/auditexport.Assemble` owns it and all three consumers use it — `lv audit export`, the web UI's download button, and `GET /api/v1/audit/export` — each assembling every page into one document. `Assemble` refuses to return a partial chain if a server stops advancing its cursor, and takes keys other than `rows` from the first page that carries them, so a later page can't replace the evidence.

The CLI kept gRPC's 4 MiB *receive* default, and so did the daemon's in-process UI and REST clients. One page carries the server's default row count plus the evidence tables and the CA, which passes 4 MiB on a busy cluster — so paging alone would have moved the failure rather than fixed it. All three now match.

## `vm_events` had the original bug untouched

Same `RFC3339Nano` trimming, and `ts` is compared as TEXT by `ListVMEvents` and by the per-VM prune — whose own cutoffs were formatted the same way, so a bare-second bound sorted *after* the padded form and swept up the whole second it meant to stop at. There's no `seq` here to fall back on, so the fixed-width stamp is the fix rather than a second line of defence.

## Docs

Three passages described the old walk. A fourth was worse than stale: it said a clock skew violating HLC's `MaxSkewMS` is clamped *"so a wildly wrong host clock cannot reorder audit rows in a way that breaks the chain."* Audit stamps never came from the HLC, so that bounded nothing here — and asserted that the bug this PR fixes could not happen.

## Tests

Twenty-four new, each written before its fix and confirmed to fail without it.

| Test | Fails without |
|---|---|
| `TestAuditChain_IntactWhenStampsRegress` | `seq` in the verifier's walk |
| `TestAuditChain_TailAfterRestartIsTheLastAuthoredRow` | `seq` in the tail read |
| `TestAuditChain_ResealLeavesAGoodChainAlone` | `seq` in the reseal walk |
| `TestAuditChain_GeneratedStampsNeverRegress` | the tail clamp |
| `TestAuditChain_ACallerStampDoesNotBecomeTheClock` | only generated stamps raising the ceiling |
| `TestAuditChain_AFutureTailDoesNotDragTheClockForward` | the far-future ceiling bound |
| `TestAuditChain_StampsSortAsTextInTimeOrder` | fixed-width audit stamps |
| `TestVMEvents_StampsSortAsTextInTimeOrder` | fixed-width `vm_events` stamps |
| `TestExportAuditChain_ReplaysInAuthoredOrder` | the export's order and `seq` |
| `TestExportAuditChain_CarriesWhatVerifyReads` | the three evidence tables |
| `TestExportAuditChain_TombstonedEvidenceIsStillExported` | dropping the `deleted_at` filter |
| `TestExportAuditChain_CarriesTheCA` | `ca_pem` |
| `TestExportAuditChain_PagesWithoutLosingOrDuplicatingRows` | pagination |
| `TestAssemble_CarriesEveryPagesRows` | the cursor walk |
| `TestAssemble_KeepsFirstPageEvidence` | first-page evidence surviving a later page |
| `TestAssemble_StopsOnARepeatedCursor` | the non-advancing-server guard |
| `TestAssemble_ReturnsTheFetchError` | the error path |
| `TestAuditExport_FollowsTheCursorToTheEndOfTheChain` (ui) | the UI assembling every page |
| `TestAuditExport_ReturnsTheWholeChainNotTheFirstPage` (restapi) | the REST endpoint assembling every page |
| `TestStreamEvents_DeliversARowThatArrivesLate` | the arrival-order cursor |
| `TestStreamEvents_DeliversARowOnAReusedRowID` | the boundary row's id |
| `TestStreamEvents_DeliversAfterARunOfRowIDsIsFreed` | following the table down |
| `TestStreamEvents_FilterDoesNotStarveTheCursor` | advancing per row read |
| `TestStreamEvents_DrainsABurstWithoutWaitingATickPerBatch` | the multi-batch drain |

The two existing enforcement tests pin the rejected design: allowing `seq 0` rows to be reordered fails both.

Two notes on test changes, since both touch someone else's work:

`TestStreamEvents_DeliversARowFromTheSecondTheStreamOpened` is **replaced**. It opened the stream just after a whole second and called `t.Skipf` if the handshake ran long — going green having tested nothing, on exactly the loaded machines most likely to break it. Its successor inserts a row stamped an hour in the past: strictly harder, no clock alignment.

Two tests in `internal/cli` asserted raw dial-option **counts** as a proxy for "the token option is added iff a token exists". Adding an unconditional option broke the proxy while the intent held, so they now state the intent directly — one *more* option with a token than without.

## Verification

`go build`, `go vet ./...`, `go test ./...` and `make ci-guards` pass, with `-race` over both changed packages. Every assertion above was mutation-checked: the property broken, the test confirmed red, the property restored.

One unrelated failure on Linux: `TestFleet_FederationAndAnycast` fails identically on unmodified `main` and is fixed by the open #168. It's intermittent — its DNS readiness probe queries a public resolver and sometimes beats its own budget.

## Not proven here

- Behaviour on a real cluster. Everything above is in-process.
- During a rolling upgrade, peers on older binaries keep writing trimmed stamps into the same replicated tables. For `audit_log` the `seq` ordering makes that harmless; `vm_events` has no `seq`, so its ordering is only correct once every node is on the new binary.
- A chain that **already** contains a backward stamp step keeps whatever order it was written with. Nothing repairs that without rewriting signed hashes — the one thing reseal must never do.
