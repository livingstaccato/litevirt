package corrosion

import (
	"regexp"
	"testing"
)

// antiEntropyExcluded documents every CREATE-TABLE in schemaDDL that is
// deliberately NOT in tableNames or sensitiveTableNames — i.e. not carried by
// either anti-entropy repair path:
//
//   - coordination / local / transient state that MUST NOT be full-state-merged
//     (leases, replication progress, per-node bookkeeping, schema version), and
//   - secret stores that are not yet safe for the peer-only sensitive
//     anti-entropy lane, and therefore still rely on push replication.
//
// TestTableNamesCoverage forces every schemaDDL table into exactly one bucket
// (tableNames, sensitiveTableNames, or here) so coverage can't silently drift
// and tests can't overstate what anti-entropy actually repairs.
var antiEntropyExcluded = map[string]string{
	"local_automation_retained_deliveries":  "v82 node-local immutable retained delivery receipt/binding; never replicated or anti-entropy repaired",
	"local_automation_retained_objects":     "v82 node-local retained object descriptors/addresses; never replicated or anti-entropy repaired",
	"local_automation_retained_completions": "v82 node-local completion receipt after retained graph/candidate verification; never replicated or anti-entropy repaired",
	"local_automation_identity_continuity":  "v88 local certified-history-derived continuity; never replicated or native authority",
	"local_automation_executors":            "v86 local certified-history-derived execution projection; exact stage reset; never replicated or native authority",
	"local_automation_execution_progress":   "v86 local certified-history-derived execution projection; exact stage reset; never replicated or native authority",
	"local_automation_execution_artifacts":  "v86 local certified-history-derived execution projection; exact stage reset; never replicated or native authority",
	"local_automation_execution_terminals":  "v86 local certified-history-derived execution projection; exact stage reset; never replicated or native authority",
	"local_automation_target_operations":    "v84 certified-history-derived local target operation projection; empty stage active, nonempty stage isolated; never replicated",
	"local_automation_target_reservations":  "v84 certified-history-derived local complete-key target reservation projection; empty stage active, nonempty stage isolated; never replicated",
	"local_automation_local_audits":         "v76 inert local snapshot/aggregate evidence; no replication or authority",
	"local_automation_local_rows":           "v76 inert local snapshot/aggregate evidence; no replication or authority",
	"local_automation_aggregates":           "v76 inert local snapshot/aggregate evidence; no replication or authority",
	"local_automation_aggregate_sources":    "v76 inert local snapshot/aggregate evidence; no replication or authority",
	"local_automation_aggregate_copies":     "v76 inert local snapshot/aggregate evidence; no replication or authority",
	"local_automation_aggregate_maxima":     "v76 inert local snapshot/aggregate evidence; no replication or authority",
	"local_automation_aggregate_conflicts":  "v76 inert local snapshot/aggregate evidence; no replication or authority",
	"local_automation_lifetimes":            "v75 originating node-local observations, not certified lifecycle proof; never replicated or public cut content",
	"local_automation_credential_issuance":  "v75 private node-local credential observations/digests; never replicated, public cut content, or certified identity",

	"local_automation_identities":        "v74 local derived projection; empty stage active, nonempty stage isolated; never replicated",
	"local_automation_aliases":           "v74 local derived projection; empty stage active, nonempty stage isolated; never replicated",
	"local_automation_owners":            "v74 local derived projection; empty stage active, nonempty stage isolated; never replicated",
	"local_automation_semantic_heads":    "v74 local derived projection; empty stage active, nonempty stage isolated; never replicated",
	"local_automation_resources":         "v74 local derived projection; empty stage active, nonempty stage isolated; never replicated",
	"local_automation_names":             "v74 local derived projection; empty stage active, nonempty stage isolated; never replicated",
	"local_automation_bindings":          "v74 local derived projection; empty stage active, nonempty stage isolated; never replicated",
	"local_automation_admissions":        "v74 local derived projection; empty stage active, nonempty stage isolated; never replicated",
	"local_automation_key_epochs":        "v77 local derived projection; empty stage active, nonempty stage isolated; never replicated",
	"local_automation_key_recipients":    "v77 local derived projection; empty stage active, nonempty stage isolated; never replicated",
	"local_automation_payload_wrappings": "v77 local derived projection; empty stage active, nonempty stage isolated; never replicated",

	// Coordination / local / transient — must not be full-state-merged.
	"clock_skew":                            "per-node clock observations, GC'd locally",
	"crl_versions":                          "per-host CRL version tracking (gossiped)",
	"schema_state":                          "per-node schema version — must stay local for rolling upgrades (not CRDT-replicated)",
	"leader_election":                       "distributed lease — merging would corrupt leadership",
	"vm_locks":                              "per-VM lease — full-state merge would risk split-brain",
	"rebalance_proposals":                   "transient, leader-gated proposals",
	"vm_restarts":                           "per-node restart bookkeeping",
	"container_restarts":                    "per-node restart bookkeeping (container analogue of vm_restarts)",
	"vm_events":                             "high-volume append-only event log; best-effort, not full-state-repaired",
	"sessions":                              "ephemeral auth sessions",
	"mutation_log":                          "the replication WAL itself — never full-state-synced",
	"replication_watermarks":                "per-node replication progress",
	"mutation_seen":                         "per-node relay-dedup table",
	"host_runtime_usage":                    "per-host runtime telemetry (disk_iops/net_mbps); replicates via the WAL/mutation_log but is excluded from full-state anti-entropy — stale telemetry self-corrects on the next sample (cf. vm_events), so it needn't be repaired and shouldn't bloat the digest/dump",
	"idempotency_keys":                      "ephemeral request-dedup records (v39); LOCAL-only (owned by the entry node, never replicated), so no anti-entropy repair applies — see localOnly",
	"host_fw_intent":                        "per-host firewall infra decisions (v40, NAT/SNAT/isolation); LOCAL-only (nft rules are per-host state, never replicated) — see localOnly",
	"local_term_bindings":                   "per-executor (lease_key, lease_term) -> coordinator binding; LOCAL-only and deliberately in NO sync path. The fenced-claim guard used to derive this from runtime_action_proofs, which IS replicated and anti-entropy repaired — so any cluster member could plant rows naming a victim as executor_host across a span of terms and durably refuse that host's recovery. A binding a peer can author is not a binding. See TermFence and TestTermFence_IgnoresPeerAuthoredProofs",
	"local_recovery_claims":                 "v59 a voter's promises and accepts; LOCAL-only and in NO sync path. A grant is a statement about what THIS voter promised, so a replicated one would let a peer write promises on its behalf, LWW would coin-flip two of them and anti-entropy would regress a voter that was correctly ahead (docs/design/recovery-claims.md §3.8). Written only through ExecuteLocal",
	"local_voter_incarnation":               "v59 the identity of this state.db's claim state; LOCAL-only by definition — it must disappear exactly when the claim state does (§3.11)",
	"local_voter_adoption":                  "v59 which voter generations THIS node has adopted and imported claim state for; a question about this node's own voting state (§4.4)",
	"local_abandoned_proofs":                "v61 the proofs THIS destination signed it will never execute; LOCAL-only and in NO sync path — an abandonment is this node's own promise, and one a peer could erase or plant would let it either revive a superseded recovery or refuse a live one (docs/design/recovery-claims.md §3.12). Written only through ExecuteLocal",
	"local_voter_seals":                     "v62 the voter generations THIS node sealed as a survivor of a forced reconfiguration; a statement about this voter's own promises (§4.6). Written only through ExecuteLocal",
	"local_incarnation_claims":              "v63 a voter's promises and accepts at incarnation-scoped workload keys; LOCAL-only and in NO sync path, for local_recovery_claims' reasons (docs/design/recovery-claims.md §3.8, §10 item 37). Written only through ExecuteLocal",
	"session_factors":                       "v64 the second factor a session's login presented; as ephemeral as sessions, replicated through the WAL in the session's own batch, never full-state-merged",
	"session_groups":                        "v66 the directory groups a session's external-realm login verified; as ephemeral as sessions, replicated through the WAL in the session's own batch, never full-state-merged",
	"netbox_sync_queue":                     "work queue for the P2 NetBox inventory mirror (v51); a LATENCY optimisation only — the periodic full sweep is the correctness mechanism, so a lost/stale queue row self-heals on the next sweep (cf. vm_events/host_runtime_usage)",
	"local_automation_receiver_audits":      "v73 inert semantic audit; never authority or replication",
	"local_automation_receiver_refs":        "v73 inert semantic audit; never authority or replication",
	"local_automation_receiver_requests":    "v73 inert semantic audit; never authority or replication",
	"local_automation_receiver_jobs":        "v72 inert receiver staging; never authority or replication",
	"local_automation_receiver_current":     "v72 inert receiver staging; never authority or replication",
	"local_automation_receiver_established": "v78 local signed floor ownership; never live proof or replication",
	"local_automation_receiver_validations": "v72 inert receiver staging; never authority or replication",
	"local_automation_receiver_sources":     "v72 inert receiver staging; never authority or replication",
	"local_automation_receiver_components":  "v72 inert receiver staging; never authority or replication",
	"local_automation_receiver_records":     "v72 inert receiver staging; never authority or replication",
	"local_automation_receiver_pages":       "v72 inert receiver staging; never authority or replication",
	"local_automation_source_jobs":          "v71 immutable outgoing source request pins; never peer-authored",
	"local_automation_publications":         "v71 completed source artifacts and public evidence; never replicated or repaired",
	"local_automation_cuts":                 "v70 immutable source-cut metadata owned by this database incarnation; generic AE cannot certify or publish a cut",
	"local_automation_cut_records":          "v70 immutable source-cut records; imported only by a future authenticated bounded transfer, never generic AE",
	"local_automation_recovery":             "v69 this node's in-progress certified prefix recovery cursor; peer-authored state cannot advance it",
	"local_automation_staging":              "v69 this node's uncommitted recovery evidence; generic AE cannot turn staging into adopted state",
	"local_automation_authority":            "v69 local automation authority and incarnation binding; replication cannot grant a node authority",
	"local_automation_prefix":               "v69 this node's durably applied automation prefix; local FULL transaction owns advancement",
	"local_automation_anchors":              "v69 locally verified certified automation anchors; generic AE cannot establish local adoption",
	"local_automation_history":              "v69 local applied automation decision history and receipts; only the certified apply path may write it",
	"local_automation_requests":             "v69 local durable automation request/receipt identity; generic AE cannot mint or overwrite admission facts",
	// (user_2fa, recovery_codes, recovery_code_sets are now in sensitiveTableNames
	//  — schema v32 made them LWW-repairable: soft-delete + active-set pointer.)
}

// localOnly are schemaDDL tables that are NOT CRDT-replicated (written via direct
// DB access, not the replicating Execute path). The updated_at→primary-key
// invariant below doesn't apply to them.
var localOnly = map[string]bool{
	"local_automation_local_audits":        true,
	"local_automation_local_rows":          true,
	"local_automation_aggregates":          true,
	"local_automation_aggregate_sources":   true,
	"local_automation_aggregate_copies":    true,
	"local_automation_aggregate_maxima":    true,
	"local_automation_aggregate_conflicts": true,
	"local_automation_lifetimes":           true,
	"local_automation_credential_issuance": true,

	"local_automation_identities":        true,
	"local_automation_aliases":           true,
	"local_automation_owners":            true,
	"local_automation_semantic_heads":    true,
	"local_automation_resources":         true,
	"local_automation_names":             true,
	"local_automation_bindings":          true,
	"local_automation_admissions":        true,
	"local_automation_key_epochs":        true,
	"local_automation_key_recipients":    true,
	"local_automation_payload_wrappings": true,

	"local_automation_receiver_audits":      true,
	"local_automation_receiver_refs":        true,
	"local_automation_receiver_requests":    true,
	"local_automation_receiver_jobs":        true,
	"local_automation_receiver_current":     true,
	"local_automation_receiver_established": true,
	"local_automation_receiver_validations": true,
	"local_automation_receiver_sources":     true,
	"local_automation_receiver_components":  true,
	"local_automation_receiver_records":     true,
	"local_automation_receiver_pages":       true,
	"local_automation_source_jobs":          true,
	"local_automation_publications":         true,
	"local_automation_cuts":                 true, // local transaction only; see exclusion reason above
	"local_automation_cut_records":          true, // local transaction only; see exclusion reason above
	"local_automation_recovery":             true, // local transaction only; see exclusion reason above
	"local_automation_staging":              true, // local transaction only; see exclusion reason above
	"local_automation_authority":            true, // local transaction only; see exclusion reason above
	"local_automation_prefix":               true, // local transaction only; see exclusion reason above
	"local_automation_anchors":              true, // local transaction only; see exclusion reason above
	"local_automation_history":              true, // local transaction only; see exclusion reason above
	"local_automation_requests":             true, // local transaction only; see exclusion reason above

	"schema_state":             true, // per-node schema version, set during InitSchema/migrate
	"idempotency_keys":         true, // v39: entry-node-owned request dedup; execLocal writes, never replicated
	"host_fw_intent":           true, // v40: per-host firewall infra intent; execLocal writes, never replicated
	"local_recovery_claims":    true, // v59: ExecuteLocal writes, never replicated
	"local_voter_incarnation":  true, // v59: ExecuteLocal writes, never replicated
	"local_voter_adoption":     true, // v59: ExecuteLocal writes, never replicated
	"local_abandoned_proofs":   true, // v61: ExecuteLocal writes, never replicated
	"local_voter_seals":        true, // v62: ExecuteLocal writes, never replicated
	"local_incarnation_claims": true, // v63: ExecuteLocal writes, never replicated
}

var createTableRe = regexp.MustCompile(`CREATE TABLE IF NOT EXISTS ([a-z_0-9]+)`)

func schemaDDLTables() []string {
	var out []string
	for _, stmt := range schemaDDL {
		if m := createTableRe.FindStringSubmatch(stmt); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

// TestTableNamesCoverage is anchored on the schema (schemaDDL), not on
// tablePrimaryKeys — a replicated table missing from tablePrimaryKeys would
// otherwise be invisible. Every schemaDDL table must be explicitly categorized,
// and every replicated table with updated_at must have a primary key so LWW
// applies (both in the anti-entropy merge and the Crescent apply path).
func TestTableNamesCoverage(t *testing.T) {
	tables := schemaDDLTables()
	if len(tables) < 50 {
		t.Fatalf("parsed only %d schemaDDL tables — regex likely broke", len(tables))
	}
	schemaSet := make(map[string]bool, len(tables))
	for _, n := range tables {
		schemaSet[n] = true
	}
	inTableNames := make(map[string]bool, len(tableNames))
	for _, n := range tableNames {
		inTableNames[n] = true
	}
	inSensitiveNames := make(map[string]bool, len(sensitiveTableNames))
	for _, n := range sensitiveTableNames {
		inSensitiveNames[n] = true
	}

	c := mustTestClient(t)
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()

	for _, tbl := range tables {
		_, excluded := antiEntropyExcluded[tbl]
		switch {
		case inTableNames[tbl] && inSensitiveNames[tbl]:
			t.Errorf("table %q is in BOTH tableNames and sensitiveTableNames — public dumps must stay redacted", tbl)
		case (inTableNames[tbl] || inSensitiveNames[tbl]) && excluded:
			t.Errorf("table %q is repaired and antiEntropyExcluded — pick one", tbl)
		case !inTableNames[tbl] && !inSensitiveNames[tbl] && !excluded:
			t.Errorf("schemaDDL table %q is neither in tableNames nor antiEntropyExcluded — "+
				"add it to tableNames/sensitiveTableNames (anti-entropy coverage) or to antiEntropyExcluded with a reason", tbl)
		}

		// Replicated table with updated_at MUST have a primary key, else LWW is
		// silently skipped and an older write/dump can clobber a newer row.
		if localOnly[tbl] {
			continue
		}
		cols, err := tableColumns(tx, tbl)
		if err != nil {
			t.Fatalf("tableColumns(%s): %v", tbl, err)
		}
		if cols["updated_at"] {
			if _, ok := tablePrimaryKeys[tbl]; !ok {
				t.Errorf("table %q has updated_at but no tablePrimaryKeys entry — LWW is silently "+
					"skipped (older write/dump can clobber newer)", tbl)
			}
		}

		// A full-state table that soft-deletes (has deleted_at) MUST also have
		// updated_at: a tombstone needs a timestamp to win LWW. The apply path uses a
		// PK-aware UPSERT (INSERT … ON CONFLICT(pk) DO UPDATE SET nonPK=excluded.…), so
		// without updated_at a stale live row from a peer wins the upsert and resurrects
		// the tombstoned row — e.g. an un-revoked token.
		if inTableNames[tbl] && cols["deleted_at"] && !cols["updated_at"] {
			t.Errorf("table %q is full-state synced with deleted_at but no updated_at — "+
				"a tombstone can't win LWW, so a stale live row resurrects it", tbl)
		}
		if inSensitiveNames[tbl] {
			if _, ok := tablePrimaryKeys[tbl]; !ok {
				t.Errorf("sensitive table %q has no tablePrimaryKeys entry — sensitive merge would blind-replace rows", tbl)
			}
			if !cols["updated_at"] {
				t.Errorf("sensitive table %q has no updated_at — sensitive merge cannot arbitrate LWW", tbl)
			}
			if !cols["deleted_at"] {
				t.Errorf("sensitive table %q has no deleted_at — delete/revoke tombstones cannot be repaired", tbl)
			}
		}
	}

	// No phantom entries: every name in our maps/lists must be a real schemaDDL table.
	for _, n := range tableNames {
		if !schemaSet[n] {
			t.Errorf("tableNames contains %q which is not a schemaDDL table", n)
		}
	}
	for _, n := range sensitiveTableNames {
		if !schemaSet[n] {
			t.Errorf("sensitiveTableNames contains %q which is not a schemaDDL table", n)
		}
	}
	for n := range antiEntropyExcluded {
		if !schemaSet[n] {
			t.Errorf("antiEntropyExcluded names %q which is not a schemaDDL table (stale?)", n)
		}
	}
	for n := range tablePrimaryKeys {
		if !schemaSet[n] {
			t.Errorf("tablePrimaryKeys names %q which is not a schemaDDL table (stale?)", n)
		}
	}
	for n := range localOnly {
		if !schemaSet[n] {
			t.Errorf("localOnly names %q which is not a schemaDDL table (stale?)", n)
		}
	}
}
