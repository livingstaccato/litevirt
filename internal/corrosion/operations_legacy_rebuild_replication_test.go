package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func snapshotClaimTestGate(c *Client) {
	c.SetVMSnapshotClaimCapability(func() bool { return true }, func(context.Context) bool { return true })
}

func snapshotClaimReplica(t *testing.T, stamped bool) (*Client, *Client, *pb.MutationEntry, OperationRecord, VMDeleteSnapshot) {
	t.Helper()
	src, before, op := snapshotCASFixture(t)
	dst := newTestDB(t)
	snapshotClaimTestGate(dst)
	ctx := context.Background()
	if stamped {
		src.SetSpecConflictGate(func() bool { return true })
		dst.SetSpecConflictGate(func() bool { return true })
	}
	if _, err := NewReplicator(dst, "", RelayConfig{}).ApplyRemoteMutations(ctx, walEntries(t, src, "source")); err != nil {
		t.Fatal(err)
	}
	n := len(walEntries(t, src, "source"))
	if ok, err := src.BeginVMOperationAtSnapshot(ctx, op, `{"cpu":4}`, before); !ok || err != nil {
		t.Fatalf("origin: applied=%v err=%v", ok, err)
	}
	entries := walEntries(t, src, "source")
	if len(entries) != n+1 {
		t.Fatalf("claim emitted %d entries", len(entries)-n)
	}
	return src, dst, entries[n], op, before
}

func snapshotClaimWire(t *testing.T, entry *pb.MutationEntry) []Statement {
	t.Helper()
	stmts, err := decodeSnapshotClaimStatements(entry.Stmts)
	if err != nil {
		t.Fatal(err)
	}
	return stmts
}

func snapshotClaimWireEntry(t *testing.T, original *pb.MutationEntry, stmts []Statement) *pb.MutationEntry {
	t.Helper()
	raw, err := json.Marshal(stmts)
	if err != nil {
		t.Fatal(err)
	}
	return &pb.MutationEntry{Seq: original.Seq, Origin: original.Origin, Hlc: original.Hlc, Stmts: string(raw)}
}

func snapshotClaimAllRows(t *testing.T, c *Client) [][]Row {
	t.Helper()
	out := snapshotCASImage(t, c)
	seen, err := c.Query(context.Background(), `SELECT * FROM mutation_seen ORDER BY origin,hlc`)
	if err != nil {
		t.Fatal(err)
	}
	return append(out, seen)
}

func snapshotClaimRefusedEntry(t *testing.T, dst *Client, entry *pb.MutationEntry) {
	t.Helper()
	before := snapshotClaimAllRows(t, dst)
	seq, err := NewReplicator(dst, "", RelayConfig{}).ApplyRemoteMutations(context.Background(), []*pb.MutationEntry{entry})
	if err == nil || seq != 0 {
		t.Fatalf("refusal consumed sequence: seq=%d err=%v", seq, err)
	}
	if !reflect.DeepEqual(before, snapshotClaimAllRows(t, dst)) {
		t.Fatal("refusal changed VM/header/steps/WAL/seen")
	}
}

func snapshotClaimExpectDecision(t *testing.T, c *Client, entry *pb.MutationEntry, want snapshotClaimOutcome) {
	t.Helper()
	tx, err := c.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	e, err := validateSnapshotClaimEntry(snapshotClaimWire(t, entry))
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.snapshotClaimDecision(context.Background(), tx, e)
	if err != nil || got != want {
		t.Fatalf("outcome=%q err=%v want=%q", got, err, want)
	}
}

func snapshotClaimExec(t *testing.T, c *Client, query string, args ...interface{}) {
	t.Helper()
	if _, err := c.db.ExecContext(context.Background(), query, args...); err != nil {
		t.Fatal(err)
	}
}

func snapshotClaimSeedRole(t *testing.T, c *Client, s Statement) {
	t.Helper()
	args := append([]interface{}(nil), s.Params...)
	for i, p := range args {
		if n, ok := p.(json.Number); ok {
			v, err := n.Int64()
			if err != nil {
				t.Fatal(err)
			}
			args[i] = v
		}
	}
	snapshotClaimExec(t, c, s.SQL, args...)
}

func TestVMSnapshotClaimReplicatedApplyAndReplay(t *testing.T) {
	for _, stamped := range []bool{false, true} {
		t.Run(fmt.Sprint(stamped), func(t *testing.T) {
			src, dst, entry, _, _ := snapshotClaimReplica(t, stamped)
			snapshotClaimExpectDecision(t, dst, entry, snapshotClaimApplied)
			r := NewReplicator(dst, "", RelayConfig{})
			if seq, err := r.ApplyRemoteMutations(context.Background(), []*pb.MutationEntry{entry}); err != nil || seq != entry.Seq {
				t.Fatalf("apply seq=%d err=%v", seq, err)
			}
			if !reflect.DeepEqual(snapshotCASImage(t, src)[:3], snapshotCASImage(t, dst)[:3]) {
				t.Fatal("receiver rewrote normalized/stamped spec or journal bytes")
			}
			before := snapshotClaimAllRows(t, dst)
			if _, err := r.ApplyRemoteMutations(context.Background(), []*pb.MutationEntry{entry}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, snapshotClaimAllRows(t, dst)) {
				t.Fatal("seen replay wrote rows")
			}
			// Different stream identity forces the retained-byte decision rather
			// than letting mutation_seen alone make this test pass.
			duplicate := snapshotClaimWireEntry(t, entry, snapshotClaimWire(t, entry))
			duplicate.Origin = "second-relay"
			snapshotClaimExpectDecision(t, dst, duplicate, snapshotClaimDuplicate)
			claimRows := snapshotCASImage(t, dst)
			if _, err := r.ApplyRemoteMutations(context.Background(), []*pb.MutationEntry{duplicate}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(claimRows, snapshotCASImage(t, dst)) {
				t.Fatal("duplicate rewrote claim or emitted WAL")
			}
		})
	}
}

func TestVMSnapshotClaimRefusesMalformedEntry(t *testing.T) {
	cases := map[string]func([]Statement) []Statement{
		"missing_update":   func(s []Statement) []Statement { return s[1:] },
		"missing_header":   func(s []Statement) []Statement { return []Statement{s[0], s[2]} },
		"missing_facts":    func(s []Statement) []Statement { return s[:2] },
		"extra_role":       func(s []Statement) []Statement { return append(s, s[2]) },
		"reordered":        func(s []Statement) []Statement { s[1], s[2] = s[2], s[1]; return s },
		"unguarded_update": func(s []Statement) []Statement { s[0].Guard = nil; return s },
		"unguarded_header": func(s []Statement) []Statement { s[1].Guard = nil; return s },
		"unguarded_facts":  func(s []Statement) []Statement { s[2].Guard = nil; return s },
		"unknown_protocol": func(s []Statement) []Statement {
			for i := range s {
				s[i].Guard.Protocol = "unknown-snapshot"
			}
			return s
		},
		"wrong_kind": func(s []Statement) []Statement {
			for i := range s {
				s[i].Guard.ResourceKind = "container"
			}
			return s
		},
		"extra_guard_axis": func(s []Statement) []Statement {
			for i := range s {
				s[i].Guard.RequireOperation = true
			}
			return s
		},
		"rebound_guard": func(s []Statement) []Statement { s[0].Guard.Incarnation += "-other"; return s },
		"sql_update": func(s []Statement) []Statement {
			s[0].SQL = strings.Replace(s[0].SQL, "created_at = ?", "created_at != ?", 1)
			return s
		},
		"ignored_header": func(s []Statement) []Statement {
			s[1].SQL = strings.Replace(s[1].SQL, "INSERT INTO", "INSERT OR IGNORE INTO", 1)
			return s
		},
		"rebound_header":       func(s []Statement) []Statement { s[1].Params[2] = "other-principal"; return s },
		"wrong_vm_name":        func(s []Statement) []Statement { s[0].Params[4] = "other"; return s },
		"wrong_after_spec":     func(s []Statement) []Statement { s[0].Params[0] = `{"cpu":8}`; return s },
		"wrong_creation_stamp": func(s []Statement) []Statement { s[2].Params[4] = "2000-01-01T00:00:00Z"; return s },
		"wrong_update_stamp":   func(s []Statement) []Statement { s[0].Params[3] = "2000-01-01T00:00:00Z"; return s },
		"empty_facts":          func(s []Statement) []Statement { s[2].Params[3] = ""; return s },
		"unknown_facts_field": func(s []Statement) []Statement {
			s[2].Params[3] = strings.Replace(s[2].Params[3].(string), `{"version":1`, `{"unknown":0,"version":1`, 1)
			return s
		},
		"duplicate_facts_field": func(s []Statement) []Statement {
			s[2].Params[3] = strings.Replace(s[2].Params[3].(string), `{"version":1`, `{"version":1,"version":1`, 1)
			return s
		},
		"unsupported_version": func(s []Statement) []Statement {
			s[2].Params[3] = strings.Replace(s[2].Params[3].(string), `{"version":1`, `{"version":2`, 1)
			return s
		},
		"omitted_zero": func(s []Statement) []Statement {
			s[2].Params[3] = strings.Replace(s[2].Params[3].(string), `"owner_epoch":0,`, "", 1)
			return s
		},
		"null_before": func(s []Statement) []Statement {
			var f map[string]interface{}
			_ = json.Unmarshal([]byte(s[2].Params[3].(string)), &f)
			f["before"] = nil
			raw, _ := json.Marshal(f)
			s[2].Params[3] = string(raw)
			return s
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			_, dst, entry, _, _ := snapshotClaimReplica(t, false)
			snapshotClaimRefusedEntry(t, dst, snapshotClaimWireEntry(t, entry, change(snapshotClaimWire(t, entry))))
		})
	}
}

func TestVMSnapshotClaimPartialConflictAndSupersession(t *testing.T) {
	for _, state := range []string{"missing_vm", "header_only", "facts_only", "after_row_only", "conflicting_header", "conflicting_facts",
		"tombstoned_header", "tombstoned_facts", "created_at_only", "tombstone", "terminal_new_lifetime",
		"complete_tombstone", "partial_tombstone", "nonterminal_new_lifetime", "faulted_terminal", "known_conflict", "acknowledged_conflict"} {
		t.Run(state, func(t *testing.T) {
			_, dst, entry, op, _ := snapshotClaimReplica(t, false)
			stmts := snapshotClaimWire(t, entry)
			want := snapshotClaimOutcome("")
			switch state {
			case "missing_vm":
				snapshotClaimExec(t, dst, `DELETE FROM vms WHERE name = ?`, op.ResourceID)
			case "header_only":
				snapshotClaimSeedRole(t, dst, stmts[1])
			case "facts_only":
				snapshotClaimSeedRole(t, dst, stmts[2])
			case "after_row_only":
				snapshotClaimSeedRole(t, dst, stmts[0])
			case "conflicting_header", "tombstoned_header":
				snapshotClaimSeedRole(t, dst, stmts[1])
				if state == "conflicting_header" {
					snapshotClaimExec(t, dst, `UPDATE operations SET principal = 'other' WHERE id = ?`, op.ID)
				} else {
					snapshotClaimExec(t, dst, `UPDATE operations SET deleted_at = '' WHERE id = ?`, op.ID)
				}
				// Conflict priority survives a same-lifetime tombstone.
				snapshotClaimExec(t, dst, `UPDATE vms SET deleted_at = 'gone' WHERE name = ?`, op.ResourceID)
			case "conflicting_facts", "tombstoned_facts":
				snapshotClaimSeedRole(t, dst, stmts[2])
				if state == "conflicting_facts" {
					snapshotClaimExec(t, dst, `UPDATE operation_steps SET facts = '{}'`)
				} else {
					snapshotClaimExec(t, dst, `UPDATE operation_steps SET deleted_at = ''`)
				}
			case "created_at_only":
				snapshotClaimExec(t, dst, `UPDATE vms SET created_at = '2030-01-01T00:00:00Z' WHERE name = ?`, op.ResourceID)
			case "tombstone":
				snapshotClaimExec(t, dst, `UPDATE vms SET deleted_at = 'gone' WHERE name = ?`, op.ResourceID)
				want = snapshotClaimTombstone
			case "complete_tombstone", "partial_tombstone":
				snapshotClaimSeedRole(t, dst, stmts[1])
				if state == "complete_tombstone" {
					snapshotClaimSeedRole(t, dst, stmts[2])
					want = snapshotClaimTombstone
				}
				snapshotClaimExec(t, dst, `UPDATE vms SET deleted_at = 'gone' WHERE name = ?`, op.ResourceID)
			case "terminal_new_lifetime", "nonterminal_new_lifetime", "faulted_terminal":
				if _, err := NewReplicator(dst, "", RelayConfig{}).ApplyRemoteMutations(context.Background(), []*pb.MutationEntry{entry}); err != nil {
					t.Fatal(err)
				}
				entry.Origin = "delayed-relay"
				snapshotClaimExec(t, dst, `UPDATE vms SET created_at = '2030-01-01T00:00:00Z', spec_generation = 0, active_operation_id = '' WHERE name = ?`, op.ResourceID)
				if state != "nonterminal_new_lifetime" {
					snapshotClaimSeedRole(t, dst, operationStepInsertStatement(op.ID, 0, OpStepCompleted, "", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", nil))
					want = snapshotClaimIncarnation
				}
				if state == "faulted_terminal" {
					snapshotClaimSeedRole(t, dst, operationStepInsertStatement(op.ID, 0, OpStepFailed, "", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", nil))
					want = ""
				}
			case "known_conflict", "acknowledged_conflict":
				key := unresolvedKey("operations", pkKey([]interface{}{op.ID}))
				dst.tieMu.Lock()
				if dst.unresolvedTies == nil {
					dst.unresolvedTies = make(map[string]unresolvedTie)
				}
				dst.unresolvedTies[key] = unresolvedTie{acknowledged: state == "acknowledged_conflict"}
				dst.tieMu.Unlock()
			}
			if want == "" {
				snapshotClaimRefusedEntry(t, dst, entry)
				return
			}
			snapshotClaimExpectDecision(t, dst, entry, want)
			before := snapshotCASImage(t, dst)
			seq, err := NewReplicator(dst, "", RelayConfig{}).ApplyRemoteMutations(context.Background(), []*pb.MutationEntry{entry})
			if err != nil || seq != entry.Seq {
				t.Fatalf("supersession seq=%d err=%v", seq, err)
			}
			if !reflect.DeepEqual(before, snapshotCASImage(t, dst)) {
				t.Fatal("supersession changed claim tables/WAL")
			}
			e, err := validateSnapshotClaimEntry(stmts)
			if err != nil {
				t.Fatal(err)
			}
			b := e.facts.Before
			expected := VMDeleteSnapshot{CreatedAt: b.CreatedAt, HostName: b.HostName, OwnerEpoch: b.OwnerEpoch,
				SpecGeneration: b.SpecGeneration, IdentityHash: b.IdentityHash, FirewallID: b.FirewallID}
			if ok, err := dst.BeginVMOperationAtSnapshot(context.Background(), op, `{"cpu":4}`, expected); ok || err == nil {
				t.Fatal("local API reported supersession as applied", ok, err)
			}
			if !reflect.DeepEqual(before, snapshotCASImage(t, dst)) {
				t.Fatal("local supersession mutated claim")
			}
		})
	}
}

func TestVMSnapshotClaimAtomicRollback(t *testing.T) {
	for _, role := range []string{"vms", "operations", "operation_steps"} {
		t.Run(role, func(t *testing.T) {
			_, dst, entry, _, _ := snapshotClaimReplica(t, false)
			event := "INSERT"
			if role == "vms" {
				event = "UPDATE"
			}
			snapshotClaimExec(t, dst, fmt.Sprintf(`CREATE TRIGGER snapshot_claim_fail AFTER %s ON %s BEGIN SELECT RAISE(ABORT, 'injected snapshot claim failure'); END`, event, role))
			snapshotClaimRefusedEntry(t, dst, entry)
			c, snap, op := snapshotCASFixture(t)
			snapshotClaimExec(t, c, fmt.Sprintf(`CREATE TRIGGER snapshot_claim_fail AFTER %s ON %s BEGIN SELECT RAISE(ABORT, 'injected snapshot claim failure'); END`, event, role))
			before := snapshotCASImage(t, c)
			if ok, err := c.BeginVMOperationAtSnapshot(context.Background(), op, `{"cpu":4}`, snap); ok || err == nil {
				t.Fatalf("origin injected failure ok=%v err=%v", ok, err)
			}
			if !reflect.DeepEqual(before, snapshotCASImage(t, c)) {
				t.Fatal("origin failed transaction leaked")
			}
		})
	}
}

func TestVMSnapshotClaimLocalRetryInputAndCapabilities(t *testing.T) {
	c, snap, op := snapshotCASFixture(t)
	ctx := context.Background()
	for _, gate := range []string{"no_hook", "not_ready", "not_durable"} {
		t.Run(gate, func(t *testing.T) {
			switch gate {
			case "no_hook":
				c.SetVMSnapshotClaimCapability(nil, nil)
			case "not_ready":
				c.SetVMSnapshotClaimCapability(func() bool { return true }, func(context.Context) bool { return false })
			case "not_durable":
				c.SetVMSnapshotClaimCapability(func() bool { return false }, func(context.Context) bool { return true })
			}
			before := snapshotCASImage(t, c)
			if ok, err := c.BeginVMOperationAtSnapshot(ctx, op, `{"cpu":4}`, snap); ok || err == nil {
				t.Fatalf("gate ok=%v err=%v", ok, err)
			}
			if !reflect.DeepEqual(before, snapshotCASImage(t, c)) {
				t.Fatal("capability refusal emitted")
			}
		})
	}
	snapshotClaimTestGate(c)
	if ok, err := c.BeginVMOperationAtSnapshot(ctx, op, `{"cpu":4}`, snap); !ok || err != nil {
		t.Fatal(ok, err)
	}
	before := snapshotCASImage(t, c)
	if ok, err := c.BeginVMOperationAtSnapshot(ctx, op, `{ "cpu":4 }`, snap); ok || err == nil {
		t.Fatal("byte-different input was accepted")
	}
	if !reflect.DeepEqual(before, snapshotCASImage(t, c)) {
		t.Fatal("input conflict changed rows")
	}
}

func TestVMSnapshotClaimCounterBounds(t *testing.T) {
	for _, generation := range []int64{-1, math.MaxInt64, 1<<53 + 1} {
		t.Run(fmt.Sprint(generation), func(t *testing.T) {
			c, _, op := snapshotCASFixture(t)
			snapshotClaimExec(t, c, `UPDATE vms SET spec_generation = ?`, generation)
			snap := SnapshotForDelete(*snapshotCASReadVM(t, c))
			before := snapshotCASImage(t, c)
			ok, err := c.BeginVMOperationAtSnapshot(context.Background(), op, `{"cpu":4}`, snap)
			if generation == 1<<53+1 {
				if !ok || err != nil {
					t.Fatalf("exact int64 claim: ok=%v err=%v", ok, err)
				}
			} else if ok || err == nil || !reflect.DeepEqual(before, snapshotCASImage(t, c)) {
				t.Fatalf("bad counter changed state: ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestVMSnapshotClaimReceiverWithoutDurableCapability(t *testing.T) {
	_, dst, entry, _, _ := snapshotClaimReplica(t, false)
	dst.SetVMSnapshotClaimCapability(nil, nil)
	snapshotClaimRefusedEntry(t, dst, entry)
}

func TestVMSnapshotClaimReceiverReopen(t *testing.T) {
	ctx := context.Background()
	src, snap, op := snapshotCASFixture(t)
	dir := t.TempDir()
	dst, err := NewLocalClient(dir, "receiver")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if dst != nil {
			dst.Close()
		}
	})
	if err := InitSchema(ctx, dst); err != nil {
		t.Fatal(err)
	}
	snapshotClaimTestGate(dst)
	if _, err := NewReplicator(dst, "", RelayConfig{}).ApplyRemoteMutations(ctx, walEntries(t, src, "source")); err != nil {
		t.Fatal(err)
	}
	n := len(walEntries(t, src, "source"))
	if ok, err := src.BeginVMOperationAtSnapshot(ctx, op, `{"cpu":4}`, snap); !ok || err != nil {
		t.Fatal(ok, err)
	}
	entry := walEntries(t, src, "source")[n]
	if _, err := NewReplicator(dst, "", RelayConfig{}).ApplyRemoteMutations(ctx, []*pb.MutationEntry{entry}); err != nil {
		t.Fatal(err)
	}
	before := snapshotCASImage(t, dst)
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
	dst, err = NewLocalClient(dir, "receiver")
	if err != nil {
		t.Fatal(err)
	}
	// A distinct stream identity exercises revalidation instead of seen dedup.
	entry.Origin = "reopen-relay"
	snapshotClaimRefusedEntry(t, dst, entry)
	snapshotClaimTestGate(dst)
	snapshotClaimExpectDecision(t, dst, entry, snapshotClaimDuplicate)
	if seq, err := NewReplicator(dst, "", RelayConfig{}).ApplyRemoteMutations(ctx, []*pb.MutationEntry{entry}); err != nil || seq != entry.Seq {
		t.Fatal(seq, err)
	}
	if !reflect.DeepEqual(before, snapshotCASImage(t, dst)) {
		t.Fatal("reopened receiver rewrote provenance")
	}
}

func TestVMSnapshotClaimLocalProvenanceRefusals(t *testing.T) {
	for _, mutation := range []string{"generic_header", "generic_planned", "empty_facts", "malformed_facts",
		"tombstoned_header", "tombstoned_facts", "changed_claim", "changed_after", "changed_generation",
		"changed_owner", "conflicting_caller_owner", "wrong_project"} {
		t.Run(mutation, func(t *testing.T) {
			c, snap, op := snapshotCASFixture(t)
			ctx := context.Background()
			if mutation == "generic_header" || mutation == "generic_planned" {
				snapshotClaimSeedRole(t, c, operationInsertStatement(op, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", nil))
				if mutation == "generic_planned" {
					snapshotClaimSeedRole(t, c, operationStepInsertStatement(op.ID, 0, OpStepPlanned, "", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", nil))
				}
			} else if mutation != "conflicting_caller_owner" && mutation != "wrong_project" {
				if ok, err := c.BeginVMOperationAtSnapshot(ctx, op, `{"cpu":4}`, snap); !ok || err != nil {
					t.Fatal(ok, err)
				}
			}
			switch mutation {
			case "empty_facts":
				snapshotClaimExec(t, c, `UPDATE operation_steps SET facts = ''`)
			case "malformed_facts":
				snapshotClaimExec(t, c, `UPDATE operation_steps SET facts = '{}'`)
			case "tombstoned_header":
				snapshotClaimExec(t, c, `UPDATE operations SET deleted_at = ''`)
			case "tombstoned_facts":
				snapshotClaimExec(t, c, `UPDATE operation_steps SET deleted_at = ''`)
			case "changed_claim":
				snapshotClaimExec(t, c, `UPDATE operations SET desired_ref = 'changed'`)
			case "changed_after":
				snapshotClaimExec(t, c, `UPDATE vms SET spec = '{"cpu":8}'`)
			case "changed_generation":
				snapshotClaimExec(t, c, `UPDATE vms SET spec_generation = spec_generation + 1`)
			case "changed_owner":
				snapshotClaimExec(t, c, `UPDATE vms SET vm_owner_epoch = vm_owner_epoch + 1`)
			case "conflicting_caller_owner":
				op.VMOwnerEpoch = 1
			case "wrong_project":
				op.Project = "another-project"
			}
			before := snapshotCASImage(t, c)
			if ok, err := c.BeginVMOperationAtSnapshot(ctx, op, `{"cpu":4}`, snap); ok || err == nil {
				t.Fatal("invalid provenance accepted", ok, err)
			}
			if !reflect.DeepEqual(before, snapshotCASImage(t, c)) {
				t.Fatal("refusal modified provenance")
			}
		})
	}
}

func TestVMSnapshotClaimStampedRetryDoesNotRestamp(t *testing.T) {
	c, snap, op := snapshotCASFixture(t)
	c.SetSpecConflictGate(func() bool { return true })
	ctx := context.Background()
	if ok, err := c.BeginVMOperationAtSnapshot(ctx, op, `{"cpu":4}`, snap); !ok || err != nil {
		t.Fatal(ok, err)
	}
	before := snapshotCASImage(t, c)
	if ok, err := c.BeginVMOperationAtSnapshot(ctx, op, `{"cpu":4}`, snap); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if !reflect.DeepEqual(before, snapshotCASImage(t, c)) {
		t.Fatal("retry recomputed stamped spec/timestamps/WAL")
	}
}

func TestVMSnapshotClaimWholePushRollback(t *testing.T) {
	_, dst, entry, _, _ := snapshotClaimReplica(t, false)
	bad := snapshotClaimWireEntry(t, entry, snapshotClaimWire(t, entry))
	bad.Seq++
	bad.Origin = "invalid-second"
	stmts := snapshotClaimWire(t, bad)
	stmts[1].Params[2] = "conflicting-principal"
	bad = snapshotClaimWireEntry(t, bad, stmts)
	before := snapshotClaimAllRows(t, dst)
	seq, err := NewReplicator(dst, "", RelayConfig{}).ApplyRemoteMutations(context.Background(), []*pb.MutationEntry{entry, bad})
	if seq != 0 || err == nil {
		t.Fatal("failed second entry consumed push", seq, err)
	}
	if !reflect.DeepEqual(before, snapshotClaimAllRows(t, dst)) {
		t.Fatal("failed push committed first claim or seen state")
	}
}

func TestVMSnapshotClaimWALFailureRollsBack(t *testing.T) {
	c, snap, op := snapshotCASFixture(t)
	snapshotClaimExec(t, c, `CREATE TRIGGER snapshot_claim_log_fail AFTER INSERT ON mutation_log BEGIN SELECT RAISE(ABORT, 'injected WAL failure'); END`)
	before := snapshotCASImage(t, c)
	if ok, err := c.BeginVMOperationAtSnapshot(context.Background(), op, `{"cpu":4}`, snap); ok || err == nil {
		t.Fatal(ok, err)
	}
	if !reflect.DeepEqual(before, snapshotCASImage(t, c)) {
		t.Fatal("WAL failure committed claim")
	}
}
