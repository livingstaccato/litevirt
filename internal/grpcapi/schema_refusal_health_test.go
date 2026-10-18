package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func schemaBehindRow(t *testing.T, s *Server, peer string) (corrosion.HealthCondition, bool) {
	t.Helper()
	h, ok, err := corrosion.GetHealthCondition(context.Background(), s.db, replicationSchemaEvaluator, condPeerSchemaBehind, "host", peer)
	if err != nil {
		t.Fatal(err)
	}
	return h, ok
}

// writeResolved writes the row another sender left when it saw peer accept a
// push made at schema accepted.
func writeResolved(t *testing.T, s *Server, peer string, refused, accepted int, at time.Time) {
	t.Helper()
	ev, _ := json.Marshal(schemaBehindEvidence{
		PeerDBSchema: refused - 1, SenderDBSchema: refused, Fix: "lv host upgrade " + peer, AcceptedDBSchema: accepted,
	})
	ts := at.UTC().Format(time.RFC3339)
	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, corrosion.HealthCondition{
		Evaluator: replicationSchemaEvaluator, Code: condPeerSchemaBehind,
		SubjectKind: "host", SubjectID: peer, Severity: corrosion.SeverityWarning,
		Hosts: []string{peer}, Evidence: string(ev), Lifecycle: corrosion.ConditionResolved,
		FirstSeen: ts, LastSeen: ts, ConfirmedAt: ts, ResolvedAt: ts, Reporter: "sender-x",
	}); err != nil {
		t.Fatal(err)
	}
}

// m2, m-d: a refusal this sender saw BEFORE it saw another node's
// resolution is stale; re-raising it would flap the condition until this
// sender's next push. "Before" is judged on this node's own clock: the
// resolver's ResolvedAt is another host's wall clock, an hour off here either
// way. A refusal after this node saw the resolution, or of a schema the
// resolution did not cover, is news and raises.
func TestReplicationSchemaHealth_StaleRefusalDoesNotReRaiseWhateverTheSkew(t *testing.T) {
	ctx := context.Background()
	for _, skew := range []time.Duration{-time.Hour, time.Hour} {
		for _, tc := range []struct {
			name     string
			after    bool // refused after this node saw the resolution
			sender   int
			wantOpen bool
		}{
			{"refused before, schema covered", false, 68, false},
			{"refused after", true, 68, true},
			{"refused before, newer schema", false, 69, true},
		} {
			t.Run(fmt.Sprintf("resolver skew %v/%s", skew, tc.name), func(t *testing.T) {
				s := testServer(t)
				s.SetSchemaRefusalGraceForTest(0)
				s.replicator = corrosion.NewReplicator(s.db, "", corrosion.RelayConfig{})
				writeResolved(t, s, "node-2", 68, 68, time.Now().Add(skew))
				if !tc.after {
					s.replicator.NoteSchemaRefusalForTest("node-2", tc.sender, 67, time.Now().Add(-5*time.Second))
				}
				s.EvaluateReplicationSchemaHealth(ctx) // this node sees the resolution now
				if tc.after {
					s.replicator.NoteSchemaRefusalForTest("node-2", tc.sender, 67, time.Now().Add(time.Second))
					s.EvaluateReplicationSchemaHealth(ctx)
				}
				h, ok := schemaBehindRow(t, s, "node-2")
				if !ok {
					t.Fatal("the condition row is gone")
				}
				if open := h.Lifecycle != corrosion.ConditionResolved; open != tc.wantOpen {
					t.Fatalf("open=%v (lifecycle %s), want %v", open, h.Lifecycle, tc.wantOpen)
				}
			})
		}
	}
}

// m-e: during a pre-stage pass every host not yet staged briefly refuses the
// ones already staged. A refusal is raised only once its run outlasts the
// grace, so a normal subset upgrade does not flash a WARNING; one that lasts
// is raised.
func TestReplicationSchemaHealth_RaisedOnlyAfterTheGrace(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	s.replicator = corrosion.NewReplicator(s.db, "", corrosion.RelayConfig{})
	now := time.Now()
	s.replicator.NoteSchemaRefusalForTest("node-2", 68, 67, now.Add(-schemaRefusalGrace/2))
	s.replicator.NoteSchemaRefusalForTest("node-2", 68, 67, now)
	s.EvaluateReplicationSchemaHealth(ctx)
	if _, ok := schemaBehindRow(t, s, "node-2"); ok {
		t.Fatal("raised a refusal younger than the grace")
	}

	s.replicator.NoteSchemaRefusalForTest("node-3", 68, 67, now.Add(-schemaRefusalGrace-time.Second))
	s.replicator.NoteSchemaRefusalForTest("node-3", 68, 67, now)
	s.EvaluateReplicationSchemaHealth(ctx)
	if h, ok := schemaBehindRow(t, s, "node-3"); !ok || h.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("a refusal that outlasted the grace is not raised: ok=%v %+v", ok, h)
	}

	// The same holds on the refusing node itself.
	local := s.db.EffectiveDBSchema()
	s.schemaRefusedMu.Lock()
	s.schemaRefused = map[string]corrosion.SchemaRefusal{
		"node-0": {Since: now.Add(-time.Second), At: now, SenderSchema: local + 1, PeerSchema: local},
	}
	s.schemaRefusedMu.Unlock()
	s.EvaluateReplicationSchemaHealth(ctx)
	if _, ok := schemaBehindRow(t, s, s.hostName); ok {
		t.Fatal("the refusing node raised a refusal younger than the grace")
	}
	s.schemaRefusedMu.Lock()
	s.schemaRefused["node-0"] = corrosion.SchemaRefusal{
		Since: now.Add(-schemaRefusalGrace - time.Second), At: now, SenderSchema: local + 1, PeerSchema: local,
	}
	s.schemaRefusedMu.Unlock()
	s.EvaluateReplicationSchemaHealth(ctx)
	if h, ok := schemaBehindRow(t, s, s.hostName); !ok || h.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("the refusing node did not raise a refusal past the grace: ok=%v %+v", ok, h)
	}
}

// m2: senders agree on one row. A sender whose refusal says no more than the
// open row (another sender raised it at a newer schema) leaves it alone, so
// two senders at different schemas do not trade the row back and forth.
func TestReplicationSchemaHealth_OpenRowNotRewrittenByALesserRefusal(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	s.SetSchemaRefusalGraceForTest(0)
	s.replicator = corrosion.NewReplicator(s.db, "", corrosion.RelayConfig{})
	ev, _ := json.Marshal(schemaBehindEvidence{PeerDBSchema: 67, SenderDBSchema: 69, Fix: "lv host upgrade node-2"})
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := corrosion.UpsertHealthCondition(ctx, s.db, corrosion.HealthCondition{
		Evaluator: replicationSchemaEvaluator, Code: condPeerSchemaBehind,
		SubjectKind: "host", SubjectID: "node-2", Severity: corrosion.SeverityWarning,
		Hosts: []string{"node-2"}, Evidence: string(ev), Lifecycle: corrosion.ConditionConfirmed,
		ObserveCount: 1, FirstSeen: ts, LastSeen: ts, ConfirmedAt: ts, Reporter: "sender-y",
	}); err != nil {
		t.Fatal(err)
	}

	s.replicator.NoteSchemaRefusalForTest("node-2", 68, 67, time.Now())
	s.EvaluateReplicationSchemaHealth(ctx)
	h, _ := schemaBehindRow(t, s, "node-2")
	if h.Reporter != "sender-y" || h.Evidence != string(ev) {
		t.Fatalf("a refusal at 68 rewrote the row raised at 69: reporter %s, evidence %s", h.Reporter, h.Evidence)
	}

	// A refusal that says more (a newer schema) does rewrite it.
	s.replicator.NoteSchemaRefusalForTest("node-2", 70, 67, time.Now())
	s.EvaluateReplicationSchemaHealth(ctx)
	h, _ = schemaBehindRow(t, s, "node-2")
	var got schemaBehindEvidence
	_ = json.Unmarshal([]byte(h.Evidence), &got)
	if h.Reporter != s.hostName || got.SenderDBSchema != 70 {
		t.Fatalf("a refusal at 70 did not update the row raised at 69: reporter %s, evidence %s", h.Reporter, h.Evidence)
	}

	// The peer moved (pre-staged part-way): the row takes its new schema and
	// keeps the newest schema refused.
	s.replicator.NoteSchemaRefusalForTest("node-2", 69, 68, time.Now())
	s.EvaluateReplicationSchemaHealth(ctx)
	h, _ = schemaBehindRow(t, s, "node-2")
	got = schemaBehindEvidence{}
	_ = json.Unmarshal([]byte(h.Evidence), &got)
	if got.PeerDBSchema != 68 || got.SenderDBSchema != 70 {
		t.Fatalf("evidence %s, want the peer at 68 and the newest refused schema 70", h.Evidence)
	}
}

// m6: a node refusing pushes for its own schema raises the condition on
// itself, and resolves it on its own proof: its schema reaches the refused one.
func TestReplicationSchemaHealth_RefusingNodeReportsItself(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	s.SetSchemaRefusalGraceForTest(0)
	local := s.db.EffectiveDBSchema()
	s.noteSchemaRefusedPush("node-0", local+1, local)

	s.EvaluateReplicationSchemaHealth(ctx)
	h, ok := schemaBehindRow(t, s, s.hostName)
	if !ok || h.Lifecycle == corrosion.ConditionResolved || h.Reporter != s.hostName {
		t.Fatalf("refusing node did not report itself: ok=%v %+v", ok, h)
	}
	var ev schemaBehindEvidence
	_ = json.Unmarshal([]byte(h.Evidence), &ev)
	if ev.PeerDBSchema != local || ev.SenderDBSchema != local+1 || ev.Fix != "lv host upgrade "+s.hostName {
		t.Fatalf("evidence %s", h.Evidence)
	}

	s.db.SetEffectiveDBSchemaForTest(local + 1)
	s.EvaluateReplicationSchemaHealth(ctx)
	if h, _ := schemaBehindRow(t, s, s.hostName); h.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("not resolved once this node reached the refused schema: %+v", h)
	}
}
