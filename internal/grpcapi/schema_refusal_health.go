package grpcapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A peer refusing this node's pushes because its database schema is behind
// takes nothing this node writes until it is pre-staged or upgraded: a member
// a subset `lv host upgrade` left on the old schema, or one restored from an
// old backup. It is a warning on the peer, so `lv health` is not HEALTHY
// while it lasts.
const (
	replicationSchemaEvaluator = "replication_schema"
	condPeerSchemaBehind       = "replication_peer_schema_behind"
)

// schemaBehindEvidence is the condition's evidence: the two schemas the
// refusal named, and the command that fixes it.
type schemaBehindEvidence struct {
	PeerDBSchema   int    `json:"peer_db_schema"`
	SenderDBSchema int    `json:"sender_db_schema"`
	Fix            string `json:"fix"`
}

// EvaluateReplicationSchemaHealth keeps condPeerSchemaBehind: raised on each
// peer this node's replicator saw refuse a push for its schema within
// corrosion.SchemaRefusalWindow, and resolved once that peer accepts a push
// made at a schema at least the one it refused. Every pushing node writes the
// same row, so a node resolves only on its own proof that the peer took the
// refused schema, never because it has nothing to push. A removed peer's row
// is resolved by the gone-subject sweep. Written only on a change. The HA
// health monitor runs it each cycle.
func (s *Server) EvaluateReplicationSchemaHealth(ctx context.Context) {
	if s.replicator == nil {
		return
	}
	now := time.Now()
	ts := now.UTC().Format(time.RFC3339)
	refusing := s.replicator.SchemaRefusals(now)
	for peer, r := range refusing {
		prev, open, err := corrosion.GetHealthCondition(ctx, s.db, replicationSchemaEvaluator, condPeerSchemaBehind, "host", peer)
		if err != nil {
			continue
		}
		open = open && prev.Lifecycle != corrosion.ConditionResolved
		ev, _ := json.Marshal(schemaBehindEvidence{
			PeerDBSchema: r.PeerSchema, SenderDBSchema: r.SenderSchema, Fix: "lv host upgrade " + peer,
		})
		if open && prev.Evidence == string(ev) {
			continue
		}
		row := corrosion.HealthCondition{
			Evaluator: replicationSchemaEvaluator, Code: condPeerSchemaBehind,
			SubjectKind: "host", SubjectID: peer, Severity: corrosion.SeverityWarning,
			Hosts: []string{peer}, Evidence: string(ev),
			Lifecycle: corrosion.ConditionConfirmed, ObserveCount: 1,
			FirstSeen: prev.FirstSeen, LastSeen: ts, ConfirmedAt: prev.ConfirmedAt, Reporter: s.hostName,
		}
		if !open {
			row.FirstSeen, row.ConfirmedAt = ts, ts
		}
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Debug("replication schema condition: write failed", "peer", peer, "error", err)
		}
	}

	conds, deleted, err := corrosion.ListHealthConditionsByCode(ctx, s.db, replicationSchemaEvaluator, condPeerSchemaBehind)
	if err != nil {
		return
	}
	for i, h := range conds {
		if deleted[i] || h.Lifecycle == corrosion.ConditionResolved || h.SubjectKind != "host" {
			continue
		}
		if _, still := refusing[h.SubjectID]; still {
			continue
		}
		var ev schemaBehindEvidence
		_ = json.Unmarshal([]byte(h.Evidence), &ev)
		accepted, ok := s.replicator.SchemaAccepted(h.SubjectID, now)
		if !ok || accepted < ev.SenderDBSchema {
			continue
		}
		h.Lifecycle, h.ResolvedAt, h.LastSeen, h.Reporter = corrosion.ConditionResolved, ts, ts, s.hostName
		if err := corrosion.UpsertHealthCondition(ctx, s.db, h); err != nil {
			slog.Debug("replication schema condition: resolve failed", "peer", h.SubjectID, "error", err)
		}
	}
}
