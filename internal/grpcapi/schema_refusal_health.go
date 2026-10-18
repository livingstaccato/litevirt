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
	// AcceptedDBSchema is, on a resolved row, the schema the peer was seen
	// to take.
	AcceptedDBSchema int `json:"accepted_db_schema,omitempty"`
}

// noteSchemaRefusedPush records this node refusing sender's push, made at
// senderSchema, because its own schema (localSchema) is behind: the refusing
// node reports the condition on itself, so its own `lv health` says so too.
func (s *Server) noteSchemaRefusedPush(sender string, senderSchema, localSchema int) {
	s.schemaRefusedMu.Lock()
	defer s.schemaRefusedMu.Unlock()
	if s.schemaRefused == nil {
		s.schemaRefused = map[string]corrosion.SchemaRefusal{}
	}
	s.schemaRefused[sender] = corrosion.SchemaRefusal{At: time.Now(), SenderSchema: senderSchema, PeerSchema: localSchema}
}

// schemaRefusedSelf folds this node's refusals within the window whose
// schema it still lacks into one: the newest schema refused, the latest
// time, and this node's schema now. ok is false when there are none.
func (s *Server) schemaRefusedSelf(now time.Time) (corrosion.SchemaRefusal, bool) {
	local := s.db.EffectiveDBSchema()
	s.schemaRefusedMu.Lock()
	defer s.schemaRefusedMu.Unlock()
	var out corrosion.SchemaRefusal
	for sender, r := range s.schemaRefused {
		if now.Sub(r.At) >= corrosion.SchemaRefusalWindow || r.SenderSchema <= local {
			delete(s.schemaRefused, sender)
			continue
		}
		out.SenderSchema = max(out.SenderSchema, r.SenderSchema)
		if r.At.After(out.At) {
			out.At = r.At
		}
	}
	out.PeerSchema = local
	return out, out.SenderSchema > 0
}

// EvaluateReplicationSchemaHealth keeps condPeerSchemaBehind on each host
// refusing pushes for its schema: a peer this node's replicator saw refuse
// one within corrosion.SchemaRefusalWindow, and this node itself while it
// refuses a sender's. Every node involved writes the same row, so:
//
//   - an open row is rewritten only by a refusal that says more (a newer
//     schema refused, or the peer's schema changed), so senders at different
//     schemas do not trade it back and forth;
//   - a resolved row is re-raised only by a refusal newer than the
//     resolution, or of a schema it did not cover, so a sender whose last
//     refusal predates another node's proof does not flap it;
//   - it is resolved only on proof that the host takes the refused schema: a
//     push accepted at it, or for this node its own schema reaching it.
//     Having nothing to push does not resolve it.
//
// A removed peer's row is resolved by the gone-subject sweep. Written only on
// a change. The HA health monitor runs it each cycle.
func (s *Server) EvaluateReplicationSchemaHealth(ctx context.Context) {
	now := time.Now()
	ts := now.UTC().Format(time.RFC3339)
	refusing := map[string]corrosion.SchemaRefusal{}
	if s.replicator != nil {
		refusing = s.replicator.SchemaRefusals(now)
	}
	if r, ok := s.schemaRefusedSelf(now); ok {
		refusing[s.hostName] = r
	}
	for peer, r := range refusing {
		prev, exists, err := corrosion.GetHealthCondition(ctx, s.db, replicationSchemaEvaluator, condPeerSchemaBehind, "host", peer)
		if err != nil {
			continue
		}
		var pev schemaBehindEvidence
		if exists {
			_ = json.Unmarshal([]byte(prev.Evidence), &pev)
		}
		open := exists && prev.Lifecycle != corrosion.ConditionResolved
		if open && pev.PeerDBSchema == r.PeerSchema && pev.SenderDBSchema >= r.SenderSchema {
			continue
		}
		if exists && !open && resolutionCovers(prev, pev, r) {
			continue
		}
		ev := schemaBehindEvidence{PeerDBSchema: r.PeerSchema, SenderDBSchema: r.SenderSchema, Fix: "lv host upgrade " + peer}
		if open {
			ev.SenderDBSchema = max(ev.SenderDBSchema, pev.SenderDBSchema)
		}
		evb, _ := json.Marshal(ev)
		row := corrosion.HealthCondition{
			Evaluator: replicationSchemaEvaluator, Code: condPeerSchemaBehind,
			SubjectKind: "host", SubjectID: peer, Severity: corrosion.SeverityWarning,
			Hosts: []string{peer}, Evidence: string(evb),
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
		var accepted int
		var ok bool
		switch {
		case h.SubjectID == s.hostName:
			accepted, ok = s.db.EffectiveDBSchema(), true
		case s.replicator != nil:
			accepted, ok = s.replicator.SchemaAccepted(h.SubjectID, now)
		}
		if !ok || accepted < ev.SenderDBSchema {
			continue
		}
		ev.AcceptedDBSchema = accepted
		evb, _ := json.Marshal(ev)
		h.Evidence = string(evb)
		h.Lifecycle, h.ResolvedAt, h.LastSeen, h.Reporter = corrosion.ConditionResolved, ts, ts, s.hostName
		if err := corrosion.UpsertHealthCondition(ctx, s.db, h); err != nil {
			slog.Debug("replication schema condition: resolve failed", "peer", h.SubjectID, "error", err)
		}
	}
}

// resolutionCovers reports whether the resolved row prev already answers
// refusal r: it was resolved no earlier than r was seen (to the second its
// timestamp keeps), on proof that the host takes r's schema.
func resolutionCovers(prev corrosion.HealthCondition, pev schemaBehindEvidence, r corrosion.SchemaRefusal) bool {
	resolvedAt, err := time.Parse(time.RFC3339, prev.ResolvedAt)
	if err != nil {
		return false
	}
	return !r.At.Truncate(time.Second).After(resolvedAt) && pev.AcceptedDBSchema >= r.SenderSchema
}
