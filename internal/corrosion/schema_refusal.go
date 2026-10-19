package corrosion

import (
	"log/slog"
	"regexp"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A peer whose database schema is behind this node's refuses every push from
// it (grpcapi PushMutations: "receiver is missing migrations"). Nothing it is
// sent lands until it is pre-staged or upgraded, so the replicator records the
// refusal for the health condition that names the peer and the fix.

// SchemaRefusalWindow is how long a recorded refusal stands without being seen
// again. A refused peer is re-pushed at least every 30 s (the push backoff
// ceiling), so a refusal older than this is from a peer no longer pushed to.
const SchemaRefusalWindow = 2 * time.Minute

// SchemaRefusal is a peer's last refusal of this node's pushes for its schema.
type SchemaRefusal struct {
	Since        time.Time // the first refusal of this run (reset by an accepted push)
	At           time.Time
	SenderSchema int // this node's effective DB schema, which the peer refused
	PeerSchema   int // the peer's own effective DB schema, as it reported it
}

// schemaPushState is one peer's last schema answer to a push: a refusal, or
// an accepted push and the schema it was made at.
type schemaPushState struct {
	refused        SchemaRefusal
	acceptedAt     time.Time
	acceptedSchema int
}

// schemaRefusalRe matches the receiver's refusal, which every release since
// the DB-applied handshake words the same way.
var schemaRefusalRe = regexp.MustCompile(`sender DB schema version (\d+), local (\d+) \(receiver is missing migrations`)

// parseSchemaRefusal reports whether err is a peer's schema refusal, and the
// two versions it names.
func parseSchemaRefusal(err error) (sender, peer int, ok bool) {
	st, isStatus := status.FromError(err)
	if !isStatus || st.Code() != codes.FailedPrecondition {
		return 0, 0, false
	}
	m := schemaRefusalRe.FindStringSubmatch(st.Message())
	if m == nil {
		return 0, 0, false
	}
	sender, _ = strconv.Atoi(m[1])
	peer, _ = strconv.Atoi(m[2])
	return sender, peer, true
}

// noteSchemaRefusal records peer refusing a push for its schema. It logs once
// per run of refusals, naming the fix.
func (r *Replicator) noteSchemaRefusal(peer string, sender, peerSchema int, at time.Time) {
	r.mu.Lock()
	if r.schemaPush == nil {
		r.schemaPush = map[string]*schemaPushState{}
	}
	st := r.schemaPush[peer]
	if st == nil {
		st = &schemaPushState{}
		r.schemaPush[peer] = st
	}
	first := st.refused.At.IsZero()
	since := st.refused.Since
	if first || at.Sub(st.refused.At) >= SchemaRefusalWindow {
		since = at
	}
	st.refused = SchemaRefusal{Since: since, At: at, SenderSchema: sender, PeerSchema: peerSchema}
	r.mu.Unlock()
	if first {
		slog.Error("replication: a peer refuses this node's pushes: its database schema is behind",
			"peer", peer, "peer_db_schema", peerSchema, "local_db_schema", sender,
			"fix", "lv host upgrade "+peer)
	}
}

// noteSchemaAccepted records peer accepting a push made at schema.
func (r *Replicator) noteSchemaAccepted(peer string, schema int, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.schemaPush == nil {
		r.schemaPush = map[string]*schemaPushState{}
	}
	st := r.schemaPush[peer]
	if st == nil {
		st = &schemaPushState{}
		r.schemaPush[peer] = st
	}
	if !st.refused.At.IsZero() {
		slog.Info("replication: a peer that refused this node's schema accepts its pushes again",
			"peer", peer, "local_db_schema", schema)
	}
	st.refused = SchemaRefusal{}
	st.acceptedAt, st.acceptedSchema = at, schema
}

// pruneSchemaPush drops the schema answers of peers that are not members.
// Called with r.mu held.
func (r *Replicator) pruneSchemaPush(members []PeerInfo) {
	if len(r.schemaPush) == 0 {
		return
	}
	in := make(map[string]bool, len(members))
	for _, m := range members {
		in[m.Name] = true
	}
	for peer := range r.schemaPush {
		if !in[peer] {
			delete(r.schemaPush, peer)
		}
	}
}

// SchemaRefusals lists the peers refusing this node's pushes for their
// schema, refused within SchemaRefusalWindow of now and not accepted since.
func (r *Replicator) SchemaRefusals(now time.Time) map[string]SchemaRefusal {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]SchemaRefusal{}
	for peer, st := range r.schemaPush {
		if !st.refused.At.IsZero() && now.Sub(st.refused.At) < SchemaRefusalWindow {
			out[peer] = st.refused
		}
	}
	return out
}

// SchemaAccepted reports the schema of peer's last accepted push, when that
// was within SchemaRefusalWindow of now and no refusal has come since.
func (r *Replicator) SchemaAccepted(peer string, now time.Time) (int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.schemaPush[peer]
	if st == nil || st.acceptedAt.IsZero() || !st.refused.At.IsZero() || now.Sub(st.acceptedAt) >= SchemaRefusalWindow {
		return 0, false
	}
	return st.acceptedSchema, true
}

// NoteSchemaRefusalForTest records peer refusing a push made at sender, as
// the replicator does on a refusal, at the given time. Test-only.
func (r *Replicator) NoteSchemaRefusalForTest(peer string, sender, peerSchema int, at time.Time) {
	r.noteSchemaRefusal(peer, sender, peerSchema, at)
}
