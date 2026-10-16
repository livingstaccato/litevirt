package corrosion

import (
	"context"
	"errors"
	"fmt"

	"github.com/litevirt/litevirt/internal/hlc"
)

// An open move of a container is the one case where two live rows may hold
// one firewall identity (spec §4, controller ruling on D2b review I-2): the
// target lands carrying the source's fw_id, and the source row is retired
// only afterwards — or, when a migrate parks its source, not until an
// operator removes it. The pair is recognised from the move's own records,
// never from the name alone:
//
//   - a failover relocation: the coordinator marked the source row
//     relocating onto the target's host under the token the target row was
//     stamped with (RelocateRestoreDetail);
//   - a cold migrate: the target row's relocate_token is bound to a
//     relocation proof the source host minted for this container and this
//     target (mintRelocationProof), the proof read whatever its status, so a
//     parked migrate stays recognised.
//
// For such a pair the members query admits the target as the identity's one
// holder and leaves the source out, and MintFirewallID refuses to mint.

// ErrFirewallIDMoveOpen refuses to mint a firewall identity while the
// container is moving; the caller retries once the move has completed.
var ErrFirewallIDMoveOpen = errors.New("the container is moving")

// containerMove is a container row's part in a move.
type containerMove struct {
	host, name           string
	state, detail, token string
}

// relocationProof is the part of a relocation proof that binds a move.
type relocationProof struct {
	targetName, destHost, coordinator string
	status, createdAt                 string
}

// readRelocationProofs reads the container relocation proofs bound to
// tokens, reaped (tombstoned) ones included, keyed by token.
//
// A reaped proof still identifies a parked migrate's pair: that is what keeps
// the parked target out of the hold. It identifies one only while its source
// row is live (matchMove reads it only for a live pair). Proof tombstones are
// never hard-deleted today (gc.go); a reclaim of them would turn every parked
// pair back into a held one, which fails closed, and should keep the proofs
// of pairs whose source row is still live.
func readRelocationProofs(ctx context.Context, c *Client, tokens map[string]bool) (map[string][]relocationProof, error) {
	out := map[string][]relocationProof{}
	if len(tokens) == 0 {
		return out, nil
	}
	rows, err := c.Query(ctx,
		`SELECT relocation_token, target_name, dest_host, coordinator, status, created_at FROM runtime_action_proofs
		  WHERE action = ? AND target_kind = 'container' AND relocation_token != ''`, ActionRelocate)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		tok := r.String("relocation_token")
		if !tokens[tok] {
			continue
		}
		out[tok] = append(out[tok], relocationProof{
			targetName: r.String("target_name"), destHost: r.String("dest_host"), coordinator: r.String("coordinator"),
			status: r.String("status"), createdAt: r.String("created_at"),
		})
	}
	return out, nil
}

// moveMatch is what binds one direction (src -> dst) of a pair: the
// coordinator's relocation marker, or the newest proof whose token dst
// carries and which names dst's container, dst's host and src's host.
type moveMatch struct {
	ok, marker bool
	createdAt  string // the newest binding proof's
	landed     bool   // that proof completed: the target landed
}

// matchMove reports what binds src -> dst, from the records alone.
func matchMove(src, dst containerMove, proofs map[string][]relocationProof) moveMatch {
	if src.name != dst.name || src.host == dst.host || dst.token == "" {
		return moveMatch{}
	}
	if target, token, ok := RelocateRestoreMarker(src.state, src.detail); ok && target == dst.host && token == dst.token {
		return moveMatch{ok: true, marker: true}
	}
	var m moveMatch
	for _, p := range proofs[dst.token] {
		if p.targetName != dst.name || p.destHost != dst.host || p.coordinator != src.host {
			continue
		}
		if !m.ok || lwwOrder(p.createdAt, m.createdAt) > 0 {
			// A failed proof is not a landed move.
			m = moveMatch{ok: true, createdAt: p.createdAt, landed: p.status == ProofCompleted}
		}
	}
	return m
}

// newerProof orders two proofs' created_at: 1 when a is newer, -1 when b is,
// and 0 when that is not known. Two HLC stamps are causally ordered. A
// wall-clock stamp (hlc_lww off) is two hosts' clocks: within the clock skew
// the cluster tolerates (hlc.MaxSkewMS), they do not say which came first.
func newerProof(a, b string) int {
	ord := lwwOrder(a, b)
	if ord == 0 || (hlc.IsHLC(a) && hlc.IsHLC(b)) {
		return ord
	}
	ia, aok := tsInstant(a)
	ib, bok := tsInstant(b)
	if !aok || !bok {
		return 0
	}
	if d := ia.Sub(ib); d <= skewCutoff && d >= -skewCutoff {
		return 0
	}
	return ord
}

// resolvePair decides which of a and b is an open move's source, from the
// records alone. A relocation marker is written only while its relocation
// is open, so it wins over a proof in the other direction (an earlier move
// of the same container); otherwise one direction binds, or both are bound
// by proofs and one is known to be newer. Anything else — two markers, or
// proofs whose order is not known — is no pair (ok false), and ambiguous
// reports that both directions bound.
func resolvePair(a, b containerMove, proofs map[string][]relocationProof) (src, dst containerMove, m moveMatch, ok, ambiguous bool) {
	ab, ba := matchMove(a, b, proofs), matchMove(b, a, proofs)
	switch {
	case ab.marker && !ba.marker:
		return a, b, ab, true, false
	case ba.marker && !ab.marker:
		return b, a, ba, true, false
	case ab.ok && !ba.ok:
		return a, b, ab, true, false
	case ba.ok && !ab.ok:
		return b, a, ba, true, false
	case ab.ok && ba.ok && !ab.marker && !ba.marker:
		switch newerProof(ab.createdAt, ba.createdAt) {
		case 1:
			return a, b, ab, true, false
		case -1:
			return b, a, ba, true, false
		}
	}
	return containerMove{}, containerMove{}, moveMatch{}, false, ab.ok && ba.ok
}

// describeMove says what the open move is and what ends it.
func describeMove(src, dst containerMove, m moveMatch) string {
	switch {
	case m.marker:
		return fmt.Sprintf("the relocation of container %s from %s to %s (token %s) is open; retry after it completes",
			src.name, src.host, dst.host, dst.token)
	case m.landed:
		return fmt.Sprintf("the migration of container %s from %s to %s (token %s) landed, but its source is still live "+
			"(a parked migrate, which does not complete by itself): remove the source container %s on %s, then retry",
			src.name, src.host, dst.host, dst.token, src.name, src.host)
	}
	return fmt.Sprintf("the migration of container %s from %s to %s (token %s) is open; retry after it completes",
		src.name, src.host, dst.host, dst.token)
}

// movingSources returns the source of every open move whose pair are the only
// two live holders of their identity.
func movingSources(ctx context.Context, c *Client, workloads []*tagWorkload, holders map[string]int) ([]*tagWorkload, error) {
	byID := map[string][]*tagWorkload{}
	tokens := map[string]bool{}
	for _, w := range workloads {
		if w.kind != TagMemberCT || w.fwID == "" || holders[w.kind+"/"+w.fwID] != 2 {
			continue
		}
		byID[w.fwID] = append(byID[w.fwID], w)
		if w.move.token != "" {
			tokens[w.move.token] = true
		}
	}
	if len(byID) == 0 {
		return nil, nil
	}
	proofs, err := readRelocationProofs(ctx, c, tokens)
	if err != nil {
		return nil, err
	}
	var out []*tagWorkload
	for _, pair := range byID {
		if len(pair) != 2 {
			continue
		}
		a, b := pair[0], pair[1]
		src, _, _, ok, _ := resolvePair(a.move, b.move, proofs)
		// A running row is never the side left out: an operator who
		// started a parked source, or a pair that both run, is held.
		if !ok || src.state == "running" {
			continue
		}
		if src == a.move {
			out = append(out, a)
		} else {
			out = append(out, b)
		}
	}
	return out, nil
}

// containerMoveOpen names why container (host, name) may not be given a
// firewall identity now, or "" when nothing stops it: its row is marked
// relocating; it and another live holder of its identity fwID are an open
// move's pair, or both directions bind and the records do not say which;
// or that holder is a same-name row on another host whose move token or
// marker no record visible here explains yet (the target row can arrive
// before the move's proof or marker). Only a holder with no move columns at
// all is a copy that the mint re-mints over.
func containerMoveOpen(ctx context.Context, c *Client, host, name, fwID string) (string, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, COALESCE(state, '') AS state, COALESCE(state_detail, '') AS state_detail,
		        COALESCE(relocate_token, '') AS relocate_token, COALESCE(create_spec, '') AS create_spec
		   FROM containers WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return "", err
	}
	var self containerMove
	var others []containerMove
	tokens := map[string]bool{}
	for _, r := range rows {
		m := containerMove{host: r.String("host_name"), name: name, state: r.String("state"),
			detail: r.String("state_detail"), token: r.String("relocate_token")}
		if m.host == host {
			self = m
		} else if fwID != "" && firewallIDOf(TagMemberCT, r.String("create_spec")) == fwID {
			others = append(others, m)
		} else {
			continue
		}
		if m.token != "" {
			tokens[m.token] = true
		}
	}
	if target, token, ok := RelocateRestoreMarker(self.state, self.detail); ok {
		return fmt.Sprintf("the relocation of container %s from %s to %s (token %s) is open; retry after it completes",
			name, host, target, token), nil
	}
	if len(others) == 0 {
		return "", nil
	}
	proofs, err := readRelocationProofs(ctx, c, tokens)
	if err != nil {
		return "", err
	}
	for _, o := range others {
		src, dst, m, ok, ambiguous := resolvePair(self, o, proofs)
		if ok {
			return describeMove(src, dst, m), nil
		}
		if ambiguous {
			return fmt.Sprintf("container %s on %s and on %s hold one firewall identity and their move records do not say "+
				"which is the source: remove the stale one, then retry", name, host, o.host), nil
		}
		if _, _, marked := RelocateRestoreMarker(o.state, o.detail); marked {
			return fmt.Sprintf("container %s on %s holds the same firewall identity and is relocating; its move records "+
				"are not yet replicated here: retry after it completes", name, o.host), nil
		}
		// No record binds the two, yet one carries a move token: a proof
		// whose coordinator is neither holder (a failover relocation, bound
		// only by its marker) or no proof at all explains nothing for this
		// pair. Its records may still be on their way; if no move is open,
		// the row without a token is a stale copy.
		if self.token != "" || o.token != "" {
			var stale string
			switch {
			case self.token == "":
				stale = "the stale container " + name + " on " + host
			case o.token == "":
				stale = "the stale container " + name + " on " + o.host
			default:
				stale = "the stale one of container " + name + " on " + host + " and on " + o.host
			}
			return fmt.Sprintf("container %s on %s and on %s hold one firewall identity, carry move tokens, and no move record "+
				"visible here binds them (move records not yet replicated?): retry; if no move is open, remove %s",
				name, host, o.host, stale), nil
		}
	}
	return "", nil
}
