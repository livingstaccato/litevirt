package corrosion

import (
	"context"
	"errors"
	"fmt"
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
}

// readRelocationProofs reads the container relocation proofs bound to
// tokens, reaped (tombstoned) ones included, keyed by token.
func readRelocationProofs(ctx context.Context, c *Client, tokens map[string]bool) (map[string][]relocationProof, error) {
	out := map[string][]relocationProof{}
	if len(tokens) == 0 {
		return out, nil
	}
	rows, err := c.Query(ctx,
		`SELECT relocation_token, target_name, dest_host, coordinator FROM runtime_action_proofs
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
		})
	}
	return out, nil
}

// movePair reports whether src and dst are the source and target of one open
// move of the container, and names the move.
func movePair(src, dst containerMove, proofs map[string][]relocationProof) (string, bool) {
	if src.name != dst.name || src.host == dst.host || dst.token == "" {
		return "", false
	}
	if target, token, ok := RelocateRestoreMarker(src.state, src.detail); ok && target == dst.host && token == dst.token {
		return fmt.Sprintf("the relocation of container %s from %s to %s (token %s)", src.name, src.host, dst.host, dst.token), true
	}
	for _, p := range proofs[dst.token] {
		if p.targetName == dst.name && p.destHost == dst.host && p.coordinator == src.host {
			return fmt.Sprintf("the migration of container %s from %s to %s (token %s)", src.name, src.host, dst.host, dst.token), true
		}
	}
	return "", false
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
		if _, ok := movePair(a.move, b.move, proofs); ok {
			out = append(out, a)
		} else if _, ok := movePair(b.move, a.move, proofs); ok {
			out = append(out, b)
		}
	}
	return out, nil
}

// containerMoveOpen names the open move container (host, name) is part of,
// or "" when it is in none: its row is marked relocating, or it and another
// live row holding its identity fwID are an open move's pair.
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
		return fmt.Sprintf("the relocation of container %s from %s to %s (token %s)", name, host, target, token), nil
	}
	if len(others) == 0 {
		return "", nil
	}
	proofs, err := readRelocationProofs(ctx, c, tokens)
	if err != nil {
		return "", err
	}
	for _, o := range others {
		if why, ok := movePair(self, o, proofs); ok {
			return why, nil
		}
		if why, ok := movePair(o, self, proofs); ok {
			return why, nil
		}
	}
	return "", nil
}
