package corrosion

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// An open move's own pair shares one fw_id without a hold (spec §4 ruling on
// D2b review I-2): the target is the identity's one holder and member, the
// source is left out, and neither is listed in SharedFWID. Any other sharing
// is still held, and minting refuses while the move is open.

// moveCT stores a live container row with a move's columns.
func (f *tagGroupFixture) moveCT(host, name, fwID, state, detail, token string) {
	f.t.Helper()
	mustExec(f.t, f.c, `INSERT INTO containers (host_name, name, state, state_detail, relocate_token, create_spec, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 't', 't')`, host, name, state, detail, token,
		fmt.Sprintf(`{"template":"debian","fw_id":%q}`, fwID))
}

// relocationProof stores a container relocation proof.
func (f *tagGroupFixture) relocationProof(id, name, dest, coordinator, token, status string, reaped bool) {
	f.t.Helper()
	f.relocationProofAt(id, name, dest, coordinator, token, status, reaped, "2026-10-15T00:00:00Z")
}

// relocationProofAt is relocationProof minted at createdAt.
func (f *tagGroupFixture) relocationProofAt(id, name, dest, coordinator, token, status string, reaped bool, createdAt string) {
	f.t.Helper()
	del := any(nil)
	if reaped {
		del = createdAt
	}
	mustExec(f.t, f.c, `INSERT INTO runtime_action_proofs (id, action, target_kind, target_name, dest_host, coordinator,
		relocation_token, status, created_at, updated_at, deleted_at) VALUES (?, ?, 'container', ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, ActionRelocate, name, dest, coordinator, token, status, createdAt, createdAt, del)
}

func sharedNames(m *TagGroupMembership) []string {
	var out []string
	for _, w := range m.SharedFWID {
		out = append(out, w.Host+"/"+w.Name)
	}
	slices.Sort(out)
	return out
}

// Mutation: drop the exemption (movingSources returns nothing) — the moving
// pairs are held: red. Match on the name alone — the unbound pairs are not
// held: red.
func TestTagGroupMembers_AnOpenMovesPairIsNotHeld(t *testing.T) {
	f := newTagGroupFixture(t)
	f.group("web", FirewallTagGroupDef{Match: map[string]string{"role": "web"}})
	for i := 1; i <= 6; i++ {
		f.tags(TagMemberCT, tgID(i), `{"tags":{"role":"web"}}`)
	}
	// A failover relocation: the source is marked onto node-2 under tok-r,
	// which the target was stamped with.
	f.moveCT("node-1", "reloc", tgID(1), "relocating", RelocateRestoreDetail("node-2", "tok-r"), "")
	f.moveCT("node-2", "reloc", tgID(1), "stopped", "", "tok-r")
	// A parked cold migrate: node-1 minted the proof bound to tok-m (reaped
	// since), and the target was stamped with it.
	f.moveCT("node-1", "mig", tgID(2), "stopped", "operator-stop", "")
	f.moveCT("node-2", "mig", tgID(2), "running", "", "tok-m")
	f.relocationProof("p-m", "mig", "node-2", "node-1", "tok-m", "completed", true)
	// Not a move: a proof minted by another host.
	f.moveCT("node-1", "forged", tgID(3), "stopped", "", "")
	f.moveCT("node-2", "forged", tgID(3), "running", "", "tok-f")
	f.relocationProof("p-f", "forged", "node-2", "node-3", "tok-f", "prepared", false)
	// Not a move: a marker naming another token.
	f.moveCT("node-1", "stale", tgID(4), "relocating", RelocateRestoreDetail("node-2", "tok-old"), "")
	f.moveCT("node-2", "stale", tgID(4), "running", "", "tok-new")
	// Same name, same id, no record at all.
	f.moveCT("node-1", "named", tgID(5), "running", "", "")
	f.moveCT("node-2", "named", tgID(5), "running", "", "")
	// A move's pair plus a third live holder: still held, all three.
	f.moveCT("node-1", "three", tgID(6), "relocating", RelocateRestoreDetail("node-2", "tok-3"), "")
	f.moveCT("node-2", "three", tgID(6), "stopped", "", "tok-3")
	f.moveCT("node-3", "three", tgID(6), "running", "", "")

	m := f.members()
	want := []string{
		"node-1/forged", "node-1/named", "node-1/stale", "node-1/three",
		"node-2/forged", "node-2/named", "node-2/stale", "node-2/three", "node-3/three",
	}
	if got := sharedNames(m); !slices.Equal(got, want) {
		t.Fatalf("held at drop: %v, want %v", got, want)
	}
	if got := m.viewFor(t, "web").memberNames(); !slices.Equal(got, []string{"ct:node-2:mig", "ct:node-2:reloc"}) {
		t.Fatalf("members %v, want each move's target", got)
	}
}

// Minting refuses while the container moves, naming the move, on either row
// of the pair and on a source marked relocating before its target landed.
// Without a move the copied-identity rule still re-mints.
//
// Mutation: skip containerMoveOpen in the mint — red.
func TestMintFirewallID_RefusesWhileTheContainerMoves(t *testing.T) {
	f := newTagGroupFixture(t)
	ctx := context.Background()
	f.c.SetRepointReady(func(context.Context) bool { return true })
	f.moveCT("node-1", "mig", tgID(1), "stopped", "operator-stop", "")
	f.moveCT("node-2", "mig", tgID(1), "running", "", "tok-m")
	f.relocationProof("p-m", "mig", "node-2", "node-1", "tok-m", "in_progress", false)
	f.moveCT("node-1", "early", tgID(2), "relocating", RelocateRestoreDetail("node-3", "tok-e"), "")
	for _, tc := range []struct{ host, name, move string }{
		{"node-1", "mig", "migration of container mig from node-1 to node-2"},
		{"node-2", "mig", "migration of container mig from node-1 to node-2"},
		{"node-1", "early", "relocation of container early from node-1 to node-3"},
	} {
		_, _, err := MintFirewallID(ctx, f.c, mintGrant(t), TagMemberCT, tc.host, tc.name)
		if !errors.Is(err, ErrFirewallIDMoveOpen) || !strings.Contains(err.Error(), tc.move) || !strings.Contains(err.Error(), "retry after it completes") {
			t.Fatalf("mint %s on %s: %v, want refused naming %q", tc.name, tc.host, err, tc.move)
		}
	}
	if got := firewallIDOf(TagMemberCT, storedCreateSpec(t, f.c, "node-2", "mig")); got != tgID(1) {
		t.Fatalf("a refused mint changed the target's identity to %q", got)
	}
	// No move record: the shared id is a copy and is re-minted, as before.
	f.moveCT("node-1", "copy", tgID(3), "running", "", "")
	f.moveCT("node-2", "copy", tgID(3), "running", "", "")
	id, abandoned, err := MintFirewallID(ctx, f.c, mintGrant(t), TagMemberCT, "node-2", "copy")
	if err != nil || id == tgID(3) || abandoned != tgID(3) {
		t.Fatalf("mint over a copied id: (%q, %q, %v), want a fresh id abandoning %s", id, abandoned, err, tgID(3))
	}
}

// Re-review N-1, M-c, M-f: a pair's direction is decided by the strictly
// newest record binding it; on a tie, or when either direction rests on a
// marker while the other also matches, nothing is exempt and both rows are
// held (visible). Each binding of a proof is checked, and a running source is
// never exempt.
//
// Mutation: take the first direction that matches — "back" (target inserted
// first) loses its target: red. Exempt a running source — red.
func TestTagGroupMembers_APairsDirectionIsUnambiguous(t *testing.T) {
	f := newTagGroupFixture(t)
	f.group("web", FirewallTagGroupDef{Match: map[string]string{"role": "web"}})
	for i := 1; i <= 7; i++ {
		f.tags(TagMemberCT, tgID(i), `{"tags":{"role":"web"}}`)
	}
	// A -> B, later B -> A: the target (node-1) was inserted first; both
	// proofs are visible, the first reaped.
	f.moveCT("node-1", "back", tgID(1), "stopped", "", "tok-2")
	f.moveCT("node-2", "back", tgID(1), "stopped", "operator-stop", "tok-1")
	f.relocationProofAt("p1", "back", "node-2", "node-1", "tok-1", "completed", true, "2026-10-01T00:00:00Z")
	f.relocationProofAt("p2", "back", "node-1", "node-2", "tok-2", "completed", false, "2026-10-14T00:00:00Z")
	// A failover relocation A -> B coordinated by C, then a migrate B -> C.
	f.moveCT("node-3", "fo", tgID(2), "running", "", "tok-m")
	f.moveCT("node-2", "fo", tgID(2), "stopped", "operator-stop", "tok-r")
	f.relocationProofAt("pr", "fo", "node-2", "node-3", "tok-r", "completed", false, "2026-10-01T00:00:00Z")
	f.relocationProofAt("pm", "fo", "node-3", "node-2", "tok-m", "in_progress", false, "2026-10-14T00:00:00Z")
	// Both directions bound by proofs minted at the same moment: held.
	f.moveCT("node-1", "tie", tgID(3), "stopped", "", "tok-b")
	f.moveCT("node-2", "tie", tgID(3), "stopped", "", "tok-a")
	f.relocationProofAt("pa", "tie", "node-2", "node-1", "tok-a", "completed", false, "2026-10-14T00:00:00Z")
	f.relocationProofAt("pb", "tie", "node-1", "node-2", "tok-b", "completed", false, "2026-10-14T00:00:00Z")
	// A proof for another dest host, and one for another container: held.
	f.moveCT("node-1", "dest", tgID(4), "stopped", "", "")
	f.moveCT("node-2", "dest", tgID(4), "running", "", "tok-d")
	f.relocationProof("pd", "dest", "node-9", "node-1", "tok-d", "completed", false)
	f.moveCT("node-1", "other", tgID(5), "stopped", "", "")
	f.moveCT("node-2", "other", tgID(5), "running", "", "tok-o")
	f.relocationProof("po", "someone-else", "node-2", "node-1", "tok-o", "completed", false)
	// A parked source an operator started again: held.
	f.moveCT("node-1", "started", tgID(6), "running", "", "")
	f.moveCT("node-2", "started", tgID(6), "running", "", "tok-s")
	f.relocationProof("ps", "started", "node-2", "node-1", "tok-s", "completed", false)
	// The control: a plain parked migrate is still exempt.
	f.moveCT("node-1", "parked", tgID(7), "stopped", "operator-stop", "")
	f.moveCT("node-2", "parked", tgID(7), "running", "", "tok-p")
	f.relocationProof("pp", "parked", "node-2", "node-1", "tok-p", "completed", false)

	m := f.members()
	want := []string{
		"node-1/dest", "node-1/other", "node-1/started", "node-1/tie",
		"node-2/dest", "node-2/other", "node-2/started", "node-2/tie",
	}
	if got := sharedNames(m); !slices.Equal(got, want) {
		t.Fatalf("held at drop: %v, want %v", got, want)
	}
	if got := m.viewFor(t, "web").memberNames(); !slices.Equal(got, []string{"ct:node-1:back", "ct:node-2:parked", "ct:node-3:fo"}) {
		t.Fatalf("members %v, want each live target", got)
	}
}

// Re-review N-2: a holder of the same id that carries a move token whose
// proof has not replicated here (the target row arrived first) is not a copy
// to re-mint over: the mint refuses with a retry naming it, and the identity
// stays as it is.
//
// Mutation: drop the unexplained-token check — the mint re-mints and
// abandons the moving container's id: red.
func TestMintFirewallID_RefusesWhileAMovesRecordsAreInFlight(t *testing.T) {
	f := newTagGroupFixture(t)
	ctx := context.Background()
	f.c.SetRepointReady(func(context.Context) bool { return true })
	f.moveCT("node-1", "mig", tgID(1), "stopped", "operator-stop", "")
	f.moveCT("node-2", "mig", tgID(1), "running", "", "tok-unseen")
	for _, host := range []string{"node-1", "node-2"} {
		_, _, err := MintFirewallID(ctx, f.c, mintGrant(t), TagMemberCT, host, "mig")
		if !errors.Is(err, ErrFirewallIDMoveOpen) || !strings.Contains(err.Error(), "move records not yet replicated") {
			t.Fatalf("mint on %s with the proof not yet here: %v, want refused for records in flight", host, err)
		}
	}
	for _, host := range []string{"node-1", "node-2"} {
		if got := firewallIDOf(TagMemberCT, storedCreateSpec(t, f.c, host, "mig")); got != tgID(1) {
			t.Fatalf("a refused mint changed %s's identity to %q", host, got)
		}
	}
}

// Re-review M-a: a parked migrate does not complete by itself; the refusal
// says the source must be removed instead of "retry after it completes".
func TestMintFirewallID_AParkedPairNamesTheRemedy(t *testing.T) {
	f := newTagGroupFixture(t)
	f.c.SetRepointReady(func(context.Context) bool { return true })
	f.moveCT("node-1", "mig", tgID(1), "stopped", "operator-stop", "")
	f.moveCT("node-2", "mig", tgID(1), "running", "", "tok-m")
	f.relocationProof("p-m", "mig", "node-2", "node-1", "tok-m", "completed", false)
	_, _, err := MintFirewallID(context.Background(), f.c, mintGrant(t), TagMemberCT, "node-2", "mig")
	if !errors.Is(err, ErrFirewallIDMoveOpen) || !strings.Contains(err.Error(), "remove the source container mig on node-1") ||
		strings.Contains(err.Error(), "retry after it completes") {
		t.Fatalf("mint over a parked migrate: %v, want refused naming the source to remove", err)
	}
}

// Re-review 2 N2-I1: a failover relocation whose proof and target row have
// replicated here but whose coordinator's marker has not. The proof (its
// coordinator is C, neither holder) explains the target's token for no pair,
// so the source, live and unmarked, is no copy to re-mint over: the mint
// refuses on both rows, naming the stale copy as the remedy if no relocation
// is open, and both identities stay as they are.
//
// Mutation: let any visible proof explain a token — red.
func TestMintFirewallID_ACoordinatedRelocationInFlightIsRefused(t *testing.T) {
	f := newTagGroupFixture(t)
	ctx := context.Background()
	f.c.SetRepointReady(func(context.Context) bool { return true })
	f.moveCT("node-1", "rel", tgID(1), "running", "", "")
	f.moveCT("node-2", "rel", tgID(1), "stopped", "", "tok-r")
	f.relocationProof("p-r", "rel", "node-2", "node-3", "tok-r", ProofCompleted, false)
	for _, host := range []string{"node-1", "node-2"} {
		_, _, err := MintFirewallID(ctx, f.c, mintGrant(t), TagMemberCT, host, "rel")
		if !errors.Is(err, ErrFirewallIDMoveOpen) || !strings.Contains(err.Error(), "remove the stale container rel on node-1") {
			t.Fatalf("mint on %s mid-relocation: %v, want refused naming the stale copy on node-1", host, err)
		}
	}
	for _, host := range []string{"node-1", "node-2"} {
		if got := firewallIDOf(TagMemberCT, storedCreateSpec(t, f.c, host, "rel")); got != tgID(1) {
			t.Fatalf("a refused mint changed %s's identity to %q", host, got)
		}
	}
}

// Re-review 2 m-4: a token no proof will ever explain (a pre-gate
// relocation) beside a copy: the refusal names the real remedy, not a retry
// alone.
func TestMintFirewallID_AProoflessTokenNamesTheRemedy(t *testing.T) {
	f := newTagGroupFixture(t)
	f.c.SetRepointReady(func(context.Context) bool { return true })
	f.moveCT("node-1", "old", tgID(1), "running", "", "")
	f.moveCT("node-2", "old", tgID(1), "running", "", "tok-pregate")
	_, _, err := MintFirewallID(context.Background(), f.c, mintGrant(t), TagMemberCT, "node-2", "old")
	if !errors.Is(err, ErrFirewallIDMoveOpen) || !strings.Contains(err.Error(), "if no move is open, remove the stale container old on node-1") {
		t.Fatalf("mint beside a proofless token: %v, want the stale copy named", err)
	}
}

// Re-review 2 m-3 and m-5: a relocation marker wins over an older proof in
// the other direction (the container's earlier migrate), so the mint says
// "retry after it completes", not "remove a row"; and a failed proof is not
// a landed move.
func TestMintFirewallID_AMarkerBeatsAReverseProofAndAFailedProofIsNotLanded(t *testing.T) {
	f := newTagGroupFixture(t)
	ctx := context.Background()
	f.c.SetRepointReady(func(context.Context) bool { return true })
	// Earlier: migrated node-2 -> node-1 (A carries tok-old). Now: node-1
	// fails, and C relocates it back to node-2 under tok-new.
	f.moveCT("node-1", "fo", tgID(1), "relocating", RelocateRestoreDetail("node-2", "tok-new"), "tok-old")
	f.moveCT("node-2", "fo", tgID(1), "stopped", "", "tok-new")
	f.relocationProof("p-old", "fo", "node-1", "node-2", "tok-old", ProofCompleted, true)
	_, _, err := MintFirewallID(ctx, f.c, mintGrant(t), TagMemberCT, "node-2", "fo")
	if !errors.Is(err, ErrFirewallIDMoveOpen) || !strings.Contains(err.Error(), "relocation of container fo from node-1 to node-2") ||
		!strings.Contains(err.Error(), "retry after it completes") || strings.Contains(err.Error(), "remove") {
		t.Fatalf("mint mid-relocation over an older reverse proof: %v", err)
	}
	f.moveCT("node-1", "bad", tgID(2), "stopped", "operator-stop", "")
	f.moveCT("node-2", "bad", tgID(2), "running", "", "tok-f")
	f.relocationProof("p-f", "bad", "node-2", "node-1", "tok-f", ProofFailed, false)
	_, _, err = MintFirewallID(ctx, f.c, mintGrant(t), TagMemberCT, "node-2", "bad")
	if !errors.Is(err, ErrFirewallIDMoveOpen) || strings.Contains(err.Error(), "landed") {
		t.Fatalf("mint over a failed move: %v, want refused without calling it landed", err)
	}
}

// Re-review 2 m-1 and m-2: the members query.
//   - Two wall-clock proofs within the replication skew limit do not say
//     which is newer: held.
//   - A running row is never the side left out: after there-and-back with
//     the source started again, both are held, and so are a pair that both
//     run.
//   - A marker beats an older reverse proof (m-3): its target is the member.
//
// Mutation: drop the skew window — "skew" is resolved: red. Leave out a
// running row — "restarted" is resolved: red.
func TestTagGroupMembers_SkewAndRunningRowsAreHeld(t *testing.T) {
	f := newTagGroupFixture(t)
	f.group("web", FirewallTagGroupDef{Match: map[string]string{"role": "web"}})
	for i := 1; i <= 4; i++ {
		f.tags(TagMemberCT, tgID(i), `{"tags":{"role":"web"}}`)
	}
	f.moveCT("node-1", "skew", tgID(1), "stopped", "", "tok-2")
	f.moveCT("node-2", "skew", tgID(1), "stopped", "operator-stop", "tok-1")
	f.relocationProofAt("s1", "skew", "node-2", "node-1", "tok-1", ProofCompleted, true, "2026-10-15T10:00:00Z")
	f.relocationProofAt("s2", "skew", "node-1", "node-2", "tok-2", ProofCompleted, false, "2026-10-15T10:01:00Z")
	// There and back, the parked source on node-2 started again; the
	// target on node-1 is stopped.
	f.moveCT("node-1", "restarted", tgID(2), "stopped", "", "tok-b")
	f.moveCT("node-2", "restarted", tgID(2), "running", "", "tok-a")
	f.relocationProofAt("ra", "restarted", "node-2", "node-1", "tok-a", ProofCompleted, true, "2026-10-01T00:00:00Z")
	f.relocationProofAt("rb", "restarted", "node-1", "node-2", "tok-b", ProofCompleted, false, "2026-10-14T00:00:00Z")
	// Both run.
	f.moveCT("node-1", "both", tgID(3), "running", "", "")
	f.moveCT("node-2", "both", tgID(3), "running", "", "tok-x")
	f.relocationProof("px", "both", "node-2", "node-1", "tok-x", ProofCompleted, false)
	// A relocation marker over an older reverse proof.
	f.moveCT("node-1", "fo", tgID(4), "relocating", RelocateRestoreDetail("node-2", "tok-new"), "tok-old")
	f.moveCT("node-2", "fo", tgID(4), "stopped", "", "tok-new")
	f.relocationProofAt("p-old", "fo", "node-1", "node-2", "tok-old", ProofCompleted, true, "2026-10-01T00:00:00Z")

	m := f.members()
	want := []string{"node-1/both", "node-1/restarted", "node-1/skew", "node-2/both", "node-2/restarted", "node-2/skew"}
	if got := sharedNames(m); !slices.Equal(got, want) {
		t.Fatalf("held at drop: %v, want %v", got, want)
	}
	if got := m.viewFor(t, "web").memberNames(); !slices.Equal(got, []string{"ct:node-2:fo"}) {
		t.Fatalf("members %v, want the relocation's target", got)
	}
}
