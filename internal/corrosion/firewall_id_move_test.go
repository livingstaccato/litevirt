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

// claimProof records that executor claimed proof id at startedAt and, when
// completedAt is set, completed it then (ClaimActionProof and
// CompleteActionProof, both on the executor's clock).
func (f *tagGroupFixture) claimProof(id, executor, startedAt, completedAt string) {
	f.t.Helper()
	mustExec(f.t, f.c, `UPDATE runtime_action_proofs SET executor_host = ?, started_at = ?, completed_at = ? WHERE id = ?`,
		executor, startedAt, completedAt, id)
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
	f.claimProof("p1", "node-2", "2026-10-01T00:01:00Z", "2026-10-01T00:02:00Z")
	f.claimProof("p2", "node-1", "2026-10-14T00:01:00Z", "2026-10-14T00:02:00Z")
	// A failover relocation A -> B coordinated by C, then a migrate B -> C.
	f.moveCT("node-3", "fo", tgID(2), "running", "", "tok-m")
	f.moveCT("node-2", "fo", tgID(2), "stopped", "operator-stop", "tok-r")
	f.relocationProofAt("pr", "fo", "node-2", "node-3", "tok-r", "completed", false, "2026-10-01T00:00:00Z")
	f.relocationProofAt("pm", "fo", "node-3", "node-2", "tok-m", "in_progress", false, "2026-10-14T00:00:00Z")
	f.claimProof("pr", "node-2", "2026-10-01T00:01:00Z", "2026-10-01T00:02:00Z")
	f.claimProof("pm", "node-3", "2026-10-14T00:01:00Z", "")
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
		// D2b re-review 4 m4-1: the proof's coordinator is a third host, so
		// the relocation's marker may still be on its way: the refusal leads
		// with the retry, and names the copy only "if no move is open".
		if !errors.Is(err, ErrFirewallIDMoveOpen) ||
			!strings.Contains(err.Error(), "retry; if no move is open, remove the stale container rel on node-1") {
			t.Fatalf("mint on %s mid-relocation: %v, want refused leading with the retry, naming the stale copy on node-1", host, err)
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

// Re-review 2 m-1 and m-2, re-review 3 N3-I1: the members query.
//   - Two wall-clock proofs are ordered by same-host comparisons: the earlier
//     move's executor is the later move's coordinator, so its claim of the
//     earlier proof precedes its mint of the later one, and the mirror holds
//     on the other host. Cross-host skew does not enter. With that data
//     missing, contradictory, or from another host, the order is not known:
//     held.
//   - A running row is never the side left out: after there-and-back with
//     the source started again, both are held, and so are a pair that both
//     run.
//   - A marker beats an older reverse proof (m-3): its target is the member.
//
// Mutation: order by created_at alone (lwwOrder) — "skew" resolves to the
// wrong target and the rest resolve: red. Hold every wall-clock pair within
// the skew (round 3) — "skew" is held: red. Leave out a running row —
// "restarted" is resolved: red.
func TestTagGroupMembers_SkewAndRunningRowsAreHeld(t *testing.T) {
	f := newTagGroupFixture(t)
	f.group("web", FirewallTagGroupDef{Match: map[string]string{"role": "web"}})
	for i := 1; i <= 7; i++ {
		f.tags(TagMemberCT, tgID(i), `{"tags":{"role":"web"}}`)
	}
	// node-1 -> node-2, then node-2 -> node-1, on a cluster whose node-2
	// clock runs two minutes behind node-1's: by created_at alone the
	// second proof is older. Each host's own clock orders them: node-2
	// claimed s1 before it minted s2, and node-1 minted s1 before it
	// claimed s2. The target on node-1 is the member.
	twoWay := func(name string, fwID string) {
		f.moveCT("node-1", name, fwID, "stopped", "", name+"-2")
		f.moveCT("node-2", name, fwID, "stopped", "operator-stop", name+"-1")
		f.relocationProofAt(name+"-s1", name, "node-2", "node-1", name+"-1", ProofCompleted, true, "2026-10-15T10:01:00Z")
		f.relocationProofAt(name+"-s2", name, "node-1", "node-2", name+"-2", ProofCompleted, false, "2026-10-15T10:00:00Z")
	}
	twoWay("skew", tgID(1))
	f.claimProof("skew-s1", "node-2", "2026-10-15T09:59:30Z", "2026-10-15T09:59:40Z")
	f.claimProof("skew-s2", "node-1", "2026-10-15T10:02:00Z", "2026-10-15T10:02:10Z")
	// The same with no claim data: the order is not known, so held.
	twoWay("noclaim", tgID(5))
	// The same with node-2's clock saying s2 was minted before it claimed
	// s1 while node-1's says s1 came first: contradictory, so held.
	twoWay("contra", tgID(6))
	f.claimProof("contra-s1", "node-2", "2026-10-15T10:00:30Z", "")
	f.claimProof("contra-s2", "node-1", "2026-10-15T10:02:00Z", "")
	// Claims by a host that is not the other move's coordinator say
	// nothing about its clock: held.
	twoWay("foreign", tgID(7))
	f.claimProof("foreign-s1", "node-3", "2026-10-15T09:59:30Z", "")
	f.claimProof("foreign-s2", "node-3", "2026-10-15T10:02:00Z", "")
	// There and back, the parked source on node-2 started again; the
	// target on node-1 is stopped.
	f.moveCT("node-1", "restarted", tgID(2), "stopped", "", "tok-b")
	f.moveCT("node-2", "restarted", tgID(2), "running", "", "tok-a")
	f.relocationProofAt("ra", "restarted", "node-2", "node-1", "tok-a", ProofCompleted, true, "2026-10-01T00:00:00Z")
	f.relocationProofAt("rb", "restarted", "node-1", "node-2", "tok-b", ProofCompleted, false, "2026-10-14T00:00:00Z")
	f.claimProof("ra", "node-2", "2026-10-01T00:01:00Z", "2026-10-01T00:02:00Z")
	f.claimProof("rb", "node-1", "2026-10-14T00:01:00Z", "2026-10-14T00:02:00Z")
	// Both run.
	f.moveCT("node-1", "both", tgID(3), "running", "", "")
	f.moveCT("node-2", "both", tgID(3), "running", "", "tok-x")
	f.relocationProof("px", "both", "node-2", "node-1", "tok-x", ProofCompleted, false)
	// A relocation marker over an older reverse proof.
	f.moveCT("node-1", "fo", tgID(4), "relocating", RelocateRestoreDetail("node-2", "tok-new"), "tok-old")
	f.moveCT("node-2", "fo", tgID(4), "stopped", "", "tok-new")
	f.relocationProofAt("p-old", "fo", "node-1", "node-2", "tok-old", ProofCompleted, true, "2026-10-01T00:00:00Z")

	m := f.members()
	want := []string{"node-1/both", "node-1/contra", "node-1/foreign", "node-1/noclaim", "node-1/restarted",
		"node-2/both", "node-2/contra", "node-2/foreign", "node-2/noclaim", "node-2/restarted"}
	if got := sharedNames(m); !slices.Equal(got, want) {
		t.Fatalf("held at drop: %v, want %v", got, want)
	}
	if got := m.viewFor(t, "web").memberNames(); !slices.Equal(got, []string{"ct:node-1:skew", "ct:node-2:fo"}) {
		t.Fatalf("members %v, want the skewed migrate's target and the relocation's target", got)
	}
}

// Re-review 3 m3-1: the holder carries a token from an old migrate, which
// completed, beside a copy. The migrate was coordinated by one of the two
// holders (its source) and sent the container to a third host, so it binds
// neither row to the other and no record will ever arrive to: the refusal
// leads with the stale copy's remedy, not a retry for records in flight.
// (A proof a third host coordinated is a relocation and never settled:
// TestMintFirewallID_ACoordinatedRelocationInFlightIsRefused, m4-1.)
//
// Mutations: drop the settled-records branch — the refusal leads with
// "move records not yet replicated": red. Count a third host's proof as
// settled — the relocation test is red.
func TestMintFirewallID_ASettledTokenBesideACopyLeadsWithTheRemedy(t *testing.T) {
	f := newTagGroupFixture(t)
	f.c.SetRepointReady(func(context.Context) bool { return true })
	f.moveCT("node-1", "old", tgID(1), "running", "", "")
	f.moveCT("node-2", "old", tgID(1), "running", "", "tok-x")
	f.relocationProof("p-x", "old", "node-3", "node-1", "tok-x", ProofCompleted, true)
	_, _, err := MintFirewallID(context.Background(), f.c, mintGrant(t), TagMemberCT, "node-2", "old")
	if !errors.Is(err, ErrFirewallIDMoveOpen) || !strings.Contains(err.Error(), "remove the stale container old on node-1, then retry") ||
		strings.Contains(err.Error(), "not yet replicated") {
		t.Fatalf("mint beside a copy with a settled token: %v, want the stale copy named first", err)
	}
}

// Re-review 3 m3-2: when both directions bind and their order is not known,
// the refusal names the row that does not own the container's leases.
//
// Mutation: do not read the leases — "remove the stale one" is all it says:
// red.
func TestMintFirewallID_AnAmbiguousPairNamesTheRowWithoutTheLeases(t *testing.T) {
	f := newTagGroupFixture(t)
	f.c.SetRepointReady(func(context.Context) bool { return true })
	for i, name := range []string{"amb", "nolease"} {
		f.moveCT("node-1", name, tgID(i+1), "stopped", "", name+"-2")
		f.moveCT("node-2", name, tgID(i+1), "stopped", "operator-stop", name+"-1")
		f.relocationProofAt(name+"-s1", name, "node-2", "node-1", name+"-1", ProofCompleted, true, "2026-10-15T10:00:00Z")
		f.relocationProofAt(name+"-s2", name, "node-1", "node-2", name+"-2", ProofCompleted, false, "2026-10-15T10:01:00Z")
	}
	f.lease("lan", "10.0.0.5", "02:00:00:00:00:05", TagMemberCT, "node-1", "amb")
	_, _, err := MintFirewallID(context.Background(), f.c, mintGrant(t), TagMemberCT, "node-1", "amb")
	if !errors.Is(err, ErrFirewallIDMoveOpen) || !strings.Contains(err.Error(), "remove the stale container amb on node-2") {
		t.Fatalf("mint over an ambiguous pair: %v, want the row without the leases named", err)
	}
	_, _, err = MintFirewallID(context.Background(), f.c, mintGrant(t), TagMemberCT, "node-1", "nolease")
	if !errors.Is(err, ErrFirewallIDMoveOpen) || !strings.Contains(err.Error(), "remove the stale one") {
		t.Fatalf("mint over an ambiguous pair with no leases: %v, want the generic remedy", err)
	}
}

// CopiedFirewallID names the identity a tag set's mint would replace as a
// copy, writing nothing, and refuses as the mint does, so a caller clearing
// that identity's tags first never clears an open move pair's (D3 review
// I-1): a copy (no move columns) is named; a unique id, or none, is not; a
// moving container, a busy row and a container with no create spec are
// refused.
//
// Mutations: drop the move check — the moving pair is named as a copy: red;
// name the id whoever holds it — the unique one is named: red.
func TestCopiedFirewallID(t *testing.T) {
	f := newTagGroupFixture(t)
	ctx := context.Background()
	f.moveCT("node-1", "copy", tgID(1), "running", "", "")
	f.moveCT("node-2", "copy", tgID(1), "running", "", "")
	f.moveCT("node-1", "mig", tgID(2), "stopped", "operator-stop", "")
	f.moveCT("node-2", "mig", tgID(2), "running", "", "tok-m")
	f.relocationProof("p-m", "mig", "node-2", "node-1", "tok-m", "in_progress", false)
	f.moveCT("node-1", "own", tgID(3), "running", "", "")
	if got, err := CopiedFirewallID(ctx, f.c, TagMemberCT, "node-2", "copy"); err != nil || got != tgID(1) {
		t.Errorf("a copy: (%q, %v), want %s", got, err, tgID(1))
	}
	if got, err := CopiedFirewallID(ctx, f.c, TagMemberCT, "node-1", "own"); err != nil || got != "" {
		t.Errorf("a unique id: (%q, %v), want none", got, err)
	}
	if got, err := CopiedFirewallID(ctx, f.c, TagMemberCT, "node-2", "mig"); !errors.Is(err, ErrFirewallIDMoveOpen) || got != "" {
		t.Errorf("an open move's target: (%q, %v), want ErrFirewallIDMoveOpen", got, err)
	}
	mustExec(t, f.c, `INSERT INTO containers (host_name, name, state, created_at, updated_at) VALUES ('node-1', 'old', 'running', 't', 't')`)
	if _, err := CopiedFirewallID(ctx, f.c, TagMemberCT, "node-1", "old"); !errors.Is(err, ErrFirewallIDNoCreateSpec) {
		t.Errorf("no create spec: %v", err)
	}
	mustExec(t, f.c, `UPDATE containers SET active_operation_id = 'op-1' WHERE host_name = 'node-1' AND name = 'copy'`)
	if _, err := CopiedFirewallID(ctx, f.c, TagMemberCT, "node-1", "copy"); !errors.Is(err, ErrFirewallIDNotMinted) {
		t.Errorf("a busy container: %v", err)
	}
	for _, n := range []string{"web", "twin", "solo", "bare"} {
		spec := fmt.Sprintf(`{"name":%q,"firewall_id":%q}`, n, tgID(4))
		if n == "solo" {
			spec = fmt.Sprintf(`{"name":"solo","firewall_id":%q}`, tgID(5))
		} else if n == "bare" {
			spec = `{"name":"bare"}`
		}
		mustExec(t, f.c, `INSERT INTO vms (name, host_name, state, spec, created_at, updated_at) VALUES (?, 'node-1', 'running', ?, 't', 't')`, n, spec)
	}
	for name, want := range map[string]string{"web": tgID(4), "solo": "", "bare": ""} {
		if got, err := CopiedFirewallID(ctx, f.c, TagMemberVM, "", name); err != nil || got != want {
			t.Errorf("VM %s: (%q, %v), want %q", name, got, err, want)
		}
	}
}
