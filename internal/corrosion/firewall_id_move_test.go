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
	del := any(nil)
	if reaped {
		del = "t"
	}
	mustExec(f.t, f.c, `INSERT INTO runtime_action_proofs (id, action, target_kind, target_name, dest_host, coordinator,
		relocation_token, status, created_at, updated_at, deleted_at) VALUES (?, ?, 'container', ?, ?, ?, ?, ?, 't', 't', ?)`,
		id, ActionRelocate, name, dest, coordinator, token, status, del)
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
