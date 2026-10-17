package corrosion

import (
	"context"
	"testing"
	"time"
)

// Resolving two versions of one spec never drops or changes the workload's
// firewall identity (firewall_id.go). The one way a live VM's identity
// changes is MintFirewallID, a spec edit at the next generation, so a sibling
// made beside it from the same parent still holds the parent's identity —
// none, or the copied one the mint replaced. Whichever version wins, every
// replica keeps the mint's identity.

// mintOn mints vm1's identity on p.
func mintOn(t *testing.T, p *specPeer) string {
	t.Helper()
	id, err := mintID(context.Background(), p.c, mintGrant(t), TagMemberVM, "", "vm1")
	if err != nil {
		t.Fatalf("mint on %s: %v", p.name, err)
	}
	return id
}

// assertSpecAndIdentity checks every peer holds content want with identity id
// at generation 1.
func assertSpecAndIdentity(t *testing.T, peers []*specPeer, want, id string) {
	t.Helper()
	for _, p := range peers {
		got := vmSpecOn(t, p)
		if gotID := firewallIDOf(TagMemberVM, got.Spec); gotID != id {
			t.Errorf("%s holds identity %q in %s, want the minted %s", p.name, gotID, got.Spec, id)
		}
		if got.SpecGeneration != 1 {
			t.Errorf("%s holds %s at generation %d, want 1", p.name, got.Spec, got.SpecGeneration)
		}
		if w, err := keepFirewallID(TagMemberVM, want, id); err != nil || content(got.Spec) != content(w) {
			t.Errorf("%s holds %s, want the later edit's content %s with the minted identity", p.name, content(got.Spec), want)
		}
	}
}

// The owner mints vm1's identity; a cut-off replica edits vm1 later at the
// same generation, from the parent that had none. The later edit wins on
// every replica, and so does the identity.
//
// Red without the identity rule: a and c take b's spec verbatim, losing the
// identity tag groups bind to, and b keeps its own.
func TestSpecConflict_AMintedIdentitySurvivesALaterSiblingEdit(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b", "c", "d")
	a, b, c, d := peers[0], peers[1], peers[2], peers[3]
	seedEverywhere(t, peers)

	id := mintOn(t, a)
	time.Sleep(5 * time.Millisecond)
	setSpec(t, b, `{"cpu":4}`)
	ea, eb := a.news(t), b.news(t)

	applyWAL(t, a.r, eb)
	applyWAL(t, b.r, ea)
	applyWAL(t, c.r, ea)
	applyWAL(t, c.r, eb)
	applyWAL(t, d.r, eb)
	applyWAL(t, d.r, ea)
	assertSpecAndIdentity(t, peers, `{"cpu":4}`, id)
}

// The same by anti-entropy alone.
func TestSpecConflictAE_AMintedIdentitySurvivesALaterSiblingEdit(t *testing.T) {
	peers := newSpecPeers(t, true, "a", "b")
	a, b := peers[0], peers[1]
	seedEverywhere(t, peers)

	id := mintOn(t, a)
	time.Sleep(5 * time.Millisecond)
	setSpec(t, b, `{"cpu":4}`)

	mergeFrom(t, a, b)
	mergeFrom(t, b, a)
	assertSpecAndIdentity(t, peers, `{"cpu":4}`, id)
}

// vm1 holds an identity copied from vm2 (stored verbatim before the writers
// kept it). The owner mints vm1 a fresh one; a cut-off replica edits vm1
// later from the parent, keeping the copy. Every replica keeps the mint's
// identity: going back to the copy would leave vm1 sharing vm2's, whose tags
// the mint's caller has cleared.
//
// Red with "the winner keeps its own identity": the later edit carries the
// copy.
func TestSpecConflict_AMintOverACopiedIdentitySurvivesALaterSiblingEdit(t *testing.T) {
	for _, lane := range []string{"wal", "ae"} {
		t.Run(lane, func(t *testing.T) {
			peers := newSpecPeers(t, true, "a", "b", "c")
			a, b := peers[0], peers[1]
			copied := tgID(21)
			for _, p := range peers {
				for _, name := range []string{"vm1", "vm2"} {
					mustExec(t, p.c, `INSERT INTO vms (name, host_name, spec, state, created_at, updated_at)
						VALUES (?, 'n1', ?, 'running', 't', 't')`, name, `{"cpu":2,"firewall_id":"`+copied+`"}`)
				}
				p.news(t)
			}
			id, abandoned, err := MintFirewallID(context.Background(), a.c, mintGrant(t), TagMemberVM, "", "vm1")
			if err != nil || abandoned != copied || id == copied {
				t.Fatalf("premise: mint over the copy gave %q abandoning %q: %v", id, abandoned, err)
			}
			time.Sleep(5 * time.Millisecond)
			setSpec(t, b, `{"cpu":4}`)
			if got := firewallIDOf(TagMemberVM, vmSpecOn(t, b).Spec); got != copied {
				t.Fatalf("premise: b's edit holds %q, want the copy", got)
			}
			if lane == "wal" {
				c := peers[2]
				ea, eb := a.news(t), b.news(t)
				applyWAL(t, a.r, eb)
				applyWAL(t, b.r, ea)
				applyWAL(t, c.r, eb)
				applyWAL(t, c.r, ea)
				assertSpecAndIdentity(t, peers, `{"cpu":4}`, id)
				return
			}
			mergeFrom(t, a, b)
			mergeFrom(t, b, a)
			assertSpecAndIdentity(t, peers[:2], `{"cpu":4}`, id)
		})
	}
}

// siblingFirewallID: the identity the version kept from two siblings holds.
// vm2 holds the copy cp; x and y are held by no other VM.
func TestSiblingFirewallID(t *testing.T) {
	x, y, cp := tgID(1), tgID(2), tgID(3)
	c := testClient(t)
	mustExec(t, c, `INSERT INTO vms (name, host_name, spec, state, created_at, updated_at)
		VALUES ('vm2', 'n1', ?, 'running', 't', 't')`, `{"cpu":2,"firewall_id":"`+cp+`"}`)
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	with := func(spec, id string) string {
		s, err := keepFirewallID(TagMemberVM, spec, id)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	for _, tc := range []struct {
		name, kept, other, want string
	}{
		{"same identity", with(`{"cpu":4}`, x), with(`{"cpu":2}`, x), x},
		{"neither holds one", `{"cpu":4}`, `{"cpu":2}`, ""},
		{"kept has none: an edit never drops one", `{"cpu":4}`, with(`{"cpu":2}`, x), x},
		{"kept has none, the other the copy", `{"cpu":4}`, with(`{"cpu":2}`, cp), cp},
		{"other has none", with(`{"cpu":2}`, x), `{"cpu":4}`, x},
		{"kept holds the copy, the other a mint over it", with(`{"cpu":4}`, cp), with(`{"cpu":2}`, x), x},
		{"kept is the mint over the other's copy", with(`{"cpu":2}`, x), with(`{"cpu":4}`, cp), x},
		{"two unheld identities: the kept one's", with(`{"cpu":2}`, y), with(`{"cpu":2}`, x), y},
		{"two unheld identities, other way round", with(`{"cpu":2}`, x), with(`{"cpu":2}`, y), x},
	} {
		got, err := siblingFirewallID(context.Background(), tx, "vm1", tc.kept, tc.other)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q (%v), want %q", tc.name, got, err, tc.want)
		}
	}
}
