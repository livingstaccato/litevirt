package grpcapi

import (
	"os"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
)

// A migration target that holds a seed of another VM of the name — one
// deleted while this host kept its seed — writes the seed again for the VM
// migrating in, and stamps it; a seed already stamped as that VM's is kept.
// A seed it wrote over was not created for the migration: a failed
// migration's cleanup leaves it.
//
// Mutations: reuse any existing seed in EnsureCloudInit — the first step is
// red (the deleted VM's seed is kept); record a written-over seed as created
// for the migration — the cleanup removes it.
func TestEnsureCloudInit_WritesAgainASeedOfAnotherVM(t *testing.T) {
	stageGenisoimage(t)
	s := testServer(t)
	s.dataDir = t.TempDir()
	insertTestVMWithSpec(t, adminCtx(), s.db, "sx", "elsewhere", "running", `{"name":"sx","uuid":"sx-2"}`)

	peer := diskPeerCtx(t, s)
	iso, _ := liveISO(t, s, "sx")
	if err := cloudinit.StampSeed(iso, "sx-1"); err != nil { // the deleted sx's
		t.Fatal(err)
	}
	if _, err := s.EnsureCloudInit(peer, &pb.EnsureCloudInitRequest{VmName: "sx"}); err != nil {
		t.Fatalf("EnsureCloudInit: %v", err)
	}
	if b, _ := os.ReadFile(iso); string(b) != "made" {
		t.Fatalf("the seed is %q, want it written again", b)
	}
	if owner, ok, _ := cloudinit.SeedOwner(iso); !ok || owner != "sx-2" {
		t.Fatalf("the seed is stamped %q (%v), want sx-2", owner, ok)
	}
	cleanupISO(t, s, "sx")
	assertISOKept(t, iso, []byte("made"), "it was written over, not created for the migration")

	// Now it is sx's own: kept as it is.
	if err := os.WriteFile(iso, []byte("sx-2's seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureCloudInit(peer, &pb.EnsureCloudInitRequest{VmName: "sx"}); err != nil {
		t.Fatalf("EnsureCloudInit: %v", err)
	}
	if b, _ := os.ReadFile(iso); string(b) != "sx-2's seed" {
		t.Fatalf("the VM's own seed was replaced: %q", b)
	}
}
