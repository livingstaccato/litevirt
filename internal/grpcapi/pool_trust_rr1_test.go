package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pooltrust"
)

// (re-review rr1 M2): a config nfs pool with no options in config mounts with the ROW's
// options (nfsPoolConfig), but config pools are judged on driver, source and
// target only: a forged rewrite of the row's options stays trusted and is
// what the mount uses.
func TestRR1Probe_ConfigNFSPoolForgedOptions(t *testing.T) {
	s := trustServer(t)
	tgt := filepath.Join(t.TempDir(), "nas")
	s.PoolTrust().SetConfig(map[string]pooltrust.Binding{"nas": pooltrust.BindingOf("nfs", "srv:/x", tgt, nil)})
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"nas": {Driver: "nfs", Source: "srv:/x", Target: tgt}})
	row := corrosion.StoragePoolRecord{HostName: s.hostName, Name: "nas", Driver: "nfs", Source: "srv:/x", Target: tgt,
		Options: map[string]string{"options": "vers=3,soft,nolock,async"}, State: "active"}
	if s.poolRowTrusted(row) && s.nfsPoolConfig(row).Options["options"] == "vers=3,soft,nolock,async" {
		t.Errorf("a forged options rewrite of a config nfs pool is trusted and mounted with: %q", s.nfsPoolConfig(row).Options["options"])
	}
}

// (re-review rr1 ACT): a non-peer caller (alice's bearer) who sends the actor metadata
// is audited as herself, not as the name she injected.
func TestRR1Probe_NonPeerCannotForgeTheAuditedOperator(t *testing.T) {
	s := trustServer(t)
	dir := filepath.Join(t.TempDir(), "x")
	forgeRow(t, s, "x", dir)
	ctx := metadata.NewIncomingContext(adminAs("alice"), metadata.Pairs(repairActorMDKey, "bob"))
	if _, err := s.TrustStoragePool(ctx, &pb.TrustStoragePoolRequest{Name: "x", Driver: "dir", Target: dir}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.db.Query(context.Background(), `SELECT username FROM audit_log WHERE action = 'storage.pool.trust'`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].String("username") != "alice" {
		var got []string
		for _, r := range rows {
			got = append(got, r.String("username"))
		}
		t.Fatalf("audited as %v, want alice", got)
	}
}

// (re-review rr1 PV): the preview needs storage.hostpath at the root; an operator with
// storage.pool.write cannot read the row through it, and a preview records
// and audits nothing.
func TestRR1Probe_PreviewAuthorityAndNoSideEffects(t *testing.T) {
	s := trustServer(t)
	dir := filepath.Join(t.TempDir(), "x")
	forgeRow(t, s, "x", dir)
	if _, err := s.TrustStoragePool(trustOperatorCtx("oscar"), &pb.TrustStoragePoolRequest{Name: "x", Preview: true}); err == nil {
		t.Fatal("an operator previewed a host path row")
	}
	resp, err := s.TrustStoragePool(adminAs("alice"), &pb.TrustStoragePoolRequest{Name: "x", Preview: true, Driver: "dir", Target: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.PoolTrust().Entry("x"); ok || resp.GetAlreadyTrusted() {
		t.Fatal("a preview (even one carrying a binding) recorded the pool")
	}
}
