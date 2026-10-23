package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pitoverlay"
	"github.com/litevirt/litevirt/internal/pooltrust"
)

func trustOperatorCtx(user string) context.Context {
	return context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, user), ctxKeyRole, "operator")
}

func adminAs(user string) context.Context {
	return context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, user), ctxKeyRole, "admin")
}

// (review r0 I1) A preview answers the host's row — the values the operator
// is shown — and records nothing; it is shown only to who could confirm it.
// A confirmation carries the values shown: when the row changed between the
// preview and the confirmation (a forger flipping it), the host refuses and
// records nothing, so the ledger never holds what the operator did not see.
//
// Mutations: record on a preview — red; skip the binding comparison — the
// flipped row is recorded, red; drop the preview's hostpath check — the
// operator reads the row, red.
func TestPoolTrust_PreviewThenAFlippedRowIsRefused(t *testing.T) {
	s := trustServer(t)
	seen := filepath.Join(t.TempDir(), "data")
	forgeRow(t, s, "data", seen)
	if _, err := s.TrustStoragePool(trustOperatorCtx("oscar"), &pb.TrustStoragePoolRequest{Name: "data", Preview: true}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an operator's preview: %v, want PermissionDenied", err)
	}
	prev, err := s.TrustStoragePool(adminCtx(), &pb.TrustStoragePoolRequest{Name: "data", Preview: true})
	if err != nil {
		t.Fatal(err)
	}
	if prev.GetPool().GetTarget() != seen || prev.GetAlreadyTrusted() || !strings.Contains(prev.GetWhy(), "neither created nor confirmed") {
		t.Fatalf("preview = %+v, want the row at %s, untrusted with why", prev, seen)
	}
	if _, ok := s.PoolTrust().Entry("data"); ok {
		t.Fatal("a preview recorded the pool")
	}
	// The forger flips the row after the operator looked.
	forgeRow(t, s, "data", "/var/lib/polkit-1/localauthority/50-local.d")
	_, err = s.TrustStoragePool(adminCtx(), &pb.TrustStoragePoolRequest{
		Name: "data", Driver: prev.GetPool().GetDriver(), Source: prev.GetPool().GetSource(), Target: prev.GetPool().GetTarget(), MountOptions: prev.GetMountOptions(),
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("confirming what was shown after the row flipped: %v, want FailedPrecondition", err)
	}
	if _, ok := s.PoolTrust().Entry("data"); ok {
		t.Fatal("the flipped row was recorded")
	}
}

// (review r0 m1) The node a confirmation enters on authorizes the exact
// values it forwards, not only its own row: an operator without
// storage.hostpath cannot confirm a host path because the entry node's row
// names none.
//
// Mutation: authorize only the entry node's row — the operator's request
// reaches the comparison (FailedPrecondition), red.
func TestPoolTrust_TheForwardedValuesAreAuthorized(t *testing.T) {
	s := trustServer(t)
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "p", Driver: "local", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := s.TrustStoragePool(trustOperatorCtx("oscar"), &pb.TrustStoragePoolRequest{Name: "p", Driver: "dir", Target: filepath.Join(t.TempDir(), "x")})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an operator confirming a host path its entry row lacks: %v, want PermissionDenied", err)
	}
}

// (review r0 I4) Every confirmation is audited as the operator who made it,
// a refusal too.
//
// Mutations: audit with s.audit (the transport caller) — the forwarded case
// in the fleet test goes red; skip the audit of a refusal — red here.
func TestPoolTrust_RefusalsAreAuditedAsTheOperator(t *testing.T) {
	s := trustServer(t)
	dir := filepath.Join(t.TempDir(), "x")
	forgeRow(t, s, "x", dir)
	if _, err := s.TrustStoragePool(trustOperatorCtx("oscar"), &pb.TrustStoragePoolRequest{Name: "x", Driver: "dir", Target: dir}); err == nil {
		t.Fatal("an operator confirmed a host path")
	}
	if _, err := s.TrustStoragePool(adminAs("alice"), &pb.TrustStoragePoolRequest{Name: "x", Driver: "dir", Target: dir}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.db.Query(context.Background(), `SELECT username, result FROM audit_log WHERE action = 'storage.pool.trust' ORDER BY username`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rows {
		got = append(got, r.String("username")+" "+r.String("result"))
	}
	if len(rows) != 2 || rows[0].String("username") != "alice" || rows[0].String("result") != "ok" ||
		rows[1].String("username") != "oscar" || !strings.HasPrefix(rows[1].String("result"), "error: PermissionDenied") {
		t.Fatalf("trust audit = %v, want alice ok and oscar's refusal", got)
	}
}

// (review r0 m4) An unreadable ledger raises pool_row_untrusted naming the
// kept copy, with no untrusted row at all.
//
// Mutation: resolve the condition when no pool is untrusted, whatever the
// ledger — red.
func TestPoolTrust_ConditionNamesAnUnreadableLedger(t *testing.T) {
	s := newPoolTestServer(t)
	s.pkiDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(s.dataDir, pooltrust.LedgerFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	pt, err := pooltrust.Open(s.dataDir, s.pkiDir)
	if err == nil {
		t.Fatal("a corrupt ledger opened without an error")
	}
	s.SetPoolTrust(pt)
	s.JudgePoolTrust(context.Background())
	row, found, err := corrosion.GetHealthCondition(context.Background(), s.db, poolTrustEvaluator, condPoolRowUntrusted, "host", s.hostName)
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved || !strings.Contains(row.Evidence, pooltrust.LedgerFile+pooltrust.CorruptSuffix) {
		t.Fatalf("condition = %+v found=%t err=%v, want raised naming the kept ledger", row, found, err)
	}
}

// (review r0 m6) The upgrade preflight's overlay scan does not walk an
// untrusted row's target: a forged row naming / cannot hold every upgrade
// at the scan's bound.
//
// Mutation: walk every row — the forged directory's overlay is found, red.
func TestPoolTrust_PITScanSkipsAnUntrustedRow(t *testing.T) {
	s, dir := upgradeTestServer(t)
	s.dataDir = filepath.Join(dir, "data")
	pt, err := pooltrust.Open(s.dataDir, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.SetPoolTrust(pt)
	forged := filepath.Join(dir, "forged")
	if err := os.MkdirAll(forged, 0o755); err != nil {
		t.Fatal(err)
	}
	forgeRow(t, s, "forged", forged)
	overlay := filepath.Join(forged, ".vm-root.qcow2"+pitoverlay.Suffix)
	if err := os.WriteFile(overlay, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if files, _ := s.pitOverlayScan(context.Background()); slices.Contains(files, overlay) {
		t.Fatal("the upgrade preflight walked a forged row's directory")
	}
	if err := pt.Record("forged", pooltrust.Binding{Driver: "dir", Target: forged}, pooltrust.HowTrust); err != nil {
		t.Fatal(err)
	}
	if files, _ := s.pitOverlayScan(context.Background()); !slices.Contains(files, overlay) {
		t.Fatal("the positive control: a confirmed pool's overlay was not found")
	}
}

// (review r0 m6) The disk chain's shared directories (another host's disk
// row is admitted for a layer under one) are this host's trusted nfs pools
// only: a forged nfs row does not widen it.
//
// Mutation: list every row for c.shared — red.
func TestPoolTrust_DiskChainSharedListIgnoresAnUntrustedRow(t *testing.T) {
	s := trustServer(t)
	ctx := context.Background()
	target := filepath.Join(t.TempDir(), "forged-nfs")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "fn", Driver: "nfs", Source: "evil:/x", Target: target, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	c := s.newDiskChain(ctx, corrosion.DiskRecord{VMName: "v", DiskName: "root", HostName: s.hostName, Path: filepath.Join(s.dataDir, "disks", "v-root.qcow2")})
	if withinAny(resolvedOr(filepath.Join(target, "x.qcow2")), c.shared) {
		t.Fatalf("a forged nfs row's target is in the disk chain's shared list: %v", c.shared)
	}
	if err := s.PoolTrust().Record("fn", pooltrust.BindingOf("nfs", "evil:/x", target, nil), pooltrust.HowTrust); err != nil {
		t.Fatal(err)
	}
	c = s.newDiskChain(ctx, corrosion.DiskRecord{VMName: "v", DiskName: "root", HostName: s.hostName, Path: filepath.Join(s.dataDir, "disks", "v-root.qcow2")})
	if !withinAny(resolvedOr(filepath.Join(target, "x.qcow2")), c.shared) {
		t.Fatalf("the positive control: a confirmed nfs pool is not in the shared list: %v", c.shared)
	}
}
