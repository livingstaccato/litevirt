package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// A re-create forwarded here names the VM it replaces (vm_recreate_replaces.go).
// The multi-host behaviour — the tombstone arriving late, arriving never, a
// host on an older build — is pinned by the fleet scenarios
// (tests/fleet/rebuild_forward_race_test.go); these pin what a single process
// can reach: whose word is taken, and that only that one incarnation is.

// replacesMD is the incoming metadata a peer re-creating VM name hands the
// host it forwards to: the row it deleted, as its delete guard saw it (the
// guard's host, owner epoch, spec generation and identity hash), with the
// incarnation set to createdAt.
func replacesMD(ctx context.Context, deleted *corrosion.VMRecord, createdAt string) context.Context {
	b, _ := json.Marshal(map[string]any{
		"name": deleted.Name, "created_at": createdAt,
		"host_name": deleted.HostName, "owner_epoch": deleted.OwnerEpoch,
		"spec_generation": deleted.SpecGeneration, "identity_hash": corrosion.VMIdentityHash(*deleted),
	})
	return metadata.NewIncomingContext(ctx, metadata.Pairs(replacedVMMD, string(b)))
}

// peerHostCtx is a peer host's call as the auth interceptor hands it on: a
// system continuation, which acts as an Admin.
func peerHostCtx(t *testing.T, s *Server, cn string) context.Context {
	t.Helper()
	ctx := context.WithValue(peerCtxFor(t, s, cn), ctxKeyUsername, "admin")
	return context.WithValue(ctx, ctxKeyRole, "admin")
}

// staleReplacedRow is this host's stale copy of VM name, which another host
// has deleted and is re-creating here: its row, still live in this replica,
// with no domain on this host.
func staleReplacedRow(t *testing.T, s *Server, name string) *corrosion.VMRecord {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: name, HostName: "host-a", State: "stopped",
		Spec: `{"name":"` + name + `","uuid":"0b9a3c1e-7d2f-4c55-9a1b-5e6f7a8b9c0d"}`,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	s.replacedTombstoneWait = 100 * time.Millisecond
	return vmRecord(t, s, name)
}

// The incarnation the peer deleted is retired here once the wait for its
// tombstone runs out, and the create goes ahead.
//
// Mutation: drop the retire in settleReplacedVM (return false after the
// wait) — AlreadyExists, red.
func TestReplacedVM_ThisHostsStaleCopyOfThatIncarnationIsRetired(t *testing.T) {
	s, _ := provableCreateServer(t)
	old := staleReplacedRow(t, s, "vm1")
	ctx := replacesMD(peerHostCtx(t, s, "host-a"), old, old.CreatedAt)
	if _, err := s.CreateVM(ctx, disklessCreateRequest("vm1")); err != nil {
		t.Fatalf("a peer's re-create of the incarnation it deleted, stale here: %v", err)
	}
	if rec := vmRecord(t, s, "vm1"); rec.CreatedAt == old.CreatedAt || rec.HostName != s.hostName {
		t.Fatalf("after the re-create: created_at %s (old %s), host %s; want a new incarnation on %s",
			rec.CreatedAt, old.CreatedAt, rec.HostName, s.hostName)
	}
}

// A live row of any other incarnation is a different VM: still refused, and
// left as it is.
//
// Mutation: match on the name alone in settleReplacedVM — red.
func TestReplacedVM_AnotherIncarnationIsStillRefused(t *testing.T) {
	s, _ := provableCreateServer(t)
	old := staleReplacedRow(t, s, "vm1")
	ctx := replacesMD(peerHostCtx(t, s, "host-a"), old, "2001-01-01T00:00:00.000000001Z")
	if _, err := s.CreateVM(ctx, disklessCreateRequest("vm1")); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("a re-create naming another incarnation than the live one: got %v, want AlreadyExists", err)
	}
	if rec := vmRecord(t, s, "vm1"); rec.CreatedAt != old.CreatedAt || rec.HostName != "host-a" {
		t.Fatalf("the live VM changed: created_at %s (was %s), host %s", rec.CreatedAt, old.CreatedAt, rec.HostName)
	}
}

// Only a peer host's word is taken. A user — an Admin included — who attaches
// the metadata by hand, naming the live incarnation exactly, is refused as
// before, and the VM is left alone.
//
// Mutation: drop the peer check in acceptReplacedVMMD — red.
func TestReplacedVM_OnlyAPeerHostNamesOne(t *testing.T) {
	s, _ := provableCreateServer(t)
	old := staleReplacedRow(t, s, "vm1")
	if _, err := s.CreateVM(replacesMD(adminCtx(), old, old.CreatedAt), disklessCreateRequest("vm1")); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("an Admin's create naming the live VM as replaced: got %v, want AlreadyExists", err)
	}
	if rec := vmRecord(t, s, "vm1"); rec.CreatedAt != old.CreatedAt {
		t.Fatalf("the live VM was replaced on an Admin's word: created_at %s, was %s", rec.CreatedAt, old.CreatedAt)
	}
}

// The replaced VM is for its own name only: a peer's marker for vm1 does not
// let it create over a live vm2.
func TestReplacedVM_IsForItsOwnNameOnly(t *testing.T) {
	s, _ := provableCreateServer(t)
	old := staleReplacedRow(t, s, "vm1")
	other := staleReplacedRow(t, s, "vm2")
	ctx := replacesMD(peerHostCtx(t, s, "host-a"), old, old.CreatedAt)
	if _, err := s.CreateVM(ctx, disklessCreateRequest("vm2")); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("a re-create of vm2 carrying vm1's marker: got %v, want AlreadyExists", err)
	}
	if rec := vmRecord(t, s, "vm2"); rec.CreatedAt != other.CreatedAt {
		t.Fatal("vm2 was replaced on vm1's marker")
	}
}

// The deleter's tombstone is guarded by its view of the row (host, owner
// epoch, spec generation, identity), and does not kill a row that has moved
// past that view — a failover that moved the VM here, say. The host does not
// retire such a row on the deleter's word either: refused, as on main, and
// the row is left as it is.
//
// Mutation: drop the snapshot check in settleReplacedVM — red.
func TestReplacedVM_ARowAheadOfTheDeletersViewIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		move func(t *testing.T, s *Server, snap *corrosion.VMRecord)
	}{
		{"moved here by a failover", func(t *testing.T, s *Server, _ *corrosion.VMRecord) {
			if err := corrosion.TransferVMOwnerFresh(context.Background(), s.db, "vm1", s.hostName, "running"); err != nil {
				t.Fatal(err)
			}
		}},
		{"on another host at the same epoch", func(t *testing.T, s *Server, snap *corrosion.VMRecord) {
			snap.HostName = "host-z"
		}},
		{"a newer spec generation", func(t *testing.T, s *Server, snap *corrosion.VMRecord) {
			snap.SpecGeneration--
		}},
		{"another identity at the same authority", func(t *testing.T, s *Server, snap *corrosion.VMRecord) {
			snap.Spec = `{"name":"vm1","uuid":"ffffffff-7d2f-4c55-9a1b-5e6f7a8b9c0d"}`
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := provableCreateServer(t)
			old := staleReplacedRow(t, s, "vm1")
			snap := *old
			tc.move(t, s, &snap)
			before := vmRecord(t, s, "vm1")
			ctx := replacesMD(peerHostCtx(t, s, "host-a"), &snap, old.CreatedAt)
			if _, err := s.CreateVM(ctx, disklessCreateRequest("vm1")); status.Code(err) != codes.AlreadyExists {
				t.Fatalf("a re-create whose deleter saw an older row: got %v, want AlreadyExists", err)
			}
			if rec := vmRecord(t, s, "vm1"); rec.CreatedAt != before.CreatedAt || rec.HostName != before.HostName ||
				rec.OwnerEpoch != before.OwnerEpoch {
				t.Fatalf("the row ahead of the deleter's view changed: %+v, was %+v", rec, before)
			}
		})
	}
}

// A host that has a domain of the name never settles it: in the case the
// marker exists for, the VM did not run here. Refused, domain untouched.
//
// Mutation: drop the domain check in settleReplacedVM — red.
func TestReplacedVM_ALocalDomainIsNeverSettled(t *testing.T) {
	s, fake := provableCreateServer(t)
	old := staleReplacedRow(t, s, "vm1")
	xml := `<domain><name>vm1</name><uuid>0b9a3c1e-7d2f-4c55-9a1b-5e6f7a8b9c0d</uuid></domain>`
	if err := fake.DefineDomain(xml); err != nil {
		t.Fatal(err)
	}
	ctx := replacesMD(peerHostCtx(t, s, "host-a"), old, old.CreatedAt)
	if _, err := s.CreateVM(ctx, disklessCreateRequest("vm1")); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("a re-create where this host has the VM's domain: got %v, want AlreadyExists", err)
	}
	if fake.DefinedXML("vm1") != xml {
		t.Fatalf("the local domain was replaced: %s", fake.DefinedXML("vm1"))
	}
	if rec := vmRecord(t, s, "vm1"); rec.CreatedAt != old.CreatedAt {
		t.Fatal("the row was retired")
	}
}

// Retiring the stale copy cleans up as DeleteVM's stale-record path does: the
// name's owner-epoch marker on this host goes with the row. Observed through a
// create that fails after the retire (a pin to a host that does not exist).
//
// Mutation: drop the marker removal from the retire — red.
func TestReplacedVM_TheRetireDropsTheOwnerEpochMarker(t *testing.T) {
	s, _ := provableCreateServer(t)
	old := staleReplacedRow(t, s, "vm1")
	if err := health.WriteVMOwnerEpochMarker(s.dataDir, "vm1", 7); err != nil {
		t.Fatal(err)
	}
	req := disklessCreateRequest("vm1")
	req.Spec.Placement = &pb.PlacementSpec{Host: "nowhere"}
	ctx := replacesMD(peerHostCtx(t, s, "host-a"), old, old.CreatedAt)
	if _, err := s.CreateVM(ctx, req); err == nil {
		t.Fatal("a create pinned to a host that does not exist succeeded")
	}
	if rec, _ := corrosion.GetVM(context.Background(), s.db, "vm1"); rec != nil {
		t.Fatalf("the stale row was not retired: %+v", rec)
	}
	if _, ok, _ := health.ReadVMOwnerEpochMarker(s.dataDir, "vm1"); ok {
		t.Fatal("the retired VM's owner-epoch marker is still on this host")
	}
}

// Kept specs never overwrite each other, however fast they come, and the
// directory is bounded: the newest recreateKeepMax files, none older than
// recreateKeepMaxAge.
//
// Mutation: second-resolution names without a unique part — red.
func TestKeepRecreateSpec_UniqueAndBounded(t *testing.T) {
	s, _ := provableCreateServer(t)
	dir := filepath.Join(s.dataDir, "recreate-failed")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, "ancient-rebuild.json")
	if err := os.WriteFile(stale, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	long := time.Now().Add(-31 * 24 * time.Hour)
	if err := os.Chtimes(stale, long, long); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		s.keepRecreateSpec("rebuild", "vm1", &pb.VMSpec{Name: "vm1", Cpu: int32(i + 1)})
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 3 {
		t.Fatalf("after three kept specs in one second and one 31 days old: %d files, want 3 (unique, aged out)", len(ents))
	}
	for i := 0; i < 60; i++ {
		s.keepRecreateSpec("rebuild", "vm1", &pb.VMSpec{Name: "vm1"})
	}
	if ents, _ = os.ReadDir(dir); len(ents) != 50 {
		t.Fatalf("after 63 kept specs: %d files, want the newest 50", len(ents))
	}
}

// A rebuild that fails after the teardown says so, and keeps the spec it was
// re-creating from where only root can read it.
func TestRecreateFailedAfterTeardown_NamesWhatIsGoneAndKeepsTheSpec(t *testing.T) {
	s, _ := provableCreateServer(t)
	cause := status.Error(codes.AlreadyExists, `VM "vm1" already exists`)
	err := s.recreateFailedAfterTeardown("rebuild", "vm1", "host-a", &pb.VMSpec{Name: "vm1", Cpu: 3}, cause)
	st := status.Convert(err)
	if st.Code() != codes.AlreadyExists {
		t.Fatalf("code = %v, want the create's own (AlreadyExists)", st.Code())
	}
	for _, want := range []string{"torn down on host-a", "already exists", "spec is kept on " + s.hostName} {
		if !strings.Contains(st.Message(), want) {
			t.Errorf("message %q does not say %q", st.Message(), want)
		}
	}
	path := st.Message()[strings.LastIndex(st.Message(), " at ")+len(" at "):]
	path = path[:strings.Index(path, "; re-create")]
	fi, serr := os.Stat(path)
	if serr != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("kept spec %s: %v, mode %v; want a 0600 file", path, serr, fi)
	}
	b, _ := os.ReadFile(path)
	kept := &pb.VMSpec{}
	if err := protojson.Unmarshal(b, kept); err != nil || kept.GetName() != "vm1" || kept.GetCpu() != 3 {
		t.Fatalf("kept spec %s = %s (%v); want the rebuild's", path, b, err)
	}
}
