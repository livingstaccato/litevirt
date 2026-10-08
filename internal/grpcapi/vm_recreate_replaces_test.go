package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A re-create forwarded here names the VM it replaces (vm_recreate_replaces.go).
// The multi-host behaviour — the tombstone arriving late, arriving never, a
// host on an older build — is pinned by the fleet scenarios
// (tests/fleet/rebuild_forward_race_test.go); these pin what a single process
// can reach: whose word is taken, and that only that one incarnation is.

// replacesMD is the incoming metadata a peer re-creating VM name, whose
// incarnation it deleted is createdAt, hands the host it forwards to.
func replacesMD(ctx context.Context, name, createdAt string) context.Context {
	b, _ := json.Marshal(replacedVMWire{Name: name, CreatedAt: createdAt})
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
	ctx := replacesMD(peerHostCtx(t, s, "host-a"), "vm1", old.CreatedAt)
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
	ctx := replacesMD(peerHostCtx(t, s, "host-a"), "vm1", "2001-01-01T00:00:00.000000001Z")
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
	if _, err := s.CreateVM(replacesMD(adminCtx(), "vm1", old.CreatedAt), disklessCreateRequest("vm1")); status.Code(err) != codes.AlreadyExists {
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
	ctx := replacesMD(peerHostCtx(t, s, "host-a"), "vm1", old.CreatedAt)
	if _, err := s.CreateVM(ctx, disklessCreateRequest("vm2")); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("a re-create of vm2 carrying vm1's marker: got %v, want AlreadyExists", err)
	}
	if rec := vmRecord(t, s, "vm2"); rec.CreatedAt != other.CreatedAt {
		t.Fatal("vm2 was replaced on vm1's marker")
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
