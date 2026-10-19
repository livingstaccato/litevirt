package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// defineSpyVirt is a libvirtfake that calls onDefine with each domain config
// before defining it.
type defineSpyVirt struct {
	*libvirtfake.Fake
	onDefine func(xml string)
}

func (d *defineSpyVirt) DefineDomain(xml string) error {
	if d.onDefine != nil {
		d.onDefine(xml)
	}
	return d.Fake.DefineDomain(xml)
}

// flightAtDefine is what spyDefineOf saw at the define of a domain: the uuid
// it carries, and whether a create in flight here held that uuid
// (liveCreateDefined), which keeps the orphan sweep off the domain being made.
type flightAtDefine struct {
	mu       sync.Mutex
	uuid     string
	inFlight bool
	defines  int
}

// spyDefineOf watches each define of name's domain on s.
func spyDefineOf(s *Server, fake *libvirtfake.Fake, name string) *flightAtDefine {
	got := &flightAtDefine{}
	s.virt = &defineSpyVirt{Fake: fake, onDefine: func(xml string) {
		if !strings.Contains(xml, "<name>"+name+"</name>") {
			return
		}
		u := domainUUIDFromXML(xml)
		in := s.liveCreateDefined(u, "")
		got.mu.Lock()
		defer got.mu.Unlock()
		got.uuid, got.inFlight = u, in
		got.defines++
	}}
	return got
}

func (f *flightAtDefine) check(t *testing.T, what string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.defines == 0 {
		t.Fatalf("%s defined no domain", what)
	}
	if f.uuid == "" || !f.inFlight {
		t.Errorf("%s defined its domain (uuid %q) while its create flight held no such uuid: the orphan sweep could take it for a leftover", what, f.uuid)
	}
}

// publishMoveOf records an unresolved move of vm's root disk here and opens
// its condition.
func publishMoveOf(t *testing.T, s *Server, vm string) {
	t.Helper()
	if err := health.RecordUnresolvedMove(s.dataDir, health.UnresolvedMove{VM: vm, Disk: "root", Src: "/a/x", Dst: "/b/x", Live: true}); err != nil {
		t.Fatal(err)
	}
	if err := health.PublishUnresolvedMoves(context.Background(), s.db, s.dataDir, s.hostName, vm); err != nil {
		t.Fatal(err)
	}
	if !health.MoveConditionCovers(context.Background(), s.db, vm, "root") {
		t.Fatal("control: no open condition")
	}
}

func assertMoveForgotten(t *testing.T, s *Server, vm string) {
	t.Helper()
	if ms := moveRecords(t, s, vm); len(ms) != 0 {
		t.Errorf("an earlier VM's move records were kept for the new %s: %+v", vm, ms)
	}
	if health.MoveConditionCovers(context.Background(), s.db, vm, "root") {
		t.Errorf("an earlier VM's move condition is still open on the new %s", vm)
	}
}

// A promotion to a new name makes a new VM of that name here: an earlier
// VM's unresolved-move records and condition for the name are dropped, and
// its domain is defined while the create flight holds its uuid.
//
// Mutations: drop the promotion's forgetMoveRecords — the records and the
// condition stay, red; pass setFlightUUID "" — the flight holds no uuid at
// the define, red.
func TestPromoteReplica_ToANewNameForgetsMoveRecordsAndHoldsItsUUIDInFlight(t *testing.T) {
	s, fake := promoteFixture(t)
	publishMoveOf(t, s, "vm1-promoted")
	got := spyDefineOf(s, fake, "vm1-promoted")
	if err := s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "vm1", NewName: "vm1-promoted", TargetPool: "replica-pool", NoLocalize: true,
	}, &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()}); err != nil {
		t.Fatalf("promote to vm1-promoted: %v", err)
	}
	got.check(t, "the promotion")
	assertMoveForgotten(t, s, "vm1-promoted")
}

// A restore to a name with auto-start makes a new VM of that name here: an
// earlier VM's unresolved-move records and condition for the name are
// dropped, and its domain is defined while the create flight holds its uuid.
//
// Mutations: drop autoDefineRestoredVM's forgetMoveRecords — the records and
// the condition stay, red; pass setFlightUUID "" — the flight holds no uuid at
// the define, red.
func TestRestoreLive_AutoStartForgetsMoveRecordsAndHoldsItsUUIDInFlight(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	fake := libvirtfake.New()
	publishMoveOf(t, s, "vm1")
	got := spyDefineOf(s, fake, "vm1")
	repoDir, ts := seedLiveRepo(t, make([]byte, pbsstore.ChunkSize), testSpecJSON(t, "vm1"))
	_, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
		TargetPath: filepath.Join(t.TempDir(), "live.qcow2"), AutoStart: true,
	}, pb.RestoreLiveProgress_STARTED)
	defer func() {
		cancel()
		<-done
	}()
	got.check(t, "the restore")
	assertMoveForgotten(t, s, "vm1")
}
