package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// definesOf counts the fake's define events of domain name.
func definesOf(fake *libvirtfake.Fake, name string) int {
	n := 0
	for _, e := range fake.EventLog() {
		if e.Domain == name && e.Op == "define" {
			n++
		}
	}
	return n
}

// promoteFixture is a VM vm1 on this host with a replica of its root disk in
// replica-pool, ready for a promotion.
func promoteFixture(t *testing.T) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s := testServer(t)
	s.dataDir = t.TempDir()
	fake := libvirtfake.New()
	s.virt = fake
	poolDir := t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"replica-pool": {Driver: "local", Target: poolDir}})
	specJSON, _ := json.Marshal(&pb.VMSpec{
		Name: "vm1", Cpu: 1, MemoryMib: 512, Uuid: "aaaaaaaa-0000-0000-0000-000000000001",
		Network: []*pb.NetworkAttachment{{Name: "lo", Model: "e1000"}},
	})
	if err := corrosion.InsertVM(adminCtx(), s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "running", Spec: string(specJSON)}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: "/nonexistent-source", SizeBytes: 1 << 20, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	seedReplica(t, poolDir, "", "vm1", "root", "20260101-000000", "raw", 1<<20)
	return s, fake
}

// Restore to a name, promote to a new name and cutover each make a VM of the
// name on this host, so each refuses while a create of the name is in flight
// here, and touches nothing (dupcreate re-review I-A).
//
// Mutations: remove the beginCreate of each path, one at a time — its row red.
func TestCreateFlight_RestorePromoteAndCutoverRefuseWhileACreateOfTheNameIsInFlight(t *testing.T) {
	t.Run("restore to a name", func(t *testing.T) {
		s := testServer(t)
		s.hostName = "host-a"
		s.dataDir = t.TempDir()
		fake := libvirtfake.New()
		s.virt = fake
		specJSON, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Cpu: 1, MemoryMib: 512})
		repoDir, ts := seedLiveRepo(t, make([]byte, pbsstore.ChunkSize), string(specJSON))
		end, _, err := s.beginCreate("vm1")
		if err != nil {
			t.Fatal(err)
		}
		defer end()
		_, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
			RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
			TargetPath: filepath.Join(t.TempDir(), "live.qcow2"), AutoStart: true,
		}, pb.RestoreLiveProgress_STARTED)
		defer cancel()
		// Refused, the RPC has returned; gone ahead, it reached STARTED and
		// holds its stream open until cancelled.
		select {
		case rerr := <-done:
			wantInProgress(t, "a restore to a name a create is making", rerr)
		default:
			t.Error("the restore defined and started vm1 while a create of the name was in flight")
			cancel()
			<-done
		}
		if n := definesOf(fake, "vm1"); n != 0 {
			t.Errorf("the refused restore defined vm1 %d times", n)
		}
		if row, _ := corrosion.GetVM(context.Background(), s.db, "vm1"); row != nil {
			t.Error("the refused restore wrote a row")
		}
	})
	t.Run("promote to a new name", func(t *testing.T) {
		s, fake := promoteFixture(t)
		end, _, err := s.beginCreate("vm1-promoted")
		if err != nil {
			t.Fatal(err)
		}
		defer end()
		perr := s.PromoteReplica(&pb.PromoteReplicaRequest{
			VmName: "vm1", NewName: "vm1-promoted", TargetPool: "replica-pool", NoLocalize: true,
		}, &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()})
		wantInProgress(t, "a promotion to a name a create is making", perr)
		if n := definesOf(fake, "vm1-promoted"); n != 0 {
			t.Errorf("the refused promotion defined vm1-promoted %d times", n)
		}
		if u, d := undefinesOf(fake, "vm1-promoted"); u != 0 || d != 0 {
			t.Errorf("the refused promotion undefined/destroyed %d/%d times", u, d)
		}
		if row, _ := corrosion.GetVM(adminCtx(), s.db, "vm1-promoted"); row != nil {
			t.Error("the refused promotion wrote a row")
		}
	})
	t.Run("cutover", func(t *testing.T) {
		s, fake, origDisk, nextDisk := cutoverFixture(t)
		before, _ := corrosion.GetVM(adminCtx(), s.db, "app")
		end, _, err := s.beginCreate("app")
		if err != nil {
			t.Fatal(err)
		}
		defer end()
		_, cerr := s.CutoverVM(adminCtx(), &pb.CutoverVMRequest{VmName: "app"})
		wantInProgress(t, "a cutover onto a name a create is making", cerr)
		for _, n := range []string{"app", "app-next"} {
			if u, d := undefinesOf(fake, n); u != 0 || d != 0 {
				t.Errorf("the refused cutover undefined/destroyed %s %d/%d times", n, u, d)
			}
			if !fake.DomainExists(n) {
				t.Errorf("the refused cutover left no domain %s", n)
			}
		}
		if row, _ := corrosion.GetVM(adminCtx(), s.db, "app"); row == nil || row.Spec != before.Spec {
			t.Error("the refused cutover changed the original's row")
		}
		if row, _ := corrosion.GetVM(adminCtx(), s.db, "app-next"); row == nil {
			t.Error("the refused cutover removed app-next's row")
		}
		for _, p := range []string{origDisk, nextDisk} {
			if _, err := os.Stat(p); err != nil {
				t.Errorf("the refused cutover removed %s: %v", p, err)
			}
		}
	})
}

// A promotion to a new name never replaces another VM, --force or not: with
// --force, a rename onto a live VM's name used to skip the row check, stop
// and undefine that VM's domain here, then fail on its row (dupcreate
// re-review, pre-existing).
//
// Mutation: check the row only without --force again — the other VM's domain
// is destroyed and undefined, red.
func TestPromoteReplica_ForceNeverRenamesOntoAnotherVM(t *testing.T) {
	s, fake := promoteFixture(t)
	const other, otherUUID = "other", "bbbbbbbb-0000-0000-0000-000000000002"
	otherSpec, _ := json.Marshal(&pb.VMSpec{Name: other, Cpu: 1, MemoryMib: 512, Uuid: otherUUID})
	if err := corrosion.InsertVM(adminCtx(), s.db,
		corrosion.VMRecord{Name: other, HostName: "test-host", State: "running", Spec: string(otherSpec)}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(fmt.Sprintf("<domain type='kvm'><name>%s</name><uuid>%s</uuid></domain>", other, otherUUID)); err != nil {
		t.Fatal(err)
	}
	if err := fake.StartDomain(other); err != nil {
		t.Fatal(err)
	}
	perr := s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "vm1", NewName: other, TargetPool: "replica-pool", NoLocalize: true, Force: true,
	}, &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()})
	if status.Code(perr) != codes.AlreadyExists {
		t.Errorf("promote --force --new-name onto a live VM: %v, want AlreadyExists", perr)
	}
	if u, d := undefinesOf(fake, other); u != 0 || d != 0 {
		t.Errorf("the other VM's domain was undefined %d and destroyed %d times", u, d)
	}
	if active, _ := fake.DomainIsActive(other); !active {
		t.Error("the other VM no longer runs")
	}
	if row, _ := corrosion.GetVM(adminCtx(), s.db, other); row == nil || row.Spec != string(otherSpec) {
		t.Error("the other VM's row was changed")
	}
}

// --force replaces only the promoted VM's own domain: a domain of the name
// with another uuid and no row is another guest (re-review, same class).
//
// Mutation: drop the uuid check before replaceDomain — red.
func TestPromoteReplica_ForceNeverStopsADomainOfAnotherUUID(t *testing.T) {
	s, fake := promoteFixture(t)
	const name, foreign = "vm1-new", "cccccccc-0000-0000-0000-000000000003"
	if err := fake.DefineDomain(fmt.Sprintf("<domain type='kvm'><name>%s</name><uuid>%s</uuid></domain>", name, foreign)); err != nil {
		t.Fatal(err)
	}
	if err := fake.StartDomain(name); err != nil {
		t.Fatal(err)
	}
	perr := s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "vm1", NewName: name, TargetPool: "replica-pool", NoLocalize: true, Force: true,
	}, &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()})
	if status.Code(perr) != codes.FailedPrecondition || !strings.Contains(perr.Error(), foreign) {
		t.Errorf("promote --force over a domain of another uuid: %v, want FailedPrecondition naming it", perr)
	}
	if u, d := undefinesOf(fake, name); u != 0 || d != 0 {
		t.Errorf("the foreign domain was undefined %d and destroyed %d times", u, d)
	}
}

// A rebuild stops and undefines only its own domain: a domain of the name
// with another uuid refuses it (dupcreate re-review m-A).
//
// Mutation: drop the uuid check — the foreign domain is destroyed, red.
func TestRebuildVM_NeverStopsADomainOfAnotherUUID(t *testing.T) {
	stageGenisoimage(t)
	s, fake, _ := isoServer(t)
	const name, foreign = "rb3", "dddddddd-0000-0000-0000-000000000004"
	if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, "")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	stopVM(t, s, name)
	// Another guest of the name takes the domain.
	if err := fake.DestroyDomain(name); err != nil {
		t.Fatal(err)
	}
	if err := fake.UndefineDomain(name, false); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(fmt.Sprintf("<domain type='kvm'><name>%s</name><uuid>%s</uuid></domain>", name, foreign)); err != nil {
		t.Fatal(err)
	}
	if err := fake.StartDomain(name); err != nil {
		t.Fatal(err)
	}
	baseU, baseD := undefinesOf(fake, name)
	_, err := s.RebuildVM(adminCtx(), &pb.RebuildVMRequest{Name: name})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), foreign) || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("rebuild over a domain of another uuid: %v, want FailedPrecondition naming it, nothing was changed", err)
	}
	if u, d := undefinesOf(fake, name); u != baseU || d != baseD {
		t.Errorf("the foreign domain was undefined/destroyed by the rebuild")
	}
	if active, _ := fake.DomainIsActive(name); !active {
		t.Error("the foreign guest no longer runs")
	}
}

// failingSecondActive is the fake with DomainIsActive failing from its
// second call on: the stop was sent, and whether it landed cannot be read.
type failingSecondActive struct {
	*libvirtfake.Fake
	calls int
}

func (f *failingSecondActive) DomainIsActive(name string) (bool, error) {
	f.calls++
	if f.calls > 1 {
		return false, errors.New("injected: libvirt connection lost")
	}
	return f.Fake.DomainIsActive(name)
}

// A stop that was sent but cannot be confirmed is not "nothing was changed"
// (dupcreate re-review m-B).
//
// Mutation: report it as could-not-be-stopped, nothing changed — red.
func TestRebuildVM_AStopThatCannotBeConfirmedSaysSo(t *testing.T) {
	stageGenisoimage(t)
	s, fake, _ := isoServer(t)
	const name = "rb4"
	if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, "")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	s.virt = &failingSecondActive{Fake: fake}
	_, err := s.RebuildVM(adminCtx(), &pb.RebuildVMRequest{Name: name})
	if err == nil || strings.Contains(err.Error(), "nothing was changed") || !strings.Contains(err.Error(), "was sent a stop") {
		t.Fatalf("rebuild whose stop cannot be confirmed: %v, want it to say the stop was sent", err)
	}
	if u, _ := undefinesOf(fake, name); u != 0 {
		t.Error("the rebuild went on to undefine the domain")
	}
	if row, _ := corrosion.GetVM(adminCtx(), s.db, name); row == nil {
		t.Error("the rebuild removed the VM's row")
	}
}

// The foreign domain's disk is matched by the file, not only by its spelling:
// a domain naming the disk through a symlinked directory still keeps a failed
// create from removing it (dupcreate review m-2).
//
// Mutation: match by spelling alone — the disk goes, red.
func TestCreateVM_AFailedCreateLeavesADiskAnotherDomainNamesThroughASymlink(t *testing.T) {
	stageGenisoimage(t)
	s, fake, _ := isoServer(t)
	const name = "ug9"
	disk := s.images.DiskPath(name, "root")
	link := filepath.Join(t.TempDir(), "disks-link")
	if err := os.MkdirAll(filepath.Dir(disk), 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(disk), link); err != nil {
		t.Fatal(err)
	}
	viaLink := filepath.Join(link, filepath.Base(disk))
	fake.FailDefineDomain = func(string) error {
		fake.FailDefineDomain = nil
		if err := fake.DefineDomain(fmt.Sprintf("<domain type='kvm'><name>%s</name><uuid>%s</uuid></domain>",
			name, "11111111-2222-3333-4444-999999999999")); err != nil {
			t.Fatal(err)
		}
		fake.SetDiskSource(name, "vda", viaLink)
		return errors.New("operation failed: domain '" + name + "' already exists")
	}
	if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, "")); err == nil {
		t.Fatal("the create was meant to fail at its define")
	}
	if _, err := os.Stat(disk); err != nil {
		t.Errorf("the failed create removed the disk another domain names through a symlink: %v", err)
	}
}
