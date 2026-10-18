package grpcapi

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/vmimport"
)

// forceMACs makes the random draw return seq, in order, then fail the test.
func forceMACs(t *testing.T, seq ...string) {
	t.Helper()
	i := 0
	restore := SetMACDrawForTests(func() string {
		if i >= len(seq) {
			t.Fatalf("MAC drawn %d times; the forced sequence has %d", i+1, len(seq))
			return ""
		}
		m := seq[i]
		i++
		return m
	})
	t.Cleanup(restore)
}

func seedNICOf(t *testing.T, s *Server, vm, mac string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: vm, HostName: "peer", State: "running"},
		[]corrosion.InterfaceRecord{{VMName: vm, NetworkName: "lan", MAC: mac}}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestMACAllocator_RedrawsAMACTheClusterRecords(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	const taken, ctTaken, free = "52:54:00:00:00:01", "52:54:00:00:00:02", "52:54:00:00:00:03"
	seedNICOf(t, s, "other", taken)
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{HostName: "peer", Name: "ct1", State: "running"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertContainerInterface(ctx, s.db, corrosion.ContainerInterfaceRecord{
		HostName: "peer", CtName: "ct1", NetworkName: "lan", MAC: ctTaken}); err != nil {
		t.Fatal(err)
	}
	forceMACs(t, taken, strings.ToUpper(ctTaken), free)
	got, err := s.newMACAllocator().next(ctx)
	if err != nil || got != free {
		t.Fatalf("next = %q, %v; want %s (the first draw no NIC records)", got, err, free)
	}
}

func TestMACAllocator_NeverHandsOutOneMACTwice(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	const named, a, b = "52:54:00:00:01:01", "52:54:00:00:01:02", "52:54:00:00:01:03"
	forceMACs(t, named, a, a, b)
	al := s.newMACAllocator()
	al.reserve(strings.ToUpper(named)) // another NIC of the request names it
	if got, err := al.next(ctx); err != nil || got != a {
		t.Fatalf("first = %q, %v; want %s", got, err, a)
	}
	if got, err := al.next(ctx); err != nil || got != b {
		t.Fatalf("second = %q, %v; want %s", got, err, b)
	}
}

func TestMACAllocator_ExhaustedDrawsAreAnError(t *testing.T) {
	s := testServer(t)
	const taken = "52:54:00:00:02:01"
	seedNICOf(t, s, "other", taken)
	restore := SetMACDrawForTests(func() string { return taken })
	defer restore()
	got, err := s.newMACAllocator().next(context.Background())
	if status.Code(err) != codes.ResourceExhausted || got != "" {
		t.Fatalf("next = %q, %v; want ResourceExhausted and no MAC", got, err)
	}
}

func TestResolveContainerNICs_RefusesAMACAnotherNICRecords(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	const taken = "52:54:00:00:04:01"
	seedNICOf(t, s, "victim", taken)
	_, err := s.resolveContainerNICs(ctx, "", "ct1", []*pb.ContainerNetwork{{Bridge: "br-raw", Mac: strings.ToUpper(taken)}})
	if status.Code(err) != codes.AlreadyExists || !strings.Contains(err.Error(), "victim") {
		t.Fatalf("explicit duplicate MAC: got %v, want AlreadyExists naming victim", err)
	}
	_, err = s.resolveContainerNICs(ctx, "", "ct1", []*pb.ContainerNetwork{
		{Bridge: "br-a", Mac: "52:54:00:00:04:02"}, {Bridge: "br-b", Mac: "52:54:00:00:04:02"}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("one MAC on two NICs of the request: got %v, want InvalidArgument", err)
	}
}

func TestReconcileMACCollisions_RaisesNamingBothAndResolves(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	const dup = "52:54:00:00:05:01"
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "mine", HostName: s.hostName, State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "mine", NetworkName: "lan", MAC: dup}}, nil); err != nil {
		t.Fatal(err)
	}
	seedNICOf(t, s, "theirs", dup)

	s.ReconcileMACCollisions(ctx)
	row, ok, err := corrosion.GetHealthCondition(ctx, s.db, NICIdentityEvaluator, CondMACDuplicate, "host", s.hostName)
	if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("condition after a collision: %+v ok=%v err=%v; want open", row, ok, err)
	}
	for _, want := range []string{dup, "VM mine", "VM theirs", "host peer"} {
		if !strings.Contains(row.Evidence, want) {
			t.Errorf("evidence %q does not name %q", row.Evidence, want)
		}
	}
	// Nothing was rewritten.
	nics, err := corrosion.MergedVMNICs(ctx, s.db, "mine")
	if err != nil || len(nics) != 1 || !strings.EqualFold(nics[0].MAC, dup) {
		t.Fatalf("mine's NICs = %+v, %v; want its MAC untouched", nics, err)
	}

	if err := corrosion.DeleteVM(ctx, s.db, "theirs"); err != nil {
		t.Fatal(err)
	}
	s.ReconcileMACCollisions(ctx)
	row, ok, err = corrosion.GetHealthCondition(ctx, s.db, NICIdentityEvaluator, CondMACDuplicate, "host", s.hostName)
	if err != nil || !ok || row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition after the collision is gone: %+v ok=%v err=%v; want resolved", row, ok, err)
	}
}

// A host none of whose workloads is involved raises nothing.
func TestReconcileMACCollisions_OnlyTheInvolvedHostsRaise(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	seedNICOf(t, s, "x", "52:54:00:00:06:01")
	seedNICOf(t, s, "y", "52:54:00:00:06:01")
	s.ReconcileMACCollisions(ctx)
	if _, ok, err := corrosion.GetHealthCondition(ctx, s.db, NICIdentityEvaluator, CondMACDuplicate, "host", s.hostName); err != nil || ok {
		t.Fatalf("an uninvolved host raised the condition (ok=%v, err=%v)", ok, err)
	}
}

// A restore under the backup's own name brings its MACs back, so one another
// VM took since is refused, naming it and the way out.
func TestRestoreLive_RefusesABackupMACAnotherVMTook(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.virt = libvirtfake.New()
	const mac = "52:54:00:00:07:01"
	seedNICOf(t, s, "thief", mac)
	spec, err := json.Marshal(&pb.VMSpec{Name: "vm1", Cpu: 1, MemoryMib: 512, Machine: "q35",
		Network: []*pb.NetworkAttachment{{Name: "lan", Mac: mac}}})
	if err != nil {
		t.Fatal(err)
	}
	repoDir, ts := seedLiveRepo(t, make([]byte, pbsstore.ChunkSize), string(spec))
	// Run until it returns or starts the VM: a restore that is not refused
	// keeps serving, and is cancelled here.
	_, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
		TargetPath: filepath.Join(t.TempDir(), "live.qcow2"), AutoStart: true,
	}, pb.RestoreLiveProgress_STARTED)
	select {
	case err = <-done:
	default:
		err = nil
	}
	cancel()
	if err == nil {
		<-done
	}
	if status.Code(err) != codes.AlreadyExists || !strings.Contains(err.Error(), "thief") || !strings.Contains(err.Error(), "--name") {
		t.Fatalf("restore onto a taken MAC: got %v, want AlreadyExists naming thief and --name", err)
	}
	if vm, _ := corrosion.GetVM(context.Background(), s.db, "vm1"); vm != nil {
		t.Fatal("the refused restore wrote a VM row")
	}
}

func TestApplyImportNetworks_GeneratedMACAvoidsTheCluster(t *testing.T) {
	s := testServer(t)
	const taken, free = "52:54:00:00:08:01", "52:54:00:00:08:02"
	seedNICOf(t, s, "other", taken)
	forceMACs(t, taken, free)
	fv := &vmimport.ForeignVM{NICs: []vmimport.ForeignNIC{{Network: "netA"}}}
	if err := s.applyImportNetworks(context.Background(), fv, &pb.ImportVMRequest{}); err != nil {
		t.Fatal(err)
	}
	if fv.NICs[0].MAC != free {
		t.Fatalf("imported NIC's MAC = %s, want %s", fv.NICs[0].MAC, free)
	}
}

// A renamed promotion is a second VM: its NIC gets a MAC no NIC of the
// cluster holds.
func TestPromoteReplica_RenamedDrawsAFreeMAC(t *testing.T) {
	s := testServer(t)
	s.virt = libvirtfake.New()
	ctx := adminCtx()
	const srcMAC, taken, free = "52:54:00:00:09:01", "52:54:00:00:09:02", "52:54:00:00:09:03"
	poolDir := t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"replica-pool": {Driver: "local", Target: poolDir}})
	specJSON, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{{Name: "lo", Mac: srcMAC}}})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "running", Spec: string(specJSON)},
		[]corrosion.InterfaceRecord{{VMName: "vm1", NetworkName: "lo", MAC: srcMAC}},
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: "/nonexistent-source", SizeBytes: 1 << 20, StorageType: "local"}},
	); err != nil {
		t.Fatal(err)
	}
	seedNICOf(t, s, "other", taken)
	seedReplica(t, poolDir, "", "vm1", "root", "20260101-000000", "raw", 1<<20)
	forceMACs(t, srcMAC, taken, free)
	if err := s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "vm1", NewName: "vm1-p", TargetPool: "replica-pool", NoLocalize: true,
	}, &streamRecorder[pb.PromoteReplicaProgress]{ctx: ctx}); err != nil {
		t.Fatalf("PromoteReplica: %v", err)
	}
	nics, err := corrosion.MergedVMNICs(ctx, s.db, "vm1-p")
	if err != nil || len(nics) != 1 || nics[0].MAC != free {
		t.Fatalf("vm1-p's NICs = %+v, %v; want one with %s", nics, err, free)
	}
}

// A stopped VM whose NIC's MAC another VM holds is refused a start, naming
// the holder and the way out; once the other is gone it starts.
func TestStartVM_RefusedWhileItsMACIsShared(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	ctx := adminCtx()
	const dup = "52:54:00:00:0a:01"
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "mine", HostName: s.hostName, State: "stopped", StateDetail: "operator-stop"},
		[]corrosion.InterfaceRecord{{VMName: "mine", NetworkName: "lan", MAC: dup}}, nil); err != nil {
		t.Fatal(err)
	}
	seedNICOf(t, s, "theirs", dup)
	_, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "mine"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "theirs") || !strings.Contains(err.Error(), "lv detach-nic") {
		t.Fatalf("start on a shared MAC: got %v, want FailedPrecondition naming theirs and lv detach-nic", err)
	}
	if err := s.refuseStartOnSharedMAC(ctx, "theirs"); err == nil {
		t.Fatal("the other side of the collision is not refused either")
	}
	if err := corrosion.DeleteVM(ctx, s.db, "theirs"); err != nil {
		t.Fatal(err)
	}
	if err := s.refuseStartOnSharedMAC(ctx, "mine"); err != nil {
		t.Fatalf("after theirs is gone: %v", err)
	}
}

// A MAC a latched cluster's detach freed — its vm_nics row tombstoned, the
// legacy row left live — is free for another NIC.
func TestMACAllocator_ADetachedNICsMACIsFree(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	const mac = "52:54:00:00:0b:01"
	seedNICOf(t, s, "det", mac)
	if err := corrosion.UpsertNIC(ctx, s.db, corrosion.NICRecord{VMName: "det", ID: corrosion.DeterministicNICID("det", mac), NetworkName: "lan", MAC: mac}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.TombstoneNIC(ctx, s.db, "det", corrosion.DeterministicNICID("det", mac)); err != nil {
		t.Fatal(err)
	}
	if _, h, err := s.macHolderOtherThan(ctx, []string{mac}, "x"); err != nil || h != "" {
		t.Fatalf("holder of the detached MAC = %q, %v; want none", h, err)
	}
	if err := s.checkNICIdentities(ctx, "", []*pb.NetworkAttachment{{Name: "lan", Mac: mac}}, "new"); err != nil {
		t.Fatalf("an explicit MAC a detach freed: %v", err)
	}
}
