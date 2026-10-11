package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// askedGate is an ioGate (every feature, open or closed) that records which
// features a caller ran through the gate.
type askedGate struct {
	ioGate
	asked *[]capabilities.Feature
}

func (g askedGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	*g.asked = append(*g.asked, f)
	return g.ioGate.WithFeature(ctx, f, write)
}

// promoteWithReleaseData promotes a renamed copy of a VM whose stored spec
// carries CPU and NIC limits, memory hot-add and a USB device, through gate.
func promoteWithReleaseData(t *testing.T, gate ioGate) (*Server, *libvirtfake.Fake, []capabilities.Feature, error) {
	t.Helper()
	s := testServer(t)
	s.dataDir = t.TempDir()
	fake := libvirtfake.New()
	s.virt = fake
	var asked []capabilities.Feature
	gate.t = t
	s.SetReleaseFeatureGate(askedGate{ioGate: gate, asked: &asked})
	ctx := adminCtx()
	poolDir := t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"replica-pool": {Driver: "local", Target: poolDir}})
	specJSON, _ := json.Marshal(&pb.VMSpec{
		Name: "vm1", Cpu: 2, MemoryMib: 1024, MemoryHotplugBaseMib: 1024, MemoryHotplugMaxMib: 4096,
		CpuLimit: 1.5, CpuShares: 200,
		UsbDevices: []*pb.USBDeviceSpec{{Vendor: "046d", Product: "c52b"}},
		Network:    []*pb.NetworkAttachment{{Name: "lo", Model: "virtio", RateMbSec: 100}},
	})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "running", Spec: string(specJSON)}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: "/nonexistent-source", SizeBytes: 1 << 20, StorageType: "local"}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	seedReplica(t, poolDir, "", "vm1", "root", "20260101-000000", "raw", 1<<20)
	stream := &streamRecorder[pb.PromoteReplicaProgress]{ctx: ctx}
	err := s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "vm1", NewName: "vm1-p", TargetPool: "replica-pool", NoLocalize: true,
	}, stream)
	return s, fake, asked, err
}

func askedFor(asked []capabilities.Feature, f capabilities.Feature) bool {
	for _, a := range asked {
		if a == f {
			return true
		}
	}
	return false
}

// A promotion is a recovery path: it is never refused for the release
// features its spec carries. Before the release latch it behaves as main does
// (main knows none of them): the limits and the hot-add band are neither
// rendered nor written. Once the gate opens, each feature's own grant is taken
// and the renamed copy's row is written through the combined writer that
// checks every one (corrosion.InsertVMWithReleaseFeatures, integration
// checklist M9); a gate that refuses after the latch drops the feature and
// the promotion still runs. A renamed copy never carries the source's USB
// devices (a clone does not either, and raw USB needs an admin).
//
// Mutations: promote back on insertVMForSpec (tuning grant only) — the open
// case asks neither vm_limits nor usb_mounts_memory; skip the limits strip —
// the closed and refusing cases render <cputune>; skip the hot-add strip — they
// render virtio-mem; skip the USB strip — the open case stores the device.
func TestPromoteReplica_ReleaseFeaturesTakeTheCombinedWriter(t *testing.T) {
	// Gate open: every grant asked, data kept, written.
	s, fake, asked, err := promoteWithReleaseData(t, ioGate{on: true})
	if err != nil {
		t.Fatalf("promote with the gate open: %v", err)
	}
	for _, f := range []capabilities.Feature{capabilities.FeatureVMLimits, capabilities.FeatureUSBMountsMemory} {
		if !askedFor(asked, f) {
			t.Errorf("gate open: the promote never ran %s through the gate (asked %v)", f, asked)
		}
	}
	x := fake.DefinedXML("vm1-p")
	if !lv.HasVirtioMem(x) || !strings.Contains(x, "<cputune>") || !strings.Contains(x, "<bandwidth") {
		t.Errorf("gate open: the promoted domain lost its hot-add or limits:\n%s", x)
	}
	got := loadStoredSpec(t, s, "vm1-p")
	if !specSetsLimits(got) || got.MemoryHotplugMaxMib != 4096 {
		t.Errorf("gate open: the stored spec lost its limits or hot-add: %+v", got)
	}
	if len(got.UsbDevices) != 0 {
		t.Errorf("gate open: the renamed copy carries the source's USB devices: %+v", got.UsbDevices)
	}

	// Gate closed (before the latch) and latched-but-refusing: the promotion
	// still runs, without any of it.
	for name, g := range map[string]ioGate{
		"closed":                   {on: false},
		"latched but refusing use": {latchedButRefuses: true},
	} {
		s, fake, asked, err := promoteWithReleaseData(t, g)
		if err != nil {
			t.Errorf("%s: promote refused: %v", name, err)
			continue
		}
		// Before the latch the data is dropped without asking the gate, which
		// would only ping the lagging hosts to refuse.
		if name == "closed" && len(asked) != 0 {
			t.Errorf("closed: the gate was asked for %v before the latch", asked)
		}
		x := fake.DefinedXML("vm1-p")
		if lv.HasVirtioMem(x) || strings.Contains(x, "<cputune>") || strings.Contains(x, "<bandwidth") {
			t.Errorf("%s: the promoted domain renders release data:\n%s", name, x)
		}
		got := loadStoredSpec(t, s, "vm1-p")
		if specSetsLimits(got) || vmSpecSetsPassthrough(got) || got.MemoryHotplugBaseMib != 0 {
			t.Errorf("%s: the stored spec carries release data: %+v", name, got)
		}
	}
}

// insertLimitedVM1 records vm1, owned by a failed host in project acme, with
// limits and a hot-add band in its spec, and a replica of its root disk.
func insertLimitedVM1(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	poolDir := t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"replica-pool": {Driver: "local", Target: poolDir}})
	specJSON, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Cpu: 2, MemoryMib: 1024,
		MemoryHotplugBaseMib: 1024, MemoryHotplugMaxMib: 4096, CpuLimit: 1.5, CpuShares: 200,
		Network: []*pb.NetworkAttachment{{Name: "lo", Model: "virtio"}}})
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm1", HostName: "dead-host", State: "running",
		Spec: string(specJSON), Project: "acme", CPUActual: 2, MemActual: 1024}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "dead-host", Path: "/gone", SizeBytes: 1 << 20, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "dead-host", Address: "10.0.0.66", State: "failed"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertProject(ctx, s.db, corrosion.ProjectRecord{Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	seedReplica(t, poolDir, "acme", "vm1", "root", "20260101-000000", "raw", 1<<20)
}

// A promotion its own checks refuse records no release-feature use: the
// grants are taken only once every refusal has passed (review m-2), so a
// renamed promotion over its project's quota asks the gate nothing.
//
// Mutation: take the grants in restrictPromotedReleaseFeatures, ahead of the
// refusals (as before) — the gate is asked.
func TestPromoteReplica_ARefusedPromotionRecordsNoUse(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.virt = libvirtfake.New()
	var asked []capabilities.Feature
	s.SetReleaseFeatureGate(askedGate{ioGate: ioGate{t: t, on: true}, asked: &asked})
	insertLimitedVM1(t, s)
	if err := corrosion.UpsertProjectQuota(context.Background(), s.db, corrosion.ProjectQuotaRecord{
		ProjectName: "acme", VCPULimit: 3, MemMiBLimit: 3000,
	}); err != nil {
		t.Fatal(err)
	}
	err := promoteVM(s, &pb.PromoteReplicaRequest{VmName: "vm1", NewName: "vm1-dr"})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("renamed promotion past the quota: %v, want ResourceExhausted", err)
	}
	if len(asked) != 0 {
		t.Errorf("a refused promotion ran the release gate for %v", asked)
	}
}

// A takeover keeps its row's spec. With the gate closed its domain is defined
// without the limits and the hot-add band, the row keeps them for the next
// redefine, and the audit says so — not that they were dropped (review m-3).
// With the gate open, the domain renders them.
//
// Mutation: word the takeover audit as a renamed one's ("not carried") —
// the closed case goes red.
func TestPromoteReplica_TakeoverKeepsTheRowsReleaseData(t *testing.T) {
	for _, open := range []bool{false, true} {
		s := testServer(t)
		s.dataDir = t.TempDir()
		fake := libvirtfake.New()
		s.virt = fake
		s.SetReleaseFeatureGate(ioGate{t: t, on: open})
		insertLimitedVM1(t, s)
		if err := promoteVM(s, &pb.PromoteReplicaRequest{VmName: "vm1"}); err != nil {
			t.Fatalf("open=%v: takeover: %v", open, err)
		}
		x := fake.DefinedXML("vm1")
		if rendered := lv.HasVirtioMem(x) && strings.Contains(x, "<cputune>"); rendered != open {
			t.Errorf("open=%v: the domain renders the limits and band = %v:\n%s", open, rendered, x)
		}
		if got := loadStoredSpec(t, s, "vm1"); !specSetsLimits(got) || got.MemoryHotplugMaxMib != 4096 {
			t.Errorf("open=%v: the takeover's row lost its release data: %+v", open, got)
		}
		rows, _ := s.db.Query(context.Background(), `SELECT detail FROM audit_log WHERE action = 'vm.release_features_dropped'`)
		switch {
		case open && len(rows) != 0:
			t.Errorf("open gate: an audit of a drop: %v", rows)
		case !open && (len(rows) != 1 || !strings.Contains(rows[0].String("detail"), "kept in the row")):
			t.Errorf("closed gate: audit rows %v; want one saying the data is kept in the row", rows)
		}
	}
}
