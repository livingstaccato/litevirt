package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Until the release token is wired, the passthrough gate fails CLOSED:
// setting USB, hot-add or host mounts is refused, and a spec without them is
// unaffected.
func TestPassthroughGate_FailsClosedUntilWired(t *testing.T) {
	s, _ := provableCreateServer(t)
	ctx := adminCtx()
	_, err := s.CreateVM(ctx, usbCreateRequest("u1", &pb.USBDeviceSpec{Vendor: "046d", Product: "c52b"}))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "the cluster upgrade must finish first") {
		t.Fatalf("USB create with no release gate wired = %v; want refused until the upgrade finishes", err)
	}
	hot := disklessCreateRequest("h1")
	hot.Spec.MemoryHotplugMaxMib = 4096
	if _, err := s.CreateVM(ctx, hot); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("hot-add create with no release gate wired = %v; want refused", err)
	}
	if _, err := s.CreateVM(ctx, disklessCreateRequest("plain")); err != nil {
		t.Fatalf("a create with none of the fields was refused: %v", err)
	}
	cs, rt := secServer(t)
	_, err = cs.CreateContainer(adminCtx(), hostAccessReq("c1"))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "the cluster upgrade must finish first") {
		t.Fatalf("container mounts with no release gate wired = %v; want refused", err)
	}
	if len(rt.createCalls) != 0 {
		t.Fatal("a refused container create reached the runtime")
	}
}

// Once the release token has latched, promote carries the hot-add band into
// the domain it defines. (Before it, the band is dropped as main drops it:
// TestPromoteReplica_ReleaseFeaturesTakeTheCombinedWriter.)
func TestPromoteReplica_CarriesMemoryHotplug(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	fake := libvirtfake.New()
	s.virt = fake
	s.SetReleaseFeatureGate(ioGate{t: t, on: true})
	ctx := adminCtx()
	poolDir := t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"replica-pool": {Driver: "local", Target: poolDir}})
	specJSON, _ := json.Marshal(&pb.VMSpec{
		Name: "vm1", Cpu: 1, MemoryMib: 1024, MemoryHotplugBaseMib: 1024, MemoryHotplugMaxMib: 4096,
		Network: []*pb.NetworkAttachment{{Name: "lo", Model: "e1000"}},
	})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "running", Spec: string(specJSON)}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "test-host",
			Path: "/nonexistent-source", SizeBytes: 1 << 20, StorageType: "local"}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	seedReplica(t, poolDir, "", "vm1", "root", "20260101-000000", "raw", 1<<20)
	stream := &streamRecorder[pb.PromoteReplicaProgress]{ctx: ctx}
	if err := s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "vm1", NewName: "vm1-promoted", TargetPool: "replica-pool", NoLocalize: true,
	}, stream); err != nil {
		t.Fatalf("PromoteReplica: %v", err)
	}
	if x := fake.DefinedXML("vm1-promoted"); !lv.HasVirtioMem(x) {
		t.Fatalf("the promoted domain has no virtio-mem region:\n%s", x)
	}
}

// The capacity sampler counts what a hot-add domain holds — its boot cell
// plus the larger of the requested and the plugged size — not the whole
// region, and not less than the guest still holds.
func TestCollectRuntimeInventory_HotplugHeldMemory(t *testing.T) {
	s := inventoryServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	x, err := lv.GenerateDomainXML(lv.VMConfig{Name: "hv", CPU: 1, MemoryMiB: 2048, HotplugBaseMiB: 1024, HotplugMaxMiB: 8192})
	if err != nil {
		t.Fatal(err)
	}
	// Requested 1024 MiB plugged; the guest still holds 3072 from before.
	x = strings.Replace(x, "</requested>", "</requested><current unit=\"KiB\">3145728</current>", 1)
	if err := fake.DefineDomain(x); err != nil {
		t.Fatal(err)
	}
	if err := fake.StartDomain("hv"); err != nil {
		t.Fatal(err)
	}
	inv := s.collectRuntimeInventory(context.Background())
	w, ok := inv.find(corrosion.WorkloadVM, "hv")
	if !ok {
		t.Fatal("hv missing from the inventory")
	}
	if w.MemoryMiB != 1024+3072 {
		t.Fatalf("hv counted at %d MiB; want 4096 (1024 boot + 3072 the guest holds), not the 8192 region top", w.MemoryMiB)
	}
}

// Privileged mode and legacy confinement from a restored spec: kept for an
// admin, or for a peer move whose source row runs the same mode; stripped
// otherwise, and an unprivileged range is then asked for.
func TestAuthorizeRestoredSecurity(t *testing.T) {
	s, _ := secServer(t)
	priv := corrosion.ContainerCreateSpec{Template: "download", Confinement: "legacy"}
	unpriv := corrosion.ContainerCreateSpec{Template: "download", IDMapBase: 1_000_065_536, Confinement: "default"}
	src := &corrosion.ContainerRecord{Name: "pv", CreateSpec: corrosion.EncodeCreateSpec(priv)}
	other := &corrosion.ContainerRecord{Name: "pv", CreateSpec: corrosion.EncodeCreateSpec(unpriv)}
	for _, tc := range []struct {
		name       string
		ctx        context.Context
		cs         corrosion.ContainerCreateSpec
		source     *corrosion.ContainerRecord
		peer, keep bool
	}{
		{"operator, privileged", ctOperatorCtx(), priv, nil, false, false},
		{"admin, privileged", adminCtx(), priv, nil, false, true},
		{"operator, unprivileged default", ctOperatorCtx(), unpriv, nil, false, true},
		{"peer, source row agrees", adminCtx(), priv, src, true, true},
		{"peer, source row unprivileged", adminCtx(), priv, other, true, false},
		{"peer, no source row", adminCtx(), priv, nil, true, false},
	} {
		got, stripped, unprivilege := s.authorizeRestoredSecurity(tc.ctx, tc.cs, tc.source, tc.peer)
		kept := got.Confinement == tc.cs.Confinement && !unprivilege
		if kept != tc.keep || (stripped == "") != tc.keep {
			t.Errorf("%s: kept=%v stripped=%q unprivilege=%v; want kept=%v", tc.name, kept, stripped, unprivilege, tc.keep)
		}
		if !tc.keep && (got.Confinement != "default" || !unprivilege) {
			t.Errorf("%s: stripped to confinement %q unprivilege=%v; want default and a range", tc.name, got.Confinement, unprivilege)
		}
	}
}
