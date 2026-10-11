package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// latchingGate models the moment the last host has upgraded but the HA
// monitor has not yet driven the latch: the local hint says "not latched",
// while driving the latch (FeatureRefusal, WithFeature) succeeds. WithFeature
// is where a use is recorded, so it is counted.
type latchingGate struct{ records *int }

func (g latchingGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	*g.records++
	return write(ctx, capabilities.GrantForTest(testingTB{}, f))
}

func (latchingGate) FeatureAvailable(capabilities.Feature) bool { return false }

func (latchingGate) FeatureRefusal(context.Context, capabilities.Feature) error { return nil }

// wrongGrantGate opens but hands out another feature's grant, so only a write
// that goes through a CHECKING writer is refused: it pins the writer choice at
// a call site whose grant is taken upstream.
type wrongGrantGate struct{}

func (wrongGrantGate) WithFeature(ctx context.Context, _ capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	return write(ctx, capabilities.GrantForTest(testingTB{}, capabilities.FeatureVMLimits))
}

func (wrongGrantGate) FeatureAvailable(capabilities.Feature) bool { return true }

// m1/m6. The entry fail-fast records nothing, and an owner records a use only
// once the cheap local refusals have passed: a request refused by permission,
// by a duplicate name or by a running container leaves no used record.
//
// Mutations: the entry check through WithReleaseFeature (as before this round)
// — the CreateVM case goes red; the owner's grant ahead of the duplicate-name
// or stopped check — that case goes red.
func TestPassthroughRelease_RefusedRequestsRecordNoUse(t *testing.T) {
	records := 0
	gate := latchingGate{records: &records}

	cr, _ := provableCreateServer(t)
	cr.SetReleaseFeatureGate(gate)
	_, err := cr.CreateVM(userCtx("op", "operator"), usbCreateRequest("c1", &pb.USBDeviceSpec{Vendor: "046d", Product: "c52b"}))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator CreateVM with a raw USB device = %v; want PermissionDenied", err)
	}
	if records != 0 {
		t.Errorf("a CreateVM refused by permission recorded %d use(s)", records)
	}

	ct, rt := secServer(t)
	ct.SetReleaseFeatureGate(gate)
	seedSecCT(t, ct, rt, "dup", "stopped", corrosion.ContainerCreateSpec{Template: "download"})
	req := hostAccessReq("dup")
	req.HostName = "host-a"
	if _, err := ct.CreateContainer(adminCtx(), req); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("CreateContainer of a duplicate name = %v; want AlreadyExists", err)
	}
	seedSecCT(t, ct, rt, "run", "running", corrosion.ContainerCreateSpec{Template: "download"})
	if _, err := ct.ConvertContainer(adminCtx(), &pb.ConvertContainerRequest{Name: "run", HostName: "host-a", SetHostAccess: true,
		Mounts: []*pb.ContainerMount{{HostPath: "/srv/data", ContainerPath: "/data"}}}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("convert --mount of a running container = %v; want FailedPrecondition", err)
	}
	if records != 0 {
		t.Errorf("container requests refused locally recorded %d use(s)", records)
	}
}

// m4. A restored container's row is written by the checking writer whenever
// it carries host access an operator restore kept, whatever grant it was
// handed; a peer move's row, or one without host access, by the plain one.
//
// Mutation: choose the writer by grant presence, or always the plain one —
// the no-grant case goes red.
func TestCreateRestoredContainerRow_WriterByContent(t *testing.T) {
	ctx := context.Background()
	s, _ := secServer(t)
	mounted := corrosion.ContainerRecord{HostName: "host-a", Name: "m", State: "stopped",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download",
			Mounts: []corrosion.ContainerHostMount{{HostPath: "/srv", ContainerPath: "/s"}}})}
	var none capabilities.FeatureGrant
	if err := s.createRestoredContainerRow(ctx, none, false, mounted, nil); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Fatalf("operator restore with host access and no grant: %v; want ErrNoFeatureGrant", err)
	}
	if row, _ := corrosion.GetContainer(ctx, s.db, "host-a", "m"); row != nil {
		t.Fatal("a refused restore row was written")
	}
	if err := s.createRestoredContainerRow(ctx, none, true, mounted, nil); err != nil {
		t.Fatalf("peer move keeping its source row's host access: %v", err)
	}
	plain := corrosion.ContainerRecord{HostName: "host-a", Name: "p", State: "stopped",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download"})}
	if err := s.createRestoredContainerRow(ctx, none, false, plain, nil); err != nil {
		t.Fatalf("restore without host access: %v", err)
	}
	if err := s.createRestoredContainerRow(ctx, capabilities.GrantForTest(t, capabilities.FeatureUSBMountsMemory), false,
		corrosion.ContainerRecord{HostName: "host-a", Name: "g", State: "stopped", CreateSpec: mounted.CreateSpec}, nil); err != nil {
		t.Fatalf("operator restore with the grant: %v", err)
	}
}

// m4. A live restore of the cluster's own row writes the VM row through the
// checking writer when the spec carries hot-add: handed another feature's
// grant, the writer refuses and no row is written; with the feature's grant
// the row lands with its band.
//
// Mutation: write the row at restore_live_autostart.go with the plain
// InsertVMWithHardware — the wrong-grant case goes red.
func TestRestoreLive_RowSpecWithHotplugGoesThroughTheWriter(t *testing.T) {
	for _, tc := range []struct {
		name string
		gate releaseFeatureGate
		ok   bool
	}{
		{"wrong grant", wrongGrantGate{}, false},
		{"feature's grant", passthroughGate{on: true}, true},
	} {
		s := testServer(t)
		s.hostName = "host-a"
		s.virt = libvirtfake.New()
		s.SetReleaseFeatureGate(tc.gate)
		spec, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Cpu: 2, MemoryMib: 2048, Machine: "q35", Firmware: "uefi",
			MemoryHotplugBaseMib: 2048, MemoryHotplugMaxMib: 4096})
		if err := corrosion.InsertVM(context.Background(), s.db,
			corrosion.VMRecord{Name: "vm1", HostName: "host-a", State: "stopped", Spec: string(spec)}, nil, nil); err != nil {
			t.Fatal(err)
		}
		repoDir, ts := seedLiveRepo(t, make([]byte, pbsstore.ChunkSize), "")
		stream, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
			RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts, FromExisting: true, NewName: "vm2",
			TargetPath: filepath.Join(t.TempDir(), "live.qcow2"), AutoStart: true,
		}, pb.RestoreLiveProgress_STARTED)
		row, _ := corrosion.GetVM(context.Background(), s.db, "vm2")
		cancel()
		err := <-done
		if !tc.ok {
			// The checking writer refuses the row. (A non-firmware live restore
			// treats a failed row write as best-effort and logs it, so the
			// observable is the missing row.)
			_ = stream
			if row != nil {
				t.Errorf("%s: restore = %v, row %+v; want refused with no row", tc.name, err, row)
			}
			continue
		}
		if row == nil {
			t.Fatalf("%s: no vm2 row (restore: %v)", tc.name, err)
		}
		var got pb.VMSpec
		_ = json.Unmarshal([]byte(row.Spec), &got)
		if got.MemoryHotplugMaxMib != 4096 {
			t.Errorf("%s: restored band = %d; want 4096", tc.name, got.MemoryHotplugMaxMib)
		}
	}
}
