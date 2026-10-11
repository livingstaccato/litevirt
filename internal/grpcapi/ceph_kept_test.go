package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/storage"
)

// keptCondition reads ceph_image_leftover for test-host: whether it is open,
// and the images it names, by image → by_hand.
func keptCondition(t *testing.T, f *cephPoolFixture) (bool, map[string]string, string) {
	t.Helper()
	row, found, err := corrosion.GetHealthCondition(context.Background(), f.s.db, cephPoolEvaluator, condCephImageLeftover, "host", "test-host")
	if err != nil {
		t.Fatal(err)
	}
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		return false, nil, row.Evidence
	}
	var ev struct {
		Images []struct {
			Image, VM, Disk, Reason string
			ByHand                  string `json:"by_hand"`
		} `json:"images"`
	}
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		t.Fatalf("evidence %s: %v", row.Evidence, err)
	}
	out := map[string]string{}
	for _, i := range ev.Images {
		if i.VM == "" || i.Disk == "" || i.Reason == "" {
			t.Fatalf("evidence %s: an image named without its VM, disk or reason", row.Evidence)
		}
		out[i.Image] = i.ByHand
	}
	return true, out, row.Evidence
}

// deleteKeptCephVM deletes a VM whose ceph data disk a live client holds
// (lab 2, Bug 2), and returns the response header.
func deleteKeptCephVM(t *testing.T, f *cephPoolFixture, name string) (*headerStream, error) {
	t.Helper()
	t.Cleanup(storage.OverrideCephBusyBudgetForTest(time.Second))
	f.insertCephVM(t, name, "test-host")
	f.fake.SetState(name, libvirtfake.StateRunning)
	f.world.mu.Lock()
	f.world.watchers = map[string]bool{"lv/" + name + "-data": true}
	f.world.mu.Unlock()
	st := &headerStream{}
	_, err := f.s.DeleteVM(grpc.NewContextWithServerTransportStream(adminCtx(), st), &pb.DeleteVMRequest{Name: name})
	return st, err
}

// Lab 2, Bug 2. A VM delete whose ceph disk is refused as in use still
// deletes the VM (as main: the delete succeeded), but the image left in the
// pool is never unnamed: the response names it with its reason, for `lv rm`
// to print, and ceph_image_leftover names it with the check to run — never
// a removal — until the image is gone or a VM's disk names it again.
func TestDeleteVM_ACephImageKeptInUseIsNamed(t *testing.T) {
	f := newCephPoolFixture(t)
	st, err := deleteKeptCephVM(t, f, "keep")
	if err != nil {
		t.Fatalf("DeleteVM: %v (the VM delete itself succeeds, as on main)", err)
	}
	if !f.world.has("lv/keep-data") {
		t.Fatal("fixture: the in-use image was removed")
	}
	vals := st.hdr.Get(KeptCephImageMD)
	if len(vals) != 1 {
		t.Fatalf("response header %v, want one kept image", st.hdr)
	}
	var k KeptCephImage
	if err := json.Unmarshal([]byte(vals[0]), &k); err != nil || k.Image != "lv/keep-data" || k.Disk != "data" || !strings.Contains(k.Reason, "in use") {
		t.Fatalf("kept image %+v (%v), want lv/keep-data, disk data, in use", k, err)
	}

	f.s.judgeCephImages(context.Background())
	open, images, ev := keptCondition(t, f)
	if !open {
		t.Fatalf("ceph_image_leftover not raised: %s", ev)
	}
	if want := "rbd status lv/keep-data; rbd info lv/keep-data"; images["lv/keep-data"] != want {
		t.Fatalf("by_hand %q, want %q", images["lv/keep-data"], want)
	}
	if strings.Contains(ev, "rbd rm") || strings.Contains(ev, "trash rm") {
		t.Fatalf("evidence advises a removal: %s", ev)
	}

	// It survives a restart of the daemon: the record is kept on disk.
	f.s.cephKept = cephKeptImages{}
	f.s.judgeCephImages(context.Background())
	if open, images, ev := keptCondition(t, f); !open || images["lv/keep-data"] == "" {
		t.Fatalf("after a restart: %v %s", open, ev)
	}

	// Reattached: a VM's disk names the image again — no longer left over.
	if err := corrosion.InsertDisk(context.Background(), f.s.db, corrosion.DiskRecord{
		VMName: "adopter", DiskName: "data", HostName: "test-host", StorageType: "ceph", StorageVolume: "ceph",
		Path: "rbd:lv/keep-data:id=litevirt:lvpool=ceph",
	}); err != nil {
		t.Fatal(err)
	}
	f.s.judgeCephImages(context.Background())
	if open, _, ev := keptCondition(t, f); open {
		t.Fatalf("still raised for an image a VM's disk names again: %s", ev)
	}
}

// Lab 2, Bug 2. Once the image is gone from its pool (an operator removed
// it), the next scan forgets it and the condition resolves.
func TestCephImageLeftover_ClearsWhenTheImageIsGone(t *testing.T) {
	f := newCephPoolFixture(t)
	if _, err := deleteKeptCephVM(t, f, "gone"); err != nil {
		t.Fatal(err)
	}
	f.s.judgeCephImages(context.Background())
	if open, _, ev := keptCondition(t, f); !open {
		t.Fatalf("fixture: not raised: %s", ev)
	}
	f.s.ScanCephTrash(context.Background())
	f.s.judgeCephImages(context.Background())
	if open, _, _ := keptCondition(t, f); !open {
		t.Fatal("an image still in its pool was forgotten by a scan")
	}
	f.world.mu.Lock()
	delete(f.world.images, "lv/gone-data")
	f.world.mu.Unlock()
	f.s.ScanCephTrash(context.Background())
	f.s.judgeCephImages(context.Background())
	if open, _, ev := keptCondition(t, f); open {
		t.Fatalf("still raised for an image gone from its pool: %s", ev)
	}
}

// Lab 2, Bug 2. A delete forwarded to the VM's owner hands the owner's kept
// images back to its own caller.
func TestDeleteVM_KeptImagesFollowAForwardedDelete(t *testing.T) {
	st := &headerStream{}
	ctx := grpc.NewContextWithServerTransportStream(context.Background(), st)
	v := `{"image":"lv/a-data","disk":"data","reason":"in use"}`
	forwardKeptImages(ctx, metadata.Pairs(KeptCephImageMD, v))
	if got := st.hdr.Get(KeptCephImageMD); len(got) != 1 || got[0] != v {
		t.Fatalf("forwarded header %v, want %s", st.hdr, v)
	}
}
