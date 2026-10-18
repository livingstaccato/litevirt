package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/storage"
)

// Breaker minor 1. A VM whose own probe got no answer keeps its own record
// until its own probe answers, not for a fixed two minutes: one not probed
// again for longer (deferred for time on every pass) is still probed, never
// started on a proof another VM's probe made later.
//
// Mutation "record lapses at cephKeyProofTTL" (ownFailed bounded by it):
// red.
func TestPrepareHardwareForStart_AFailedVMsOwnRecordOutlastsTheProofTTL(t *testing.T) {
	f := newCephPoolFixture(t)
	x := f.insertPoolVM(t, "x-db", "ceph", "lv", "stopped")
	y := f.insertPoolVM(t, "y-web", "ceph", "lv", "stopped")
	now := time.Now()
	prev := cephProofNow
	cephProofNow = func() time.Time { return now }
	t.Cleanup(func() { cephProofNow = prev })
	f.world.downImages = map[string]bool{"lv/x-db-root": true}
	if _, err := f.s.PrepareHardwareForStart(health.WithWalkProbeTurn(context.Background()), &x); !errors.Is(err, health.ErrStartProbeFailed) {
		t.Fatalf("x, whose image does not answer: %v, want ErrStartProbeFailed", err)
	}
	now = now.Add(cephKeyProofTTL + time.Minute)
	if _, err := f.s.PrepareHardwareForStart(context.Background(), &y); err != nil {
		t.Fatalf("y, on the same key: %v", err)
	}
	before := f.world.probes()
	_, err := f.s.PrepareHardwareForStart(health.WithWalkProbeTurn(context.Background()), &x)
	if f.world.probes() != before+1 || !errors.Is(err, health.ErrStartProbeFailed) {
		t.Fatalf("x %s after its failure, y having proved the key: %v, %d new probes; want x probed itself, not started on y's proof",
			cephKeyProofTTL+time.Minute, err, f.world.probes()-before)
	}
}

// Labfix M2. A kept image a VM's disk named again (reattached) is no longer a
// leftover, and its record goes: when that VM is later deleted keeping its
// disks, the image is not named again with the first delete's VM and reason.
//
// Mutation "record kept" (judgeCephImages only skips a named image): red.
func TestCephImageLeftover_AReattachedImageIsForgotten(t *testing.T) {
	f := newCephPoolFixture(t)
	ctx := context.Background()
	if _, err := deleteKeptCephVM(t, f, "keep"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertDisk(ctx, f.s.db, corrosion.DiskRecord{
		VMName: "adopter", DiskName: "data", HostName: "test-host", StorageType: "ceph", StorageVolume: "ceph",
		Path: "rbd:lv/keep-data:id=litevirt:lvpool=ceph",
	}); err != nil {
		t.Fatal(err)
	}
	f.s.judgeCephImages(ctx)
	if err := f.s.db.Execute(ctx, `UPDATE vm_disks SET deleted_at = ? WHERE vm_name = 'adopter'`, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	f.s.judgeCephImages(ctx)
	if open, _, ev := keptCondition(t, f); open {
		t.Fatalf("an image its adopter kept is named again as the first delete's leftover: %s", ev)
	}
	if recs := f.s.keptRecords(); len(recs) != 0 {
		t.Fatalf("records %+v, want the reattached image's record gone", recs)
	}
}

// Labfix M4a. A record file that cannot be read is set aside, never saved
// over: the names it held are kept for an operator.
//
// Mutation "overwrite" (no set-aside): red.
func TestCephKeptImages_AnUnreadableRecordIsSetAside(t *testing.T) {
	f := newCephPoolFixture(t)
	path := filepath.Join(f.s.dataDir, cephKeptFile)
	garbage := `[{"image":"lv/old-data","vm":"old"`
	if err := os.WriteFile(path, []byte(garbage), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := deleteKeptCephVM(t, f, "keep"); err != nil {
		t.Fatal(err)
	}
	asides, _ := filepath.Glob(path + ".unreadable-*")
	if len(asides) != 1 {
		t.Fatalf("set aside %v, want the unreadable record kept under a name of its own", asides)
	}
	if raw, _ := os.ReadFile(asides[0]); string(raw) != garbage {
		t.Fatalf("set-aside file %q, want the unreadable record as it was", raw)
	}
	if recs := f.s.keptRecords(); len(recs) != 1 || recs[0].Image != "lv/keep-data" {
		t.Fatalf("records %+v, want the new kept image recorded", recs)
	}
}

// Labfix M4b. A recheck that found an image gone forgets only the record it
// checked: an image recorded again meanwhile (another delete left it) stays.
//
// Mutation "delete by key" (no compare): red.
func TestCephKeptImages_ARecheckKeepsARecordWrittenMeanwhile(t *testing.T) {
	f := newCephPoolFixture(t)
	if _, err := deleteKeptCephVM(t, f, "gone"); err != nil {
		t.Fatal(err)
	}
	f.world.mu.Lock()
	delete(f.world.images, "lv/gone-data")
	f.world.mu.Unlock()
	cephKeptRecheckHook = func(image string) {
		f.s.cephKept.mu.Lock()
		r := f.s.keptLocked()[image]
		r.VM, r.Reason, r.Since = "again", "in use (again)", time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
		f.s.keptLocked()[image] = r
		f.s.cephKept.mu.Unlock()
	}
	t.Cleanup(func() { cephKeptRecheckHook = nil })
	f.s.recheckKeptCephImages(context.Background())
	if recs := f.s.keptRecords(); len(recs) != 1 || recs[0].VM != "again" {
		t.Fatalf("records %+v, want the record written during the recheck kept", recs)
	}
}

// Labfix M4d. The kept image's response header is ASCII and bounded, whatever
// rbd answered: a non-ASCII or very long reason still decodes to its text.
//
// Mutation "raw JSON" (setKeptHeader without the escape and bound): red.
func TestSetKeptHeader_IsASCIIAndBounded(t *testing.T) {
	st := &headerStream{}
	ctx := grpc.NewContextWithServerTransportStream(context.Background(), st)
	reason := "rbd: übel " + strings.Repeat("x", 8000)
	setKeptHeader(ctx, []KeptCephImage{{Image: "lv/a-data", Disk: "data", Reason: reason}})
	vals := st.hdr.Get(KeptCephImageMD)
	if len(vals) != 1 {
		t.Fatalf("header %v", st.hdr)
	}
	v := vals[0]
	for _, r := range v {
		if r < 0x20 || r > 0x7e {
			t.Fatalf("header value carries %q, not printable ASCII", r)
		}
	}
	if len(v) > 2048 {
		t.Fatalf("header value is %d bytes, want it bounded", len(v))
	}
	var k KeptCephImage
	if err := json.Unmarshal([]byte(v), &k); err != nil || k.Image != "lv/a-data" || !strings.HasPrefix(k.Reason, "rbd: übel xxx") {
		t.Fatalf("decoded %+v (%v)", k, err)
	}
}

// Labfix M1. The condition does not claim nothing uses a kept image: a
// clone's parent, or a client outside litevirt, may.
func TestCephImageLeftover_DetailAllowsForAClonesParent(t *testing.T) {
	f := newCephPoolFixture(t)
	if _, err := deleteKeptCephVM(t, f, "keep"); err != nil {
		t.Fatal(err)
	}
	f.s.judgeCephImages(context.Background())
	_, _, ev := keptCondition(t, f)
	if !strings.Contains(ev, "clone") {
		t.Fatalf("detail %s, want it to allow for a clone's parent", ev)
	}
}

// Review I-1. A kept image the deleting VM's own rows still name — its delete
// records before it tombstones them — is not forgotten: it is named once
// those rows are gone.
//
// Mutation "any naming row forgets" (the round-0 rule): red.
func TestCephImageLeftover_TheDeletingVMsOwnRowsDoNotForgetIt(t *testing.T) {
	f := newCephPoolFixture(t)
	ctx := context.Background()
	vm := f.insertCephVM(t, "own", "test-host")
	disks, _ := corrosion.GetVMDisks(ctx, f.s.db, vm.Name)
	var data *corrosion.DiskRecord
	for i := range disks {
		if disks[i].DiskName == "data" {
			data = &disks[i]
		}
	}
	if _, ok := f.s.recordKeptCephImage(vm.Name, data, errors.New("in use")); !ok {
		t.Fatal("fixture: not recorded")
	}
	f.s.judgeCephImages(ctx)
	if recs := f.s.keptRecords(); len(recs) != 1 {
		t.Fatalf("records %+v: the deleting VM's own row forgot the kept image", recs)
	}
	if err := f.s.db.Execute(ctx, `UPDATE vm_disks SET deleted_at = ? WHERE vm_name = ?`, time.Now().UTC().Format(time.RFC3339), vm.Name); err != nil {
		t.Fatal(err)
	}
	f.s.judgeCephImages(ctx)
	if open, images, ev := keptCondition(t, f); !open || images["lv/own-data"] == "" {
		t.Fatalf("after the delete's tombstone: open %v, %s", open, ev)
	}
}

// Review m-6. A queue file that could not be moved aside is not described
// as set aside.
func TestCephTrashLeftover_AnUnmovedQueueFileIsNotCalledSetAside(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root renames in a read-only directory")
	}
	f := newCephPoolFixture(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ceph-trash-purges.json"), []byte("[{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_ = storage.ResumeCephPurges(dir)
	f.s.judgeCephTrash(context.Background())
	row, _, _ := corrosion.GetHealthCondition(context.Background(), f.s.db, cephPoolEvaluator, condCephTrashLeftover, "host", "test-host")
	if !strings.Contains(row.Evidence, "left in place") {
		t.Fatalf("evidence %s, want an unmoved file described as left in place", row.Evidence)
	}
}

// Re-review m-D. A kept record whose VM name has a VM again — created anew
// and using the image — is that VM's disk now: the record goes, though the
// rows naming it carry the deleted VM's name.
//
// Mutation "name only" (anotherIncarnation always false): red.
func TestCephImageLeftover_AReCreatedVMOfTheNameForgetsIt(t *testing.T) {
	f := newCephPoolFixture(t)
	ctx := context.Background()
	vm := f.insertCephVM(t, "again", "test-host")
	disks, _ := corrosion.GetVMDisks(ctx, f.s.db, vm.Name)
	var data corrosion.DiskRecord
	for _, d := range disks {
		if d.DiskName == "data" {
			data = d
		}
	}
	if _, ok := f.s.recordKeptCephImage(vm.Name, &data, errors.New("in use")); !ok {
		t.Fatal("fixture: not recorded")
	}
	if err := corrosion.DeleteVM(ctx, f.s.db, vm.Name); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond) // a new created_at
	data.VMName = vm.Name
	if err := corrosion.InsertVM(ctx, f.s.db, corrosion.VMRecord{Name: vm.Name, HostName: "test-host", State: "stopped",
		Spec: `{"name":"again","cpu":1,"memory_mib":256}`}, nil, []corrosion.DiskRecord{data}); err != nil {
		t.Fatal(err)
	}
	f.s.judgeCephImages(ctx)
	if recs := f.s.keptRecords(); len(recs) != 0 {
		t.Fatalf("records %+v: a re-created VM using the image kept the old delete's record", recs)
	}
}
