package fleet

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Host drain and failback of a running Secure Boot + vTPM VM (spec §13, D-4):
// a VM whose disks are all on shared storage, between two hosts labelled for
// a live firmware move, moves through the live firmware move; any other is
// skipped with today's text and the reason. The scene and its one-copy
// watcher are fwlive_scene_test.go's.

// fwliveAllShared gives fwlive1 one disk on shared storage, and labels src as
// dst is labelled, so a drain of src may move it live.
func fwliveAllShared(t *testing.T, sc *fwliveScene) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertDisk(ctx, sc.src.DB, corrosion.DiskRecord{VMName: fwwVM, DiskName: "root", HostName: sc.src.Name,
		Path: filepath.Join(sc.c.tmpRoot, "nfs", fwwVM+"-root.qcow2"), SizeBytes: 1 << 30, StorageType: "nfs", TargetDev: "vda"}); err != nil {
		t.Fatal(err)
	}
	fwliveLabelForMove(t, sc.src, sc.src)
}

// fwliveLabelForMove labels host n for a live firmware move, as the scene
// labels dst, with a write made on at.
func fwliveLabelForMove(t *testing.T, at, n *Node) {
	t.Helper()
	for _, l := range []string{corrosion.LabelTPMCapable, corrosion.LabelSecureBootCapable, corrosion.LabelFwLiveMigrate} {
		if err := corrosion.SetHostLabel(context.Background(), at.DB, n.Name, l, "true"); err != nil {
			t.Fatal(err)
		}
	}
}

// fwliveDrain runs `lv host drain` of n and returns each VM's last frame and
// the drain's terminal error.
func fwliveDrain(t *testing.T, sc *fwliveScene, n *Node) (map[string]*pb.DrainProgress, error) {
	t.Helper()
	st, err := sc.c.SelfClient(n).DrainHost(context.Background(), &pb.DrainHostRequest{Name: n.Name})
	if err != nil {
		return nil, err
	}
	got := map[string]*pb.DrainProgress{}
	for {
		p, rerr := st.Recv()
		if rerr == io.EOF {
			return got, nil
		}
		if rerr != nil {
			return got, rerr
		}
		got[p.VmName] = p
	}
}

// fwliveStayed asserts fwlive1 was not moved off src at all: it runs there
// with its own row, its own state and no move record, and libvirt was never
// asked to migrate it.
func fwliveStayed(t *testing.T, src, dst *Node) {
	t.Helper()
	if st := fwliveState(src); st != string(libvirtfake.StateRunning) {
		t.Errorf("%s's guest is %s, want running", src.Name, st)
	}
	if row := fwliveRow(t, src); row.HostName != src.Name || row.State != "running" {
		t.Errorf("row %s/%s, want running on %s", row.HostName, row.State, src.Name)
	}
	if n := migrateCalls(src); n != 0 {
		t.Errorf("libvirt was asked to migrate %d time(s)", n)
	}
	if m, ok := fwliveMarker(t, src); ok {
		t.Errorf("a marker was left on %s (%s)", src.Name, m.Phase)
	}
	if _, ok := dst.Virt.RawState(fwwVM); ok {
		t.Errorf("a domain was defined on %s", dst.Name)
	}
	fwliveSourceKept(t, src)
}

// F-10. `lv host drain` of a host running an all-shared Secure Boot + vTPM VM
// moves it live through the live firmware move: memory only, on the tunnelled
// route, the guest paused on the target until Verify and Release, the
// source's state wiped after; the frame says done, live, with no error.
//
// Mutation: route the VM through drain's inline live path (drop the firmware
// branch in drainOneVM, so it reaches the raw MigrateToTarget) — red: libvirt
// is asked without firmware_live, no hold or Verify, and the source state
// stays.
func TestFleet_FwLive_F10_DrainMovesAnAllSharedFirmwareVMLive(t *testing.T) {
	sc := fwliveSetup(t, false)
	src, dst := sc.src, sc.dst
	fwliveAllShared(t, sc)

	progress, err := fwliveDrain(t, sc, src)
	if err != nil {
		t.Fatalf("drain: %v (fwlive1: %+v)", err, progress[fwwVM])
	}
	if p := progress[fwwVM]; p == nil || p.Status != "done" || p.Error != "" || p.Strategy != pb.MigrateStrategy_MIGRATE_LIVE {
		t.Fatalf("drain progress for %s = %+v, want done live with no error", fwwVM, p)
	}
	note := lastMigrateNote(src)
	for _, w := range []string{"firmware_live=true", "with_storage=false", "direct=false"} {
		if !strings.Contains(note, w) {
			t.Errorf("libvirt migrate = %q, want %s (memory only, tunnelled)", note, w)
		}
	}
	if !fwliveDid(dst, "migrate-in") {
		t.Error("the guest never landed on the target through the live firmware move")
	}
	fwliveMoved(t, src, dst)
	disks, err := corrosion.ListDisks(context.Background(), src.DB, fwwVM)
	if err != nil || len(disks) != 1 || disks[0].HostName != dst.Name {
		t.Errorf("disk rows %+v (%v), want root on %s", disks, err, dst.Name)
	}
}

// A running firmware VM with a host-local disk is still skipped by drain: a
// live move would need a storage copy, which drain does not ask for, and a
// cold move would shut it down. It keeps running where it is, untouched, and
// the frame gives today's text and the reason.
//
// Mutation: let the firmware branch take a VM with a host-local disk to
// drain's cold path (drainRunningVMCold) — red: the guest is shut down and
// moved cold.
func TestDrain_FirmwareHostLocalStillSkipped(t *testing.T) {
	sc := fwliveSetup(t, true)
	src, dst := sc.src, sc.dst
	fwliveLabelForMove(t, src, src)

	progress, err := fwliveDrain(t, sc, src)
	assertIncomplete(t, err)
	p := progress[fwwVM]
	if p == nil || p.Status != "skipped" || p.Strategy != pb.MigrateStrategy_MIGRATE_NONE {
		t.Fatalf("drain progress for %s = %+v, want skipped, not moved", fwwVM, p)
	}
	for _, w := range []string{"can't be drained while running", "host-local", "`lv stop " + fwwVM + "`", "drain again",
		"`lv migrate " + fwwVM + " <target-host> --cold`"} {
		if !strings.Contains(p.Error, w) {
			t.Errorf("skip reason %q does not contain %q", p.Error, w)
		}
	}
	if fwliveDid(src, "shutdown") || fwliveDid(src, "destroy") {
		t.Errorf("the guest was shut down: %v", fwliveOps(src))
	}
	fwliveStayed(t, src, dst)
}

// The target runs a build without the live firmware RPCs (a rolling upgrade)
// though its label says it can take the move: drain keeps today's behaviour
// for the VM, skipped with today's text and the target's build named, and
// nothing is written on the target; the drain itself is not failed by it.
//
// Mutation: report a refused firmware move as an error (status "error") —
// red.
func TestFleet_FwLive_DrainOlderTargetSkips(t *testing.T) {
	sc := fwliveSetup(t, false)
	src, dst := sc.src, sc.dst
	fwliveAllShared(t, sc)
	dst.RefuseRPCs("PrepareLiveFirmwareTarget", "VerifyLiveFirmwareTarget", "ReleaseLiveFirmwareTarget", "AbortLiveFirmwareTarget")

	progress, err := fwliveDrain(t, sc, src)
	assertIncomplete(t, err)
	p := progress[fwwVM]
	if p == nil || p.Status != "skipped" {
		t.Fatalf("drain progress for %s = %+v, want skipped", fwwVM, p)
	}
	for _, w := range []string{"can't be drained while running", "runs a build without live firmware migration", "`lv stop " + fwwVM + "`"} {
		if !strings.Contains(p.Error, w) {
			t.Errorf("skip reason %q does not contain %q", p.Error, w)
		}
	}
	fwliveStayed(t, src, dst)
}

// Failback follows drain's rules (D-4): a firmware VM a drain moved live
// returns live once both hosts are labelled for the move, and is skipped
// with drain's reason, not failed, while the returning host is not.
//
// Mutation: drop the firmware check in failbackOne — red: the unlabelled
// return reaches the move and fails instead of being skipped.
func TestFailback_FirmwareFollowsDrainRules(t *testing.T) {
	sc := fwliveSetup(t, false)
	src, dst := sc.src, sc.dst
	fwliveAllShared(t, sc)
	ctx := context.Background()
	for _, n := range sc.c.Nodes {
		n.Server.SetReleaseFeatureGate(passedReleaseGate{t: t})
		n.DB.SetClusterPolicyGate(func() bool { return true })
	}

	progress, err := fwliveDrain(t, sc, src)
	if err != nil {
		t.Fatalf("drain: %v (fwlive1: %+v)", err, progress[fwwVM])
	}
	src.Server.WaitDrainRecordsForTest()
	fwliveMoved(t, src, dst)
	if o, err := corrosion.ListDrainOrigins(ctx, src.DB, src.Name); err != nil || len(o) != 1 || o[0].VM != fwwVM {
		t.Fatalf("drain records %+v (%v), want one for %s", o, err, fwwVM)
	}
	if _, err := sc.c.SelfClient(src).UndrainHost(ctx, &pb.UndrainHostRequest{Name: src.Name}); err != nil {
		t.Fatalf("undrain: %v", err)
	}
	dst.LandMigrationsOn(src)
	// Hosts keep a VM's NVRAM at <data_dir>/nvram/<vm>_VARS.fd, one path
	// across a cluster with one data_dir; each fleet node has its own data
	// dir, so the landed definition is pointed at dst's store, as it names
	// the same path there. Stage A refuses the move back otherwise.
	x, err := dst.Virt.DumpXML(fwwVM)
	if err != nil {
		t.Fatal(err)
	}
	x = strings.ReplaceAll(x, src.FW.NvramPath(fwwVM), dst.FW.NvramPath(fwwVM))
	dst.Virt.SetInactiveXML(fwwVM, x)
	dst.Virt.SetActiveXML(fwwVM, x)
	failback := func() *pb.FailbackProgress {
		t.Helper()
		st, err := sc.c.SelfClient(src).FailbackHost(ctx, &pb.FailbackHostRequest{Name: src.Name, All: true})
		if err != nil {
			t.Fatalf("failback: %v", err)
		}
		got, err := collect(t, st)
		if err != nil {
			t.Fatalf("failback: %v", err)
		}
		return got[fwwVM]
	}

	// The returning host no longer advertises the move: skipped, as drain
	// skips it, and nothing moves.
	if err := corrosion.SetHostLabel(ctx, src.DB, src.Name, corrosion.LabelFwLiveMigrate, "false"); err != nil {
		t.Fatal(err)
	}
	if p := failback(); p == nil || p.Status != "skipped" || !strings.Contains(p.Reason, corrosion.LabelFwLiveMigrate) {
		t.Fatalf("failback to an unlabelled host = %+v, want skipped naming %s", p, corrosion.LabelFwLiveMigrate)
	}
	if n := migrateCalls(dst); n != 0 {
		t.Fatalf("libvirt on %s was asked to migrate %d time(s)", dst.Name, n)
	}
	if row := fwliveRow(t, src); row.HostName != dst.Name {
		t.Fatalf("the VM moved to %s", row.HostName)
	}

	// Labelled again: it returns live, through the live firmware move.
	if err := corrosion.SetHostLabel(ctx, src.DB, src.Name, corrosion.LabelFwLiveMigrate, "true"); err != nil {
		t.Fatal(err)
	}
	if p := failback(); p == nil || p.Status != "moved" {
		t.Fatalf("failback = %+v, want moved", p)
	}
	if note := lastMigrateNote(dst); !strings.Contains(note, "firmware_live=true") {
		t.Errorf("libvirt migrate on %s = %q, want firmware_live", dst.Name, note)
	}
	if st := fwliveState(src); st != string(libvirtfake.StateRunning) {
		t.Errorf("%s's guest is %s after the failback, want running", src.Name, st)
	}
	if st := fwliveState(dst); st != "undefined" {
		t.Errorf("%s's leftover domain is %s, want undefined", dst.Name, st)
	}
	if row := fwliveRow(t, src); row.HostName != src.Name || row.State != "running" {
		t.Errorf("row %s/%s after the failback, want running on %s", row.HostName, row.State, src.Name)
	}
	if m, ok := fwliveMarker(t, dst); ok {
		t.Errorf("%s's marker is left in %s", dst.Name, m.Phase)
	}
	if h, ok := fwliveHold(t, src); ok {
		t.Errorf("%s still holds the move (%s)", src.Name, h.State)
	}
}
