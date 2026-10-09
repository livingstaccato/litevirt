package grpcapi

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// seedRestorableVM is a running VM rs on this host with snapshot s1 of the
// given type in the fake and in corrosion.
func seedRestorableVM(t *testing.T, s *Server, typ string) *libvirtfake.Fake {
	t.Helper()
	fake := s.virt.(*libvirtfake.Fake)
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{
		Name: "rs", HostName: s.hostName, State: "running",
		Spec: `{"name":"rs","cpu":1,"memory_mib":512}`,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	rec := corrosion.SnapshotRecord{ID: "rs-s1", VMName: "rs", HostName: s.hostName, Name: "s1", State: "ok", Type: typ}
	if typ == "memory" {
		rec.VMStatePath = filepath.Join(t.TempDir(), "rs-s1.save")
		if err := os.WriteFile(rec.VMStatePath, []byte("ram"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := fake.CreateLiveSnapshot("rs", "s1", rec.VMStatePath, nil); err != nil {
			t.Fatal(err)
		}
		fake.SetSavedImageXML(rec.VMStatePath, "<domain type='kvm'><name>rs</name><devices></devices></domain>")
	} else if _, err := fake.CreateSnapshot("rs", "s1"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertSnapshot(adminCtx(), s.db, rec); err != nil {
		t.Fatal(err)
	}
	return fake
}

// A restore takes the VM's domain down and brings it back. On the lab the
// reconciler saw the VM recorded running with no domain in that window and
// restarted it on the old overlay; the restore then reset a file the new
// qemu no longer read, and returned "domain is already running" with the
// guest not restored (snapshot-repro.md, incidental finding 1). Every start
// path takes the VM's start lease, so the restore holds it throughout.
func TestRestoreSnapshot_HoldsTheStartLeaseForTheWholeRevert(t *testing.T) {
	for _, typ := range []string{"disk", "memory"} {
		t.Run(typ, func(t *testing.T) {
			s := lockTestServer(t)
			fake := seedRestorableVM(t, s, typ)
			reverted := false
			fake.OnRevertSnapshot = func(domain, snap string) {
				reverted = true
				// The reconciler's own start path, mid-revert.
				heldBy, err := health.TryVMStartLease(adminCtx(), s.db, s.hostName, "rs", time.Now())
				if err != nil {
					t.Errorf("TryVMStartLease: %v", err)
					return
				}
				if heldBy == s.hostName {
					health.ReleaseVMStartLease(adminCtx(), s.db, s.hostName, "rs")
					t.Error("the reconciler took the VM's start lease in the middle of its restore, and would restart it")
				}
			}
			if _, err := s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "rs", SnapshotName: "s1"}); err != nil {
				t.Fatalf("RestoreSnapshot: %v", err)
			}
			if !reverted {
				t.Fatal("the revert did not run")
			}
			heldBy, err := health.TryVMStartLease(adminCtx(), s.db, s.hostName, "rs", time.Now())
			if err != nil || heldBy != s.hostName {
				t.Fatalf("after the restore the start lease is held by %q (%v); it must be released", heldBy, err)
			}
		})
	}
}

// A start in progress holds the lease; the restore waits for nothing and is
// refused, naming the holder, before anything is torn down.
func TestRestoreSnapshot_RefusedWhileAStartHoldsTheLease(t *testing.T) {
	s := lockTestServer(t)
	fake := seedRestorableVM(t, s, "disk")
	if heldBy, err := health.TryVMStartLease(adminCtx(), s.db, s.hostName, "rs", time.Now()); err != nil || heldBy != s.hostName {
		t.Fatalf("setup: lease %q %v", heldBy, err)
	}
	_, err := s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "rs", SnapshotName: "s1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("RestoreSnapshot = %v, want FailedPrecondition while a start holds the lease", err)
	}
	for _, e := range fake.EventLog() {
		if e.Op == "revert" || e.Op == "revert-live" {
			t.Fatal("the revert ran while a start held the VM's start lease")
		}
	}
}

// A restore libvirt would not take back as current (review I-1) succeeds,
// and says so: in the response header lv prints, and as the VM's event
// snapshot.restore-not-current — not only in the daemon's log.
func TestRestoreSnapshot_ANotCurrentRestoreIsReported(t *testing.T) {
	for _, typ := range []string{"disk", "memory"} {
		t.Run(typ, func(t *testing.T) {
			s := lockTestServer(t)
			fake := seedRestorableVM(t, s, typ)
			fake.RevertNotCurrent = true
			h := &headerCapture{}
			ctx := grpc.NewContextWithServerTransportStream(adminCtx(), h)
			if _, err := s.RestoreSnapshot(ctx, &pb.RestoreSnapshotRequest{VmName: "rs", SnapshotName: "s1"}); err != nil {
				t.Fatalf("RestoreSnapshot: %v (the revert itself succeeded)", err)
			}
			if w := h.md.Get(RestoreWarningHeader); len(w) != 1 || !strings.Contains(w[0], "current") {
				t.Errorf("response header %s = %v, want the not-current warning", RestoreWarningHeader, w)
			}
			evs, err := corrosion.ListVMEvents(adminCtx(), s.db, "rs", 50, "")
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, e := range evs {
				if e.Type == "snapshot.restore-not-current" {
					found = true
				}
			}
			if !found {
				t.Errorf("no snapshot.restore-not-current event among %+v", evs)
			}
		})
	}
}

// A lease no live holder stands behind does not stop a restore (review
// M-1): main allowed it, and the holder cannot be starting the VM. The
// restore takes the lease over, and releases it after.
func TestRestoreSnapshot_TakesOverAStaleStartLease(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, s *Server)
	}{
		{"this node's crashed run", func(t *testing.T, s *Server) {
			// Taken a minute before this daemon started.
			s.startedAt = time.Now()
			if h, err := health.TryVMStartLease(adminCtx(), s.db, s.hostName, "rs", s.startedAt.Add(-time.Minute)); err != nil || h != s.hostName {
				t.Fatalf("setup: lease %q %v", h, err)
			}
		}},
		{"a host that is not active", func(t *testing.T, s *Server) {
			if err := corrosion.InsertHost(adminCtx(), s.db, corrosion.HostRecord{Name: "host-b", Address: "10.0.0.2", State: "fenced"}); err != nil {
				t.Fatal(err)
			}
			if h, err := health.TryVMStartLease(adminCtx(), s.db, "host-b/vmcheck", "rs", time.Now()); err != nil || h != "host-b/vmcheck" {
				t.Fatalf("setup: lease %q %v", h, err)
			}
		}},
		{"a host marked offline", func(t *testing.T, s *Server) {
			if err := corrosion.InsertHost(adminCtx(), s.db, corrosion.HostRecord{Name: "host-c", Address: "10.0.0.4", State: "offline"}); err != nil {
				t.Fatal(err)
			}
			if h, err := health.TryVMStartLease(adminCtx(), s.db, "host-c/vmcheck", "rs", time.Now()); err != nil || h != "host-c/vmcheck" {
				t.Fatalf("setup: lease %q %v", h, err)
			}
		}},
		{"a host removed from the cluster", func(t *testing.T, s *Server) {
			if err := corrosion.InsertHost(adminCtx(), s.db, corrosion.HostRecord{Name: "gone-host", Address: "10.0.0.3", State: "active"}); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.DeleteHost(adminCtx(), s.db, "gone-host"); err != nil {
				t.Fatal(err)
			}
			if h, err := health.TryVMStartLease(adminCtx(), s.db, "gone-host", "rs", time.Now()); err != nil || h != "gone-host" {
				t.Fatalf("setup: lease %q %v", h, err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := lockTestServer(t)
			seedRestorableVM(t, s, "disk")
			tc.setup(t, s)
			if _, err := s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "rs", SnapshotName: "s1"}); err != nil {
				t.Fatalf("RestoreSnapshot refused over a stale lease: %v", err)
			}
			if h, err := health.TryVMStartLease(adminCtx(), s.db, s.hostName, "rs", time.Now()); err != nil || h != s.hostName {
				t.Fatalf("after the restore the lease is held by %q (%v); it must be released", h, err)
			}
		})
	}
}

// A live holder still stops it: a component of this daemon (taken since it
// started), or an active host.
func TestRestoreSnapshot_RefusedWhileALiveHolderHasTheLease(t *testing.T) {
	cases := []struct {
		name   string
		holder string
		setup  func(t *testing.T, s *Server)
	}{
		{"this daemon", "", func(t *testing.T, s *Server) { s.startedAt = time.Now().Add(-time.Hour) }},
		// A host whose hosts row has not reached this replica yet (re-review
		// R1-M2): nothing says it is gone, so it counts as live.
		{"a host this replica has no row for", "new-host", func(t *testing.T, s *Server) {}},
		{"an active host", "host-b/repair", func(t *testing.T, s *Server) {
			if err := corrosion.InsertHost(adminCtx(), s.db, corrosion.HostRecord{Name: "host-b", Address: "10.0.0.2", State: "active"}); err != nil {
				t.Fatal(err)
			}
		}},
	}
	// A host that is draining, in maintenance, upgrading, joining or merely
	// suspect still runs its daemon, which may hold the lease and run the VM:
	// a draining source's cold move holds it until the handoff is cleaned up
	// (final whole-branch review M6). Only offline, fenced or removed is gone.
	for _, st := range []string{"draining", "maintenance", "upgrading", corrosion.HostStateJoining, "suspect"} {
		st := st
		cases = append(cases, struct {
			name   string
			holder string
			setup  func(t *testing.T, s *Server)
		}{"a " + st + " host", "host-d/cold-migrate", func(t *testing.T, s *Server) {
			if err := corrosion.InsertHost(adminCtx(), s.db, corrosion.HostRecord{Name: "host-d", Address: "10.0.0.5", State: st}); err != nil {
				t.Fatal(err)
			}
		}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := lockTestServer(t)
			fake := seedRestorableVM(t, s, "disk")
			tc.setup(t, s)
			holder := tc.holder
			if holder == "" {
				holder = s.hostName
			}
			if h, err := health.TryVMStartLease(adminCtx(), s.db, holder, "rs", time.Now()); err != nil || h != holder {
				t.Fatalf("setup: lease %q %v", h, err)
			}
			_, err := s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "rs", SnapshotName: "s1"})
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), holder) {
				t.Fatalf("RestoreSnapshot = %v, want FailedPrecondition naming %s", err, holder)
			}
			for _, e := range fake.EventLog() {
				if e.Op == "revert" {
					t.Fatal("the revert ran while a live holder had the start lease")
				}
			}
		})
	}
}

// Re-review R2-M2 and R3-M1: a restore of an older snapshot moves the VM to
// a new overlay, so a record that could not be brought along names a later
// snapshot's layer. The restore did happen and the VM runs: its running
// state is recorded all the same, the error says so and names safe
// actions — never "restore again", which would throw away what the VM has
// written since — and the daemon keeps trying to record the path itself.
func TestRestoreSnapshot_AnUnrecordedDiskPathStillRecordsTheRunningVM(t *testing.T) {
	oldEvery, oldFor := pathRecordRetryEvery, pathRecordRetryFor
	pathRecordRetryEvery, pathRecordRetryFor = 20*time.Millisecond, 10*time.Second
	t.Cleanup(func() { pathRecordRetryEvery, pathRecordRetryFor = oldEvery, oldFor })

	s := lockTestServer(t)
	fake := seedRestorableVM(t, s, "disk")
	if err := corrosion.UpdateVMState(adminCtx(), s.db, "rs", "stopped", ""); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertHost(adminCtx(), s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	fake.OnRevertSnapshot = func(domain, snap string) {
		fake.SetFailDomainDiskSources(func(string) error { return errors.New("libvirt connection lost") })
	}
	_, err := s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "rs", SnapshotName: "s1"})
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "disk path") {
		t.Fatalf("RestoreSnapshot = %v, want an error saying the disk path was not recorded", err)
	}
	msg := err.Error()
	if strings.Contains(msg, "again") || !strings.Contains(msg, "lv inspect rs") || !strings.Contains(msg, "lv snapshot create rs") {
		t.Errorf("the error does not name only safe actions: %s", msg)
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "rs"); vm == nil || vm.State != "running" {
		t.Fatalf("the restored VM is recorded %v, want running", vm)
	}
	// Once libvirt answers again, the daemon records the path itself.
	fake.SetFailDomainDiskSources(nil)
	deadline := time.Now().Add(5 * time.Second)
	for {
		evs, _ := corrosion.ListVMEvents(adminCtx(), s.db, "rs", 50, "")
		found := false
		for _, e := range evs {
			if e.Type == "snapshot.restore-path-recorded" {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the daemon did not record the path after libvirt answered again; events %+v", evs)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A refused restore says so in the daemon's log at WARN, not only to the
// caller: the lab found a refusal nothing on the host recorded.
func TestRestoreSnapshot_ARefusalIsLoggedAtWarn(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	s := lockTestServer(t)
	seedRestorableVM(t, s, "disk")
	if h, err := health.TryVMStartLease(adminCtx(), s.db, s.hostName, "rs", time.Now()); err != nil || h != s.hostName {
		t.Fatalf("setup: lease %q %v", h, err)
	}
	if _, err := s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "rs", SnapshotName: "s1"}); err == nil {
		t.Fatal("the restore went ahead under a live start lease")
	}
	log := buf.String()
	if !strings.Contains(log, "level=WARN") || !strings.Contains(log, "vm=rs") || !strings.Contains(log, "snapshot=s1") {
		t.Fatalf("no WARN naming the VM and snapshot in the log:\n%s", log)
	}
}

// Re-review R4-M4: the background disk-path retry writes this host's live
// paths into the VM's replicated record, so it must stop — touching
// nothing — once this host no longer owns the VM: moved to another host
// (a failover in the retry window, with a stale domain still here),
// deleted, or this host fenced.
func TestRestoreSnapshot_TheBackgroundPathRetryStopsWhenTheVMIsNotHere(t *testing.T) {
	for _, tc := range []string{"moved", "deleted", "this host fenced"} {
		t.Run(tc, func(t *testing.T) {
			oldEvery, oldFor := pathRecordRetryEvery, pathRecordRetryFor
			pathRecordRetryEvery, pathRecordRetryFor = 20*time.Millisecond, 600*time.Millisecond
			t.Cleanup(func() { pathRecordRetryEvery, pathRecordRetryFor = oldEvery, oldFor })

			s := lockTestServer(t)
			fake := seedRestorableVM(t, s, "disk")
			if err := corrosion.InsertHost(adminCtx(), s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.1", State: "active"}); err != nil {
				t.Fatal(err)
			}
			const recorded = "/var/lib/litevirt/disks/rs-root.qcow2"
			if err := corrosion.InsertDisk(adminCtx(), s.db, corrosion.DiskRecord{VMName: "rs", DiskName: "root", HostName: s.hostName,
				Path: recorded, StorageType: "local", DeviceKind: "disk", DeleteWithVM: true}); err != nil {
				t.Fatal(err)
			}
			fake.OnRevertSnapshot = func(domain, snap string) {
				fake.SetFailDomainDiskSources(func(string) error { return errors.New("libvirt connection lost") })
			}
			if _, err := s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "rs", SnapshotName: "s1"}); err == nil {
				t.Fatal("setup: the restore recorded the path")
			}
			switch tc {
			case "moved":
				if err := corrosion.UpdateVMHost(adminCtx(), s.db, "rs", "host-b", "running"); err != nil {
					t.Fatal(err)
				}
			case "deleted":
				if err := corrosion.DeleteVM(adminCtx(), s.db, "rs"); err != nil {
					t.Fatal(err)
				}
			case "this host fenced":
				if err := corrosion.UpdateHostState(adminCtx(), s.db, s.hostName, "fenced"); err != nil {
					t.Fatal(err)
				}
			}
			fake.SetFailDomainDiskSources(nil) // the live sources would now be read and recorded
			time.Sleep(900 * time.Millisecond)
			evs, _ := corrosion.ListVMEvents(adminCtx(), s.db, "rs", 50, "")
			for _, e := range evs {
				if e.Type == "snapshot.restore-path-recorded" {
					t.Fatalf("the retry recorded the path of a VM this host no longer owns (%s)", tc)
				}
			}
			if tc != "deleted" {
				if d, _ := corrosion.GetVMDisks(adminCtx(), s.db, "rs"); len(d) != 1 || d[0].Path != recorded {
					t.Fatalf("the retry wrote the record of a VM this host no longer owns: %+v", d)
				}
			}
		})
	}
}
