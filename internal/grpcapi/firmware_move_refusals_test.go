package grpcapi

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Entry refusals of a live firmware move (spec §6.9; T-17, T-18, T-19, T-25,
// T-30) on the D2-7 fake, with the guard wired over the host's own store as
// the daemon wires it. Each refused operation must leave the VM's
// definition, its NVRAM and its permall as they were, and must answer with
// the entry refusal (FailedPrecondition naming this host and the attempt),
// not with whatever the guard beneath happened to stop.

const frAttempt = "a7000000-0000-4000-8000-0000000000f4"

// frSpec is os1: Secure Boot + vTPM, UEFI, its uuid fwLiveUUID.
const frSpec = `{"name":"os1","cpu":1,"memory_mib":512,"secure_boot":true,"tpm":true,"firmware":"uefi","uuid":"` + fwLiveUUID + `"}`

type frFixture struct {
	t     *testing.T
	s     *Server
	fake  *libvirtfake.Fake
	store *lv.FirmwareStore
	recs  *fwmig.Records
	disk  string
}

// newFRFixture is "test-host" owning os1 (row in rowState, domain in dom)
// with a host-local disk, NVRAM "NV0" and permall "P0", and the firmware move
// guard wired. No record yet.
func newFRFixture(t *testing.T, rowState string, dom libvirtfake.State) *frFixture {
	t.Helper()
	s, fake := provableCreateServer(t)
	store := &lv.FirmwareStore{DataDir: s.dataDir, SwtpmBase: t.TempDir()}
	s.SetFirmwareStore(store)
	fake.SetFirmwareStore(store)
	setFWTestFirmwarePaths(t, s)
	s.db.MarkReplicaCaughtUpForTests("test")
	f := &frFixture{t: t, s: s, fake: fake, store: store, recs: fwmig.New(s.dataDir)}
	f.disk = filepath.Join(s.dataDir, "disks", "os1-root.qcow2")
	f.write(f.disk, "DISK")
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "os1", HostName: s.hostName, State: rowState,
		CPUActual: 1, MemActual: 512, Spec: frSpec}, nil,
		[]corrosion.DiskRecord{{VMName: "os1", DiskName: "root", HostName: s.hostName, Path: f.disk, StorageType: "local",
			TargetDev: "vda", SizeBytes: 1 << 20}}); err != nil {
		t.Fatal(err)
	}
	x := fwLiveDomainXML(fwLiveUUID, s.firmware.SecbootCode, store.NvramPath("os1"), true, "yes")
	if err := fake.DefineDomain(x); err != nil {
		t.Fatal(err)
	}
	fake.SetActiveXML("os1", x)
	fake.SetState("os1", dom)
	f.write(store.NvramPath("os1"), "NV0")
	f.write(f.permall(), "P0")
	fwmig.Wire(fake, store)
	return f
}

func (f *frFixture) write(p, body string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *frFixture) permall() string {
	return filepath.Join(f.store.SwtpmDir(fwLiveUUID), "tpm2", "tpm2-00.permall")
}

func (f *frFixture) createdAt() string {
	f.t.Helper()
	row, err := corrosion.GetVM(adminCtx(), f.s.db, "os1")
	if err != nil {
		f.t.Fatal(err)
	}
	if row == nil {
		return "2026-10-17T00:00:00Z"
	}
	return row.CreatedAt
}

// marker writes os1's source marker in phase (a parked phase parked from
// migrating).
func (f *frFixture) marker(phase fwmig.Phase) {
	f.t.Helper()
	m := fwmig.Marker{VM: "os1", Binding: fwmig.Binding{UUID: fwLiveUUID, CreatedAt: f.createdAt(), Attempt: frAttempt},
		Target: "dst-host", Route: fwmig.RouteTunnelled, Phase: fwmig.PhaseMigrating, TPM: true, UEFI: true, Since: time.Now().UTC()}
	if phase.Parked() {
		var err error
		if m, err = m.Park(phase); err != nil {
			f.t.Fatal(err)
		}
	} else {
		m.Phase = phase
	}
	if err := f.recs.PutMarker(m); err != nil {
		f.t.Fatal(err)
	}
}

// hold writes os1's target hold in state.
func (f *frFixture) hold(state fwmig.HoldState) {
	f.t.Helper()
	h := fwmig.Hold{VM: "os1", Binding: fwmig.Binding{UUID: fwLiveUUID, CreatedAt: f.createdAt(), Attempt: frAttempt},
		Source: "src-host", Since: time.Now().UTC(), State: state, TPM: true, UEFI: true, NvramMaterialised: fwmig.NvramDone}
	if err := f.recs.PutHold(h); err != nil {
		f.t.Fatal(err)
	}
}

// requireKept: os1 still defined in state dom, NVRAM, permall and disk
// byte-unchanged.
func (f *frFixture) requireKept(dom libvirtfake.State) {
	f.t.Helper()
	if st, ok := f.fake.RawState("os1"); !ok || st != dom {
		f.t.Fatalf("os1 is %q (defined %v), want %q kept", st, ok, dom)
	}
	for p, want := range map[string]string{f.store.NvramPath("os1"): "NV0", f.permall(): "P0", f.disk: "DISK"} {
		if b, err := os.ReadFile(p); err != nil || string(b) != want {
			f.t.Fatalf("%s = %q, %v; want %q kept", p, b, err, want)
		}
	}
}

// requireEntryRefusal: err is the §6.9 entry refusal, naming this host and
// the attempt.
func (f *frFixture) requireEntryRefusal(err error) {
	f.t.Helper()
	if status.Code(err) != codes.FailedPrecondition {
		f.t.Fatalf("err = %v (%v), want the FailedPrecondition entry refusal", err, status.Code(err))
	}
	msg := status.Convert(err).Message()
	for _, w := range []string{"refused on " + f.s.hostName, frAttempt} {
		if !strings.Contains(msg, w) {
			f.t.Fatalf("refusal %q does not name %q", msg, w)
		}
	}
}

// frSite is one operation an entry refusal stops.
type frSite struct {
	name     string
	rowState string
	dom      libvirtfake.State
	call     func(f *frFixture) error
}

func frSites() []frSite {
	ctx := adminCtx()
	return []frSite{
		{"start", "stopped", libvirtfake.StateShutdown, func(f *frFixture) error {
			_, err := f.s.StartVM(ctx, &pb.StartVMRequest{Name: "os1"})
			return err
		}},
		{"restart", "running", libvirtfake.StateRunning, func(f *frFixture) error {
			_, err := f.s.RestartVM(ctx, &pb.RestartVMRequest{Name: "os1"})
			return err
		}},
		{"delete", "stopped", libvirtfake.StateShutdown, func(f *frFixture) error {
			_, err := f.s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "os1"})
			return err
		}},
		{"rebuild", "stopped", libvirtfake.StateShutdown, func(f *frFixture) error {
			_, err := f.s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "os1"})
			return err
		}},
		{"update", "stopped", libvirtfake.StateShutdown, func(f *frFixture) error {
			_, err := f.s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "os1", Cpu: 2})
			return err
		}},
		{"resize_disk", "stopped", libvirtfake.StateShutdown, func(f *frFixture) error {
			_, err := f.s.ResizeDisk(ctx, &pb.ResizeDiskRequest{VmName: "os1", DiskName: "root", Size: "2G"})
			return err
		}},
		{"snapshot", "stopped", libvirtfake.StateShutdown, func(f *frFixture) error {
			_, err := f.s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "os1", Name: "s1"})
			return err
		}},
		{"snapshot_restore", "stopped", libvirtfake.StateShutdown, func(f *frFixture) error {
			_, err := f.s.RestoreSnapshot(ctx, &pb.RestoreSnapshotRequest{VmName: "os1", SnapshotName: "s1"})
			return err
		}},
		{"clone_source", "stopped", libvirtfake.StateShutdown, func(f *frFixture) error {
			_, err := f.s.CloneVM(ctx, &pb.CloneVMRequest{Source: "os1", Target: "os1-copy"})
			return err
		}},
		{"backup", "running", libvirtfake.StateRunning, func(f *frFixture) error {
			return f.s.BackupSnapshot(&pb.BackupSnapshotRequest{VmName: "os1", RepoPath: f.t.TempDir()},
				&progressStream[pb.BackupSnapshotProgress]{ctx: ctx})
		}},
		// An in-place restore overwrites the VM's own stopped disk from a
		// backup in a repo that has a manifest of it (D2-14 review m-2).
		{"backup_restore_in_place", "stopped", libvirtfake.StateShutdown, func(f *frFixture) error {
			const ts = "2026-10-17T09:00:00Z"
			repoDir := filepath.Join(f.t.TempDir(), "repo")
			repo, err := pbsstore.Init(repoDir)
			if err != nil {
				return err
			}
			// A real image, so a restore that went on would replace the disk.
			img := filepath.Join(f.t.TempDir(), "os1-root.qcow2")
			if err := qcow2.Create(img, 1<<20, nil); err != nil {
				return err
			}
			body, err := os.ReadFile(img)
			if err != nil {
				return err
			}
			if _, err := pbsstore.PushDisk(ctx, repo, bytes.NewReader(body), pbsstore.PushOptions{
				VMName: "os1", DiskName: "root", Timestamp: ts, ContentFormat: pbsstore.ContentDiskFile,
			}); err != nil {
				return err
			}
			f.s.SetBackupRepos(map[string]string{"r": repoDir})
			return f.s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
				RepoPath: "r", VmName: "os1", DiskName: "root", Timestamp: ts, InPlace: true,
			}, &progressStream[pb.RestoreFromBackupProgress]{ctx: ctx})
		}},
		{"reconcile_definition", "stopped", libvirtfake.StateShutdown, func(f *frFixture) error {
			row, err := corrosion.GetVM(ctx, f.s.db, "os1")
			if err != nil {
				return err
			}
			return f.s.reconcileDomainDefinition(ctx, row, nil)
		}},
	}
}

// T-19 (grpcapi), with T-18's start paths: every operation §6.9 refuses at
// its entry, under a source marker (in progress and parked) and a target
// hold, answers with the entry refusal and leaves the domain, its NVRAM, its
// permall and its disk as they were.
//
// Mutations, per site: remove that site's entry refusal — red (the answer is
// the guard's, or the operation's own, not the entry refusal; RebuildVM and
// the redefine also lose state with the guard removed too); remove the guard
// AND that entry refusal — red.
func TestFirmwareMarker_SitesLeaveState(t *testing.T) {
	type rec struct {
		name string
		put  func(f *frFixture)
	}
	recs := []rec{
		{"marker_migrating", func(f *frFixture) { f.marker(fwmig.PhaseMigrating) }},
		{"marker_target_unreachable", func(f *frFixture) { f.marker(fwmig.PhaseTargetUnreachable) }},
		{"marker_cleaning", func(f *frFixture) { f.marker(fwmig.PhaseCleaning) }},
		{"hold_verified", func(f *frFixture) { f.hold(fwmig.HoldVerified) }},
		{"hold_released_unconfirmed", func(f *frFixture) { f.hold(fwmig.HoldReleasedUnconfirmed) }},
	}
	for _, site := range frSites() {
		t.Run(site.name, func(t *testing.T) {
			for _, r := range recs {
				t.Run(r.name, func(t *testing.T) {
					f := newFRFixture(t, site.rowState, site.dom)
					r.put(f)
					f.requireEntryRefusal(site.call(f))
					f.requireKept(site.dom)
				})
			}
		})
	}
}

// T-19 (grpcapi), create-same-name, and the clone's target name: a name a
// target hold holds here (its row gone on the source: a delete raced the
// move) is not taken by a new domain, whose create would first undefine the
// held one (probe (g) deletes its NVRAM) and then define over it.
//
// Mutations: remove the create's name refusal — red; remove it AND the
// guard — red (the NVRAM goes); remove the clone's target-name refusal — red.
func TestFirmwareHold_NameRefusals(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		f := newFRFixture(t, "stopped", libvirtfake.StatePaused)
		f.hold(fwmig.HoldPrepared)
		if err := corrosion.DeleteVM(adminCtx(), f.s.db, "os1"); err != nil {
			t.Fatal(err)
		}
		req := disklessCreateRequest("os1")
		req.Spec.Placement = &pb.PlacementSpec{Host: f.s.hostName}
		_, err := f.s.CreateVM(adminCtx(), req)
		f.requireEntryRefusal(err)
		if b, rerr := os.ReadFile(f.store.NvramPath("os1")); rerr != nil || string(b) != "NV0" {
			t.Fatalf("the held NVRAM = %q, %v; want NV0 kept", b, rerr)
		}
		if st, ok := f.fake.RawState("os1"); !ok || st != libvirtfake.StatePaused {
			t.Fatalf("the held domain is %q (defined %v), want paused", st, ok)
		}
	})
	t.Run("clone_target", func(t *testing.T) {
		f := newFRFixture(t, "stopped", libvirtfake.StatePaused)
		f.hold(fwmig.HoldPrepared)
		if err := corrosion.DeleteVM(adminCtx(), f.s.db, "os1"); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertVM(adminCtx(), f.s.db, corrosion.VMRecord{Name: "plain", HostName: f.s.hostName, State: "stopped",
			Spec: `{"name":"plain","cpu":1,"memory_mib":512}`}, nil, nil); err != nil {
			t.Fatal(err)
		}
		_, err := f.s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "plain", Target: "os1"})
		f.requireEntryRefusal(err)
	})
}

// T-30. StopVM refuses a VM a source marker or a target hold names here,
// naming the move and what resolves it; the domain keeps running.
//
// Mutation: remove the record check — red.
func TestStopVM_RefusesFirmwareMove(t *testing.T) {
	for name, put := range map[string]func(f *frFixture){
		"marker_migrating":          func(f *frFixture) { f.marker(fwmig.PhaseMigrating) },
		"marker_target_ran":         func(f *frFixture) { f.marker(fwmig.PhaseTargetRan) },
		"hold_verified":             func(f *frFixture) { f.hold(fwmig.HoldVerified) },
		"hold_released_unconfirmed": func(f *frFixture) { f.hold(fwmig.HoldReleasedUnconfirmed) },
	} {
		t.Run(name, func(t *testing.T) {
			for _, force := range []bool{false, true} {
				f := newFRFixture(t, "running", libvirtfake.StateRunning)
				put(f)
				_, err := f.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "os1", Force: force})
				f.requireEntryRefusal(err)
				if msg := status.Convert(err).Message(); !strings.Contains(msg, "`lv doctor firmware-move os1`") {
					t.Fatalf("refusal %q does not name what resolves it", msg)
				}
				f.requireKept(libvirtfake.StateRunning)
			}
		})
	}
}

// T-30. A VM no record names stops exactly as before — one in `migrating`
// included (a non-firmware live migration's source): StopVM is scoped to
// firmware moves, not to the row state.
//
// Mutation: refuse every `migrating` row — red.
func TestStopVM_NonFirmwareMigratingUnchanged(t *testing.T) {
	for _, state := range []string{"migrating", "running"} {
		t.Run(state, func(t *testing.T) {
			s, fake := provableCreateServer(t)
			store := &lv.FirmwareStore{DataDir: s.dataDir, SwtpmBase: t.TempDir()}
			s.SetFirmwareStore(store)
			fake.SetFirmwareStore(store)
			fwmig.Wire(fake, store)
			insertTestVMWithSpec(t, adminCtx(), s.db, "plain", s.hostName, state, `{"name":"plain"}`)
			fake.SetState("plain", libvirtfake.StateRunning)
			if _, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "plain", Force: true}); err != nil {
				t.Fatalf("StopVM of a %s VM no firmware move names: %v", state, err)
			}
			if st, _ := fake.RawState("plain"); st == libvirtfake.StateRunning {
				t.Fatal("the VM is still running after its stop")
			}
		})
	}
}

// T-17 (grpcapi, non-NIC paths): a held target guest — the row names this
// host after the commit — is not stopped, restarted, shut down with the
// host's workloads, or backed up, in each hold state its guest can be in.
//
// Mutation: remove one check (StopVM's, RestartVM's, the backup's) — red.
func TestHeldFirmwareGuest_NoResumeOrStopPath(t *testing.T) {
	for _, c := range []struct {
		state fwmig.HoldState
		dom   libvirtfake.State
	}{
		{fwmig.HoldVerified, libvirtfake.StatePaused},
		{fwmig.HoldResuming, libvirtfake.StatePaused},
		{fwmig.HoldReleasedUnconfirmed, libvirtfake.StateRunning},
	} {
		t.Run(string(c.state), func(t *testing.T) {
			ctx := adminCtx()
			for name, call := range map[string]func(f *frFixture) error{
				"stop": func(f *frFixture) error {
					_, err := f.s.StopVM(ctx, &pb.StopVMRequest{Name: "os1", Force: true})
					return err
				},
				"restart": func(f *frFixture) error {
					_, err := f.s.RestartVM(ctx, &pb.RestartVMRequest{Name: "os1"})
					return err
				},
				"backup": func(f *frFixture) error {
					return f.s.BackupSnapshot(&pb.BackupSnapshotRequest{VmName: "os1", RepoPath: f.t.TempDir()},
						&progressStream[pb.BackupSnapshotProgress]{ctx: ctx})
				},
			} {
				t.Run(name, func(t *testing.T) {
					f := newFRFixture(t, "running", c.dom)
					f.hold(c.state)
					f.requireEntryRefusal(call(f))
					f.requireKept(c.dom)
				})
			}
			t.Run("shutdown_workloads", func(t *testing.T) {
				f := newFRFixture(t, "running", c.dom)
				f.hold(c.state)
				stream := &mockShutdownStream{ctx: ctx}
				if err := f.s.ShutdownHostWorkloads(&pb.ShutdownHostWorkloadsRequest{Name: f.s.hostName}, stream); err != nil {
					t.Fatalf("ShutdownHostWorkloads: %v", err)
				}
				reported := false
				for _, p := range stream.sent {
					if p.VmName == "os1" && p.Status == "error" && strings.Contains(p.Error, frAttempt) {
						reported = true
					}
				}
				if !reported {
					t.Fatalf("the held guest was not reported as refused: %+v", stream.sent)
				}
				f.requireKept(c.dom)
			})
		})
	}
}

// T-25. The movers that live-migrate without the live firmware move — the
// rebalancer, the health-check migrate action, CrossRegionMigrate's live
// move — refuse a Secure Boot / vTPM VM (spec §1, §12); a plain VM goes on.
//
// Mutation: remove a mover's refusal — its sub-test goes red.
func TestRebalanceExecutor_SkipsFirmwareVM(t *testing.T) {
	for _, c := range []struct {
		name, spec string
		skipped    bool
	}{
		{"secure_boot_tpm", `{"secure_boot":true,"tpm":true,"firmware":"uefi"}`, true},
		{"tpm", `{"tpm":true}`, true},
		{"plain_control", `{}`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := testServerR2(t)
			ctx := adminContext(context.Background())
			insertTestHostR2(t, ctx, s.db, "src", "active")
			insertTestHostR2(t, ctx, s.db, "dst", "active")
			insertTestVMR2WithSpec(t, ctx, s.db, "vm-a", "src", "running", c.spec)
			insertProposal(t, ctx, s.db, "p1", "vm-a", "src", "dst", "approved")
			called := make(chan struct{}, 1)
			e := NewRebalanceExecutor(s, "exec-host", s.db)
			e.migrateOverride = func(context.Context, string, string) error { called <- struct{}{}; return nil }
			e.RunOnce(ctx)
			if !c.skipped {
				eventually(t, func() bool { st, _, _ := proposalStatus(t, ctx, s.db, "p1"); return st == "applied" })
				return
			}
			st, detail, _ := proposalStatus(t, ctx, s.db, "p1")
			if st != "failed" || !strings.Contains(detail, "Secure Boot / vTPM") {
				t.Fatalf("proposal %s (%q), want failed naming the firmware VM", st, detail)
			}
			select {
			case <-called:
				t.Fatal("the rebalancer migrated a firmware VM")
			default:
			}
		})
	}
}

func TestMigrateVMForHealthCheck_RefusesFirmwareVM(t *testing.T) {
	f := newFRFixture(t, "running", libvirtfake.StateRunning)
	err := f.s.MigrateVMForHealthCheck(context.Background(), "os1", "dst-host")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "health-check migrate action") {
		t.Fatalf("err = %v, want the health-check mover's refusal", err)
	}
	f.requireKept(libvirtfake.StateRunning)
	if row, _ := corrosion.GetVM(adminCtx(), f.s.db, "os1"); row == nil || row.State != "running" {
		t.Fatalf("row %+v, want running untouched", row)
	}
	// A plain VM is not refused by it (it fails later, on its own terms).
	insertTestVMWithSpec(t, adminCtx(), f.s.db, "plain", f.s.hostName, "running", `{"name":"plain"}`)
	if err := f.s.MigrateVMForHealthCheck(context.Background(), "plain", "dst-host"); err != nil &&
		strings.Contains(err.Error(), "health-check migrate action") {
		t.Fatalf("a plain VM was refused as a firmware VM: %v", err)
	}
}

func TestCrossRegionMigrate_RefusesLiveFirmwareVM(t *testing.T) {
	f := newFRFixture(t, "running", libvirtfake.StateRunning)
	ctx := adminCtx()
	if err := corrosion.InsertHost(ctx, f.s.db, corrosion.HostRecord{Name: "far", Address: "10.9.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostRegion(ctx, f.s.db, "far", "us"); err != nil {
		t.Fatal(err)
	}
	err := f.s.CrossRegionMigrate(&pb.CrossRegionMigrateRequest{VmName: "os1", TargetHost: "far", Live: true},
		&progressStream[pb.MigrateProgress]{ctx: ctx})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "CrossRegionMigrate does not live-migrate") {
		t.Fatalf("err = %v, want CrossRegionMigrate's firmware refusal", err)
	}
	f.requireKept(libvirtfake.StateRunning)
}

// More §6.9 entries: promote, cutover, and the name a restore-as or an
// import would take. A name refusal matters where a record holds the name
// with no domain (a prepared hold whose domain has not arrived, a cleaning
// marker past its undefine): a defined domain of the name is refused by those
// paths already.
//
// Mutation: remove that entry's refusal — its sub-test goes red.
func TestFirmwareMove_MoreEntryRefusals(t *testing.T) {
	ctx := adminCtx()
	t.Run("promote", func(t *testing.T) {
		f := newFRFixture(t, "stopped", libvirtfake.StateShutdown)
		f.marker(fwmig.PhaseSourceStateSuspect)
		row, _ := corrosion.GetVM(ctx, f.s.db, "os1")
		f.requireEntryRefusal(f.s.doPromoteLocal(ctx, &pb.PromoteReplicaRequest{VmName: "os1"}, row, nil, "", "", false,
			func(*pb.PromoteReplicaProgress) error { return nil }))
		f.requireKept(libvirtfake.StateShutdown)
	})
	t.Run("cutover", func(t *testing.T) {
		f := newFRFixture(t, "running", libvirtfake.StateRunning)
		enableVMReplace(f.s)
		insertTestVMWithSpec(t, ctx, f.s.db, "os1-next", f.s.hostName, "running", `{"name":"os1-next"}`)
		f.marker(fwmig.PhaseTargetRan)
		_, err := f.s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "os1"})
		f.requireEntryRefusal(err)
		f.requireKept(libvirtfake.StateRunning)
	})
	// noDomain: os1's row and domain are gone; a prepared hold still holds
	// the name and its materialised NVRAM.
	noDomain := func(t *testing.T) *frFixture {
		f := newFRFixture(t, "stopped", libvirtfake.StateShutdown)
		f.hold(fwmig.HoldPrepared)
		if err := corrosion.DeleteVM(ctx, f.s.db, "os1"); err != nil {
			t.Fatal(err)
		}
		f.fake.VanishDomain("os1")
		return f
	}
	keptNvram := func(t *testing.T, f *frFixture) {
		if b, err := os.ReadFile(f.store.NvramPath("os1")); err != nil || string(b) != "NV0" {
			t.Fatalf("the held NVRAM = %q, %v; want NV0 kept", b, err)
		}
		if f.fake.DomainExists("os1") {
			t.Fatal("a domain was defined under a name a hold holds")
		}
	}
	t.Run("restore_as", func(t *testing.T) {
		f := noDomain(t)
		_, _, err := f.s.autoDefineRestoredVM(ctx, &pb.RestoreLiveRequest{VmName: "os1",
			Spec: &pb.VMSpec{Name: "os1", Cpu: 1, MemoryMib: 512}}, nil, &pbsstore.Manifest{}, "", "default",
			func(*pb.RestoreLiveProgress) error { return nil })
		f.requireEntryRefusal(err)
		keptNvram(t, f)
	})
	t.Run("import", func(t *testing.T) {
		f := noDomain(t)
		err := f.s.ImportVM(&fakeImportStream{ctx: ctx, frames: []*pb.ImportVMRequest{{Name: "os1"}}})
		f.requireEntryRefusal(err)
		keptNvram(t, f)
	})
}

// §6.9: a scheduled backup and a scheduled replication skip a VM a record
// names here, with a log line, and report the run as neither a success nor a
// failure; an unmarked VM's run goes ahead as before.
//
// Mutations: remove the scheduled backup's skips (both: the second is the
// same check under the VM lock) — red; remove the replication's skip — red.
func TestFirmwareMove_ScheduledJobsSkip(t *testing.T) {
	ctx := adminCtx()
	for _, marked := range []bool{true, false} {
		name := map[bool]string{true: "marked", false: "unmarked_control"}[marked]
		t.Run("backup/"+name, func(t *testing.T) {
			f := newFRFixture(t, "running", libvirtfake.StateRunning)
			if marked {
				f.marker(fwmig.PhaseTargetUnreachable)
			}
			r := BackupRunnerForScheduler(f.s, map[string]string{"r1": t.TempDir()})
			err := r.RunBackup(ctx, corrosion.BackupScheduleRecord{VMName: "os1", Repo: "r1", Scope: "vm"}, time.Now())
			evs, _ := corrosion.ListVMEvents(ctx, f.s.db, "os1", 50, "")
			started := false
			for _, e := range evs {
				if e.Type == "backup.started" {
					started = true
				}
			}
			if !marked {
				if !started {
					t.Fatalf("control: an unmarked VM's scheduled backup did not start (%v)", err)
				}
				return
			}
			if err != nil || started {
				t.Fatalf("a marked VM's scheduled backup: err=%v started=%v, want skipped quietly", err, started)
			}
			f.requireKept(libvirtfake.StateRunning)
		})
		t.Run("replication/"+name, func(t *testing.T) {
			f := newFRFixture(t, "running", libvirtfake.StateRunning)
			if marked {
				f.marker(fwmig.PhaseTargetUnreachable)
			}
			err := f.s.RunReplication(ctx, corrosion.BackupScheduleRecord{VMName: "os1", Repo: "p1", TargetPool: "p1",
				Type: "replication", Scope: "vm"}, time.Now())
			if !marked {
				if err == nil {
					t.Fatal("control: an unmarked VM's replication to a pool that does not exist reported success")
				}
				return
			}
			if err != nil {
				t.Fatalf("a marked VM's scheduled replication: %v, want skipped quietly", err)
			}
			f.requireKept(libvirtfake.StateRunning)
		})
	}
}

// D2-14 review I-1 (spec §6.9, §9): no migration of a VM a live firmware
// move's marker names here, whatever the strategy. Under a parked move whose
// source guest was shut down from inside (the stop sync records `stopped`),
// a cold move would hand the row to a third host, cut off from the move's
// records and their start veto. Drain's cold path enters the same way.
//
// Mutation: remove the refusal at migrateOwnedVM's entry — red.
func TestMigrateVM_ColdRefusedUnderMarker(t *testing.T) {
	ctx := adminCtx()
	for _, phase := range []fwmig.Phase{fwmig.PhaseTargetRan, fwmig.PhaseTargetUnreachable} {
		t.Run(string(phase)+"/migrate_cold", func(t *testing.T) {
			f := newFRFixture(t, "stopped", libvirtfake.StateShutdown)
			if err := corrosion.InsertHost(ctx, f.s.db, corrosion.HostRecord{Name: "dst-host", Address: "10.0.0.2", State: "active",
				CPUTotal: 8, MemTotal: 16384}); err != nil {
				t.Fatal(err)
			}
			f.marker(phase)
			err := f.s.MigrateVM(&pb.MigrateVMRequest{VmName: "os1", TargetHost: "dst-host", Strategy: pb.MigrateStrategy_MIGRATE_COLD},
				&progressStream[pb.MigrateProgress]{ctx: ctx})
			f.requireEntryRefusal(err)
			f.requireKept(libvirtfake.StateShutdown)
			if row, _ := corrosion.GetVM(ctx, f.s.db, "os1"); row == nil || row.HostName != f.s.hostName || row.State != "stopped" {
				t.Fatalf("row %+v, want stopped on %s", row, f.s.hostName)
			}
		})
		t.Run(string(phase)+"/drain_cold", func(t *testing.T) {
			f := newFRFixture(t, "stopped", libvirtfake.StateShutdown)
			dst := corrosion.HostRecord{Name: "dst-host", Address: "10.0.0.2", State: "active", CPUTotal: 8, MemTotal: 16384}
			if err := corrosion.InsertHost(ctx, f.s.db, dst); err != nil {
				t.Fatal(err)
			}
			f.marker(phase)
			row, _ := corrosion.GetVM(ctx, f.s.db, "os1")
			adopted := false
			p := f.s.drainStoppedVM(ctx, row, dst, func() {}, &adopted)
			if p.Status != "failed" || !strings.Contains(p.Error, "refused on "+f.s.hostName) || !strings.Contains(p.Error, frAttempt) {
				t.Fatalf("drain progress %+v, want failed with the entry refusal", p)
			}
			f.requireKept(libvirtfake.StateShutdown)
		})
	}
	// An unmarked firmware VM's cold move is not stopped by this refusal (it
	// goes on, and fails or not on its own terms).
	t.Run("unmarked_control", func(t *testing.T) {
		f := newFRFixture(t, "stopped", libvirtfake.StateShutdown)
		err := f.s.MigrateVM(&pb.MigrateVMRequest{VmName: "os1", TargetHost: "dst-host", Strategy: pb.MigrateStrategy_MIGRATE_COLD},
			&progressStream[pb.MigrateProgress]{ctx: ctx})
		if err != nil && strings.Contains(status.Convert(err).Message(), "refused on "+f.s.hostName) {
			t.Fatalf("an unmarked VM's cold move was refused as a firmware move: %v", err)
		}
	})
}

// D2-14 review m-1: CutoverVM refuses when the record names the replacement
// (-next) VM, not only the replaced one.
//
// Mutation: remove the -next check — red.
func TestCutoverVM_RefusesRecordOnNext(t *testing.T) {
	ctx := adminCtx()
	f := newFRFixture(t, "running", libvirtfake.StateRunning)
	enableVMReplace(f.s)
	const nextUUID = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
	insertTestVMWithSpec(t, ctx, f.s.db, "os1-next", f.s.hostName, "running", `{"name":"os1-next","uuid":"`+nextUUID+`"}`)
	h := fwmig.Hold{VM: "os1-next", Binding: fwmig.Binding{UUID: nextUUID, CreatedAt: "2026-10-17T00:00:00Z", Attempt: frAttempt},
		Source: "src-host", Since: time.Now().UTC(), State: fwmig.HoldReleasedUnconfirmed, TPM: true, UEFI: true,
		NvramMaterialised: fwmig.NvramDone}
	if err := f.recs.PutHold(h); err != nil {
		t.Fatal(err)
	}
	_, err := f.s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "os1"})
	f.requireEntryRefusal(err)
	f.requireKept(libvirtfake.StateRunning)
}
