package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Live firmware (Secure Boot + vTPM) migration scenarios over real gRPC and
// the D2-7 fake (spec §15, Fleet: F-1, F-2, F-2b, F-4, F-9). Each node has a
// firmware store of its own, the fake models what libvirt did to the state
// in the probes, and every scenario checks that the guest runs on at most
// one host at every moment.

const (
	fwliveVM   = "fwlivesc"
	fwliveUUID = "3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f"
)

var (
	fwlivePermall = []byte("fwlivesc's TPM state")
	fwliveNvram   = []byte("fwlivesc's UEFI vars")
)

// fwliveScene is two nodes, src running fwlivesc (Secure Boot + vTPM) with
// its firmware state in src's store, dst labelled for a live firmware move,
// one firmware layout, and src's migrations landing on dst.
type fwliveScene struct {
	c        *Cluster
	src, dst *Node
	// disk is the host-local disk's path when the VM has one (a storage
	// copy), else "".
	disk string
}

func fwliveSetup(t *testing.T, withDisk bool) *fwliveScene {
	t.Helper()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	src, dst := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	setHostCapacity(t, c, src.Name, 64, 65536)
	setHostCapacity(t, c, dst.Name, 64, 65536)
	layout := filepath.Join(c.tmpRoot, "layout")
	for _, n := range c.Nodes {
		n.Server.SetFirmwareLayoutDirForTest(layout)
	}
	for _, l := range []string{corrosion.LabelTPMCapable, corrosion.LabelSecureBootCapable, corrosion.LabelFwLiveMigrate} {
		if err := corrosion.SetHostLabel(ctx, src.DB, dst.Name, l, "true"); err != nil {
			t.Fatal(err)
		}
	}
	spec, err := json.Marshal(&pb.VMSpec{Name: fwliveVM, Cpu: 1, MemoryMib: 256, SecureBoot: true, Tpm: true, Firmware: "uefi", Uuid: fwliveUUID})
	if err != nil {
		t.Fatal(err)
	}
	sc := &fwliveScene{c: c, src: src, dst: dst}
	var disks []corrosion.DiskRecord
	if withDisk {
		// Both hosts can encrypt the copy (a storage copy carries the TPM
		// state and has no plaintext fallback).
		migrationTLSReady(src, true)
		migrationTLSReady(dst, true)
		sc.disk = filepath.Join(c.tmpRoot, dst.Name, "data", "disks", fwliveVM+"-root.qcow2")
		disks = []corrosion.DiskRecord{{VMName: fwliveVM, DiskName: "root", HostName: src.Name, Path: sc.disk,
			SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda"}}
	}
	if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{Name: fwliveVM, HostName: src.Name, State: "running",
		Spec: string(spec), CPUActual: 1, MemActual: 256}, nil, disks); err != nil {
		t.Fatal(err)
	}
	x := "<domain type='kvm'><name>" + fwliveVM + "</name><uuid>" + fwliveUUID + "</uuid><os><type>hvm</type>" +
		"<loader readonly='yes' secure='yes' type='pflash'>/usr/share/OVMF/OVMF_CODE.secboot.fd</loader>" +
		"<nvram>" + src.FW.NvramPath(fwliveVM) + "</nvram></os><devices>" +
		"<tpm model='tpm-crb'><backend type='emulator' version='2.0' persistent_state='yes'/></tpm></devices></domain>"
	src.Virt.SetInactiveXML(fwliveVM, x)
	src.Virt.SetActiveXML(fwliveVM, x)
	src.Virt.SetState(fwliveVM, libvirtfake.StateRunning)
	hlWrite(t, fwlivePermallPath(src), fwlivePermall)
	hlWrite(t, src.FW.NvramPath(fwliveVM), fwliveNvram)
	src.LandMigrationsOn(dst)
	return sc
}

func fwlivePermallPath(n *Node) string {
	return filepath.Join(n.FW.SwtpmDir(fwliveUUID), "tpm2", "tpm2-00.permall")
}

// migrate runs `lv migrate fwlivesc <dst>` on src (live, a storage copy when
// the VM has a disk) and returns its terminal error.
func (sc *fwliveScene) migrate(t *testing.T) error {
	t.Helper()
	st, err := sc.c.SelfClient(sc.src).MigrateVM(context.Background(), &pb.MigrateVMRequest{
		VmName: fwliveVM, TargetHost: sc.dst.Name, Strategy: pb.MigrateStrategy_MIGRATE_LIVE, WithStorage: sc.disk != "",
	})
	if err != nil {
		return err
	}
	for {
		if _, err := st.Recv(); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
	}
}

// fwliveOneCopy samples both fakes every millisecond for the whole scenario
// and fails the test if the guest is ever running on both hosts, or running
// on one while the other's guest is not shut off or absent: one copy of the
// VM at every moment. Its stop func ends the sampling and reports.
func fwliveOneCopy(t *testing.T, a, b *Node) (stop func()) {
	t.Helper()
	done := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var seen []string
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			sa, _ := a.Virt.RawState(fwliveVM)
			sb, _ := b.Virt.RawState(fwliveVM)
			if sa == libvirtfake.StateRunning && sb == libvirtfake.StateRunning {
				mu.Lock()
				if len(seen) < 3 {
					seen = append(seen, string(sa)+"/"+string(sb))
				}
				mu.Unlock()
			}
			select {
			case <-done:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	return func() {
		close(done)
		wg.Wait()
		mu.Lock()
		defer mu.Unlock()
		if len(seen) > 0 {
			t.Errorf("the guest ran on both %s and %s at once (%v)", a.Name, b.Name, seen)
		}
	}
}

// fwliveEventIndex is the index of the first event op for fwlivesc in n's
// fake log at or after from, or -1.
func fwliveEventIndex(n *Node, op string, from int) int {
	for i, e := range n.Virt.EventLog() {
		if i >= from && e.Op == op && e.Domain == fwliveVM {
			return i
		}
	}
	return -1
}

func fwliveExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func fwliveRow(t *testing.T, n *Node) *corrosion.VMRecord {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), n.DB, fwliveVM)
	if err != nil || vm == nil {
		t.Fatalf("the VM's row: %+v (%v)", vm, err)
	}
	return vm
}

// fwliveQuarantine is the one quarantine directory dst keeps for fwlivesc,
// or "".
func fwliveQuarantine(t *testing.T, n *Node) string {
	t.Helper()
	dirs, _ := filepath.Glob(filepath.Join(n.FW.DataDir, fwmig.QuarantineDir, fwliveVM+"-*"))
	if len(dirs) > 1 {
		t.Fatalf("quarantines %v, want at most one", dirs)
	}
	if len(dirs) == 0 {
		return ""
	}
	return dirs[0]
}

func fwliveOpenCondition(t *testing.T, n *Node, code string) (corrosion.HealthCondition, bool) {
	t.Helper()
	row, found, err := corrosion.GetHealthCondition(context.Background(), n.DB, "firmware_migration", code, "vm", fwliveVM)
	if err != nil {
		t.Fatalf("condition %s: %v", code, err)
	}
	return row, found && row.Lifecycle != corrosion.ConditionResolved
}

// F-1. The happy path of a Secure Boot + vTPM VM with a host-local disk
// (`--with-storage`): the guest lands paused on the target and stays paused
// through Verify, which matches; only Release, after the commit, resumes it,
// and the target's NVRAM is then the source's final; the source's state is
// wiped only after Release answered with the NVRAM confirmed, kept in the
// retained bundle; no move record is left on either host.
//
// Mutation: resume without Verify — liveFirmwareCutover writes the marker
// verified instead of calling Verify, and Release accepts a prepared hold —
// red: the move otherwise completes, and only the fake's order log (no
// Verify before the resume) catches it.
func TestFleet_FwLive_F1_HappyPathWithStorage(t *testing.T) {
	sc := fwliveSetup(t, true)
	src, dst := sc.src, sc.dst
	stop := fwliveOneCopy(t, src, dst)

	var mu sync.Mutex
	verifyEnd, releaseStart, releaseEnd := -1, -1, -1
	dst.HookUnary("VerifyLiveFirmwareTarget", func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		if st, _ := dst.Virt.RawState(fwliveVM); st != libvirtfake.StatePaused {
			t.Errorf("at Verify the target guest is %q, want paused", st)
		}
		if i := fwliveEventIndex(dst, "migrate-in", 0); i < 0 {
			t.Error("Verify came before the guest landed on the target")
		}
		resp, err := h(ctx, req)
		mu.Lock()
		verifyEnd = len(dst.Virt.EventLog())
		mu.Unlock()
		if v := resp.(*pb.VerifyLiveFirmwareTargetResponse).GetVerdict(); err != nil || v != pb.FirmwareVerdict_FIRMWARE_VERDICT_MATCH {
			t.Errorf("Verify answered %v (%v), want MATCH", v, err)
		}
		if st, _ := dst.Virt.RawState(fwliveVM); st != libvirtfake.StatePaused {
			t.Errorf("after Verify the target guest is %q, want still paused", st)
		}
		return resp, err
	})
	dst.HookUnary("ReleaseLiveFirmwareTarget", func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		mu.Lock()
		releaseStart = len(dst.Virt.EventLog())
		mu.Unlock()
		// The commit landed first: the row names the target.
		if row := fwliveRow(t, dst); row.HostName != dst.Name {
			t.Errorf("Release before the commit: the row names %s", row.HostName)
		}
		if st, _ := dst.Virt.RawState(fwliveVM); st != libvirtfake.StatePaused {
			t.Errorf("at Release the target guest is %q, want paused", st)
		}
		resp, err := h(ctx, req)
		mu.Lock()
		releaseEnd = len(dst.Virt.EventLog())
		mu.Unlock()
		if err != nil || !resp.(*pb.ReleaseLiveFirmwareTargetResponse).GetNvramConfirmed() {
			t.Errorf("Release answered %+v (%v), want the NVRAM confirmed", resp, err)
		}
		// The source's state is all still there when Release answers: the
		// cleanup waits for it.
		if _, ok := src.Virt.RawState(fwliveVM); !ok {
			t.Error("the source domain was undefined before Release answered")
		}
		if !bytes.Equal(hlRead(t, fwlivePermallPath(src)), fwlivePermall) || !bytes.Equal(hlRead(t, src.FW.NvramPath(fwliveVM)), fwliveNvram) {
			t.Error("the source's firmware state changed before Release answered")
		}
		if got := hlRead(t, dst.FW.NvramPath(fwliveVM)); !bytes.Equal(got, fwliveNvram) {
			t.Errorf("target NVRAM when Release answered = %q, want the source's final", got)
		}
		return resp, err
	})

	err := sc.migrate(t)
	stop()
	if err != nil {
		t.Fatalf("live firmware move: %v", err)
	}
	if note := lastMigrateNote(src); !strings.Contains(note, "with_storage=true") || !strings.Contains(note, "firmware_live=true") ||
		!strings.Contains(note, "tls=true") {
		t.Errorf("libvirt migrate = %q, want an encrypted storage copy, firmware_live", note)
	}

	// The fake's order log: landed, Verify, Release, and the one resume
	// inside Release.
	resume := fwliveEventIndex(dst, "resume", 0)
	if verifyEnd < 0 || releaseStart < 0 || releaseEnd < 0 {
		t.Fatalf("Verify or Release never ran on the target (%d %d %d)", verifyEnd, releaseStart, releaseEnd)
	}
	if resume < verifyEnd || resume < releaseStart || resume >= releaseEnd {
		t.Errorf("target resume at event %d, want inside Release [%d,%d) and after Verify (%d): %+v",
			resume, releaseStart, releaseEnd, verifyEnd, dst.Virt.EventLog())
	}
	if again := fwliveEventIndex(dst, "resume", resume+1); again >= 0 {
		t.Errorf("the target guest was resumed twice (events %d and %d)", resume, again)
	}

	if st, _ := dst.Virt.RawState(fwliveVM); st != libvirtfake.StateRunning {
		t.Errorf("target domain %q, want running", st)
	}
	row := fwliveRow(t, src)
	if row.HostName != dst.Name || row.State != "running" {
		t.Errorf("row %s/%s, want running on %s", row.HostName, row.State, dst.Name)
	}
	disks, err := corrosion.ListDisks(context.Background(), src.DB, fwliveVM)
	if err != nil || len(disks) != 1 || disks[0].HostName != dst.Name {
		t.Errorf("disk rows %+v (%v), want root on %s", disks, err, dst.Name)
	}
	if got := hlRead(t, dst.FW.NvramPath(fwliveVM)); !bytes.Equal(got, fwliveNvram) {
		t.Errorf("target NVRAM %q, want the source's final", got)
	}
	// Source: undefined, state wiped, retained bundle kept.
	if st, ok := src.Virt.RawState(fwliveVM); ok {
		t.Errorf("the source domain is still defined (%s)", st)
	}
	for _, p := range []string{fwlivePermallPath(src), src.FW.NvramPath(fwliveVM)} {
		if fwliveExists(p) {
			t.Errorf("source state %s not wiped", p)
		}
	}
	if tars, _ := filepath.Glob(filepath.Join(src.FW.DataDir, fwmig.RetainedDir, fwliveVM+"-*.tar")); len(tars) != 1 {
		t.Errorf("retained bundles %v, want one", tars)
	}
	// No record on either host.
	if _, ok, err := fwmig.New(dst.FW.DataDir).GetHold(fwliveVM); ok || err != nil {
		t.Errorf("the target still holds the move (%v)", err)
	}
	if m, ok, err := fwmig.New(src.FW.DataDir).GetMarker(fwliveVM); ok || err != nil {
		t.Errorf("source marker %s left (%v)", m.Phase, err)
	}
	if q := fwliveQuarantine(t, dst); q != "" {
		t.Errorf("a happy move quarantined %s", q)
	}
}

// F-2. Verify answers MISMATCH (the permall was corrupted on the way) and the
// source domain stopped as a completed migration stops it (reason
// migrated): the source's copy is current. The target's copy is discarded
// into quarantine (tree and NVRAM moved there, nothing deleted), the held
// domain undefined, the row stopped on the source, and the source's state is
// byte-for-byte what it was; `lv start` on the source works.
//
// Mutation: DISCARD_UNVERIFIED deletes the target's state (rule D, the
// store's RemoveFirmwareMoveTargetState) instead of quarantining it
// (migrate_firmware_live_target.go) — red: no quarantine holds the tree.
func TestFleet_FwLive_F2_MismatchQuarantines(t *testing.T) {
	sc := fwliveSetup(t, false)
	src, dst := sc.src, sc.dst
	dst.Virt.CorruptLandedPermall = func(string) bool { return true }
	stop := fwliveOneCopy(t, src, dst)

	err := sc.migrate(t)
	if err == nil || status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "did not verify") {
		t.Fatalf("migrate = %v, want FailedPrecondition: did not verify", err)
	}

	q := fwliveQuarantine(t, dst)
	if q == "" {
		t.Fatalf("no quarantine on %s", dst.Name)
	}
	if got, err := os.ReadFile(filepath.Join(q, "swtpm", "tpm2", "tpm2-00.permall")); err != nil ||
		!bytes.HasPrefix(got, fwlivePermall) || bytes.Equal(got, fwlivePermall) {
		t.Errorf("quarantined permall %q (%v), want the corrupted copy", got, err)
	}
	// The NVRAM Prepare materialised from the source (T0); the guest never
	// resumed, so nothing wrote it since.
	if got, err := os.ReadFile(filepath.Join(q, "nvram")); err != nil || !bytes.Equal(got, fwliveNvram) {
		t.Errorf("quarantined NVRAM %q (%v), want the one Prepare materialised", got, err)
	}
	for _, p := range []string{fwlivePermallPath(dst), dst.FW.NvramPath(fwliveVM)} {
		if fwliveExists(p) {
			t.Errorf("target state %s left outside the quarantine", p)
		}
	}
	if _, ok := dst.Virt.RawState(fwliveVM); ok {
		t.Error("the held domain is still defined on the target")
	}
	if _, ok, err := fwmig.New(dst.FW.DataDir).GetHold(fwliveVM); ok || err != nil {
		t.Errorf("the target still holds the move (%v)", err)
	}
	if _, ok, err := fwmig.New(src.FW.DataDir).GetMarker(fwliveVM); ok || err != nil {
		t.Errorf("the source marker was kept (%v)", err)
	}

	row := fwliveRow(t, src)
	if row.HostName != src.Name || row.State != "stopped" {
		t.Errorf("row %s/%s, want stopped on %s", row.HostName, row.State, src.Name)
	}
	if st, ok := src.Virt.RawState(fwliveVM); !ok || st != libvirtfake.StateShutdown {
		t.Errorf("source domain %q (defined %v), want defined and shut off", st, ok)
	}
	if !bytes.Equal(hlRead(t, fwlivePermallPath(src)), fwlivePermall) || !bytes.Equal(hlRead(t, src.FW.NvramPath(fwliveVM)), fwliveNvram) {
		t.Error("the source's firmware state is not byte-for-byte what it was")
	}
	if _, open := fwliveOpenCondition(t, src, "firmware_migration_unverified"); !open {
		t.Error("no firmware_migration_unverified on the source")
	}

	// The source's copy is the VM: it starts there.
	if _, err := sc.c.SelfClient(src).StartVM(context.Background(), &pb.StartVMRequest{Name: fwliveVM}); err != nil {
		t.Fatalf("lv start on the source after the discard: %v", err)
	}
	stop()
	if st, _ := src.Virt.RawState(fwliveVM); st != libvirtfake.StateRunning {
		t.Errorf("source domain after lv start %q, want running", st)
	}
}

// F-2b. Verify answers MISMATCH, but the source domain stopped with reason
// unknown (a host crash or reboot, not a completed migration): its state may
// be stale, so neither copy is chosen. The move parks source_state_suspect;
// both copies are kept, the target guest stays paused and held, and `lv
// start` on the source is refused while it is parked.
//
// Mutation: take V1's discard on any stop reason (drop the SrcStopReason
// check in verifyLiveFirmwareMove) — red: the target's copy is quarantined
// and the row stopped.
func TestFleet_FwLive_F2b_MismatchAfterUnknownReasonParks(t *testing.T) {
	sc := fwliveSetup(t, false)
	src, dst := sc.src, sc.dst
	dst.Virt.CorruptLandedPermall = func(string) bool { return true }
	src.Virt.ReportSourceReasonUnknown = func(string) bool { return true }
	stop := fwliveOneCopy(t, src, dst)
	defer stop()

	if err := sc.migrate(t); err == nil {
		t.Fatal("the move succeeded with a mismatched target copy")
	}
	m, ok, err := fwmig.New(src.FW.DataDir).GetMarker(fwliveVM)
	if err != nil || !ok || m.Phase != fwmig.PhaseSourceStateSuspect {
		t.Fatalf("source marker %q (present %v, %v), want source_state_suspect", m.Phase, ok, err)
	}
	if m.SrcStopReason != "unknown" {
		t.Errorf("marker stop reason %q, want unknown", m.SrcStopReason)
	}
	h, ok, err := fwmig.New(dst.FW.DataDir).GetHold(fwliveVM)
	if err != nil || !ok || h.State != fwmig.HoldMismatch || h.Attempt != m.Attempt {
		t.Errorf("target hold %+v (present %v, %v), want mismatch for attempt %s", h, ok, err, m.Attempt)
	}
	if st, _ := dst.Virt.RawState(fwliveVM); st != libvirtfake.StatePaused {
		t.Errorf("target guest %q, want paused", st)
	}
	if fwliveEventIndex(dst, "resume", 0) >= 0 {
		t.Error("the target guest was resumed")
	}
	if q := fwliveQuarantine(t, dst); q != "" {
		t.Errorf("the target's copy was quarantined (%s)", q)
	}
	// Both copies.
	if !bytes.Equal(hlRead(t, fwlivePermallPath(src)), fwlivePermall) || !bytes.Equal(hlRead(t, src.FW.NvramPath(fwliveVM)), fwliveNvram) {
		t.Error("the source's firmware state changed")
	}
	if !fwliveExists(fwlivePermallPath(dst)) || !fwliveExists(dst.FW.NvramPath(fwliveVM)) {
		t.Error("the target's copy is gone")
	}
	if st, ok := src.Virt.RawState(fwliveVM); !ok || st != libvirtfake.StateShutdown {
		t.Errorf("source domain %q (defined %v), want defined and shut off", st, ok)
	}
	if row := fwliveRow(t, src); row.State == "stopped" || row.State == "running" {
		t.Errorf("row %s/%s, want neither stopped nor running while parked", row.HostName, row.State)
	}
	if _, open := fwliveOpenCondition(t, src, "firmware_migration_source_state_suspect"); !open {
		t.Error("no firmware_migration_source_state_suspect on the source")
	}
	// The parked source's start veto.
	_, err = sc.c.SelfClient(src).StartVM(context.Background(), &pb.StartVMRequest{Name: fwliveVM})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("lv start on the parked source = %v, want FailedPrecondition", err)
	}
	if st, _ := src.Virt.RawState(fwliveVM); st != libvirtfake.StateShutdown {
		t.Errorf("source domain after the refused start %q, want shut off", st)
	}
}

// F-4. The source's final firmware state is missing at cutover (its permall,
// or its NVRAM, gone once the guest left): nothing can be verified against
// it, and nothing is deleted. The move parks source_state_missing before any
// Verify; the target keeps its hold and its paused guest, the source what is
// left of its state.
//
// Mutation: treat a missing final state as a mismatch (liveFirmwareCutover
// sends it to discardUnverifiedLiveFirmware) — red: the target's copy is
// quarantined and the hold gone.
func TestFleet_FwLive_F4_SourceStateMissingParks(t *testing.T) {
	for _, missing := range []string{"permall", "nvram"} {
		t.Run(missing, func(t *testing.T) {
			sc := fwliveSetup(t, false)
			src, dst := sc.src, sc.dst
			gone := fwlivePermallPath(src)
			if missing == "nvram" {
				gone = src.FW.NvramPath(fwliveVM)
			}
			// The guest lands on dst; then its final state vanishes from src.
			src.Virt.OnMigrateToTarget = func(name, _ string, p lv.MigrateParams) error {
				if err := dst.Virt.LandFirmwareLive(src.Virt, name, p); err != nil {
					return err
				}
				return os.Remove(gone)
			}
			verifies := 0
			dst.HookUnary("VerifyLiveFirmwareTarget", func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
				verifies++
				return h(ctx, req)
			})
			stop := fwliveOneCopy(t, src, dst)
			defer stop()

			err := sc.migrate(t)
			if err == nil {
				t.Fatal("the move succeeded without the source's final state")
			}
			m, ok, merr := fwmig.New(src.FW.DataDir).GetMarker(fwliveVM)
			if merr != nil || !ok || m.Phase != fwmig.PhaseSourceStateMissing {
				t.Fatalf("source marker %q (present %v, %v), want source_state_missing (migrate: %v)", m.Phase, ok, merr, err)
			}
			if verifies != 0 {
				t.Errorf("Verify was called %d time(s) without the source's final state", verifies)
			}
			h, ok, herr := fwmig.New(dst.FW.DataDir).GetHold(fwliveVM)
			if herr != nil || !ok || h.Attempt != m.Attempt || h.State != fwmig.HoldPrepared {
				t.Errorf("target hold %+v (present %v, %v), want prepared for attempt %s", h, ok, herr, m.Attempt)
			}
			if st, _ := dst.Virt.RawState(fwliveVM); st != libvirtfake.StatePaused {
				t.Errorf("target guest %q, want paused", st)
			}
			if fwliveEventIndex(dst, "resume", 0) >= 0 {
				t.Error("the target guest was resumed")
			}
			if q := fwliveQuarantine(t, dst); q != "" {
				t.Errorf("the target's copy was quarantined (%s)", q)
			}
			// Nothing deleted: the target's copy, and what the source kept.
			if got := hlRead(t, fwlivePermallPath(dst)); !bytes.Equal(got, fwlivePermall) {
				t.Errorf("target permall %q, want the landed copy", got)
			}
			if !fwliveExists(dst.FW.NvramPath(fwliveVM)) {
				t.Error("the target's NVRAM is gone")
			}
			if missing == "permall" && !bytes.Equal(hlRead(t, src.FW.NvramPath(fwliveVM)), fwliveNvram) {
				t.Error("the source's NVRAM changed")
			}
			if missing == "nvram" && !bytes.Equal(hlRead(t, fwlivePermallPath(src)), fwlivePermall) {
				t.Error("the source's permall changed")
			}
			if st, ok := src.Virt.RawState(fwliveVM); !ok || st != libvirtfake.StateShutdown {
				t.Errorf("source domain %q (defined %v), want defined and shut off", st, ok)
			}
			if row := fwliveRow(t, src); row.State == "stopped" || row.State == "running" {
				t.Errorf("row %s/%s, want neither stopped nor running while parked", row.HostName, row.State)
			}
			if _, open := fwliveOpenCondition(t, src, "firmware_migration_source_state_missing"); !open {
				t.Error("no firmware_migration_source_state_missing on the source")
			}
		})
	}
}

// F-9. The target runs an older build, without the live firmware RPCs: the
// move is refused before anything is written there, with the cold-only text
// naming the target's build; the source keeps running with no marker, and
// libvirt was never asked to migrate.
//
// Mutation: treat Prepare's Unimplemented as OK (stage B item 8 returns nil,
// and beginLiveFirmwareMove's Unimplemented branch is dropped) — red: libvirt
// migrates, the target lands the guest and its state, and the move parks
// when Verify is unimplemented.
func TestFleet_FwLive_F9_OlderTargetRefusedNoWrite(t *testing.T) {
	sc := fwliveSetup(t, false)
	src, dst := sc.src, sc.dst
	dst.RefuseRPCs("PrepareLiveFirmwareTarget", "VerifyLiveFirmwareTarget", "ReleaseLiveFirmwareTarget", "AbortLiveFirmwareTarget")
	stop := fwliveOneCopy(t, src, dst)
	defer stop()

	err := sc.migrate(t)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("migrate = %v, want FailedPrecondition", err)
	}
	msg := status.Convert(err).Message()
	if !strings.Contains(msg, "target "+dst.Name+" runs a build without live firmware migration") || !strings.Contains(msg, "--cold") {
		t.Errorf("refusal %q, want it to name %s's build and the cold move", msg, dst.Name)
	}
	if n := migrateCalls(src); n != 0 {
		t.Errorf("libvirt was asked to migrate %d time(s)", n)
	}
	if st, _ := src.Virt.RawState(fwliveVM); st != libvirtfake.StateRunning {
		t.Errorf("source guest %q, want running", st)
	}
	if row := fwliveRow(t, src); row.HostName != src.Name || row.State != "running" {
		t.Errorf("row %s/%s, want running on %s", row.HostName, row.State, src.Name)
	}
	if _, ok, err := fwmig.New(src.FW.DataDir).GetMarker(fwliveVM); ok || err != nil {
		t.Errorf("a marker was left on the source (%v)", err)
	}
	// Nothing written on the target: no domain, no record, no state.
	if _, ok := dst.Virt.RawState(fwliveVM); ok {
		t.Error("a domain was defined on the target")
	}
	for _, sub := range fwmig.Dirs() {
		ents, err := os.ReadDir(filepath.Join(dst.FW.DataDir, sub))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if len(ents) > 0 {
			t.Errorf("the target wrote %s/%s", sub, ents[0].Name())
		}
	}
	for _, p := range []string{dst.FW.SwtpmDir(fwliveUUID), dst.FW.NvramPath(fwliveVM)} {
		if fwliveExists(p) {
			t.Errorf("the target has %s", p)
		}
	}
}
