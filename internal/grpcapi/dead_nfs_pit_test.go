package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pitoverlay"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/storage"
)

// Lab 2 N-4: a start of a VM on an NFS pool whose server does not answer
// hung in settlePITOverlays — an unbounded lstat of the disk's point-in-time
// overlay, under the VM lock, before the bounded start checks — and a second
// start and a stop of the VM queued behind it.

// blockPITLstat makes every lstat the overlay code makes of a path that
// satisfies dead block until the test ends, as one on a hard NFS mount whose
// server does not answer does.
func blockPITLstat(t *testing.T, dead func(string) bool) {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(pitoverlay.SetLstatForTest(func(p string) (os.FileInfo, error) {
		if dead(p) {
			<-release
		}
		return os.Lstat(p)
	}))
	t.Cleanup(func() { close(release) })
}

// deadPoolVM is the start-chain fixture with an nfs pool on a dead mount and
// VM "nvm" whose root disk is on it.
func deadPoolVM(t *testing.T) (*startChainFixture, string, string) {
	t.Helper()
	f, mnt, _ := startChainWithDeadNFS(t)
	disk := filepath.Join(mnt, "nvm-root.qcow2")
	if err := qcow2.CreateWithBacking(disk, "ubuntu", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	f.insertVM(t, "nvm", "a", disk, "shared", "ubuntu")
	return f, mnt, disk
}

func wantNoAnswer(t *testing.T, what string, err error) {
	t.Helper()
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "does not answer") {
		t.Fatalf("%s: %v; want Unavailable saying its storage does not answer", what, err)
	}
}

// Two starts of the VM at once, as on the lab: both are refused as
// retryable, within the bound, and a stop of the VM is not queued behind
// them.
//
// Mutation "settlePITOverlays looks for the overlay unbounded" — the starts
// hang: red.
func TestStart_AVMWhoseOverlayCheckDoesNotAnswerIsRefused(t *testing.T) {
	f, mnt, _ := deadPoolVM(t)
	blockPITLstat(t, func(p string) bool { return pathWithin(mnt, p) })
	errs := within(t, 10*time.Second, "two starts of a VM on the dead pool", func() []error {
		var wg sync.WaitGroup
		out := make([]error, 2)
		for i := range out {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, out[i] = f.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "nvm"})
			}()
		}
		wg.Wait()
		return out
	})
	for i, err := range errs {
		wantNoAnswer(t, "start "+string(rune('1'+i)), err)
	}
	within(t, 3*time.Second, "a stop of the VM after its refused starts", func() error {
		_, err := f.s.StopVM(adminCtx(), &pb.StopVMRequest{Name: "nvm", Force: true})
		return err
	})
}

// A no-answer is never "no overlay", wherever it comes: from the disk's own
// file (which decides whether a hold may be cleared), from the overlay's
// binding, or from a disk recorded on another host (a shared disk), whose
// overlay this host would otherwise skip as absent.
//
// Mutations, each red: "the disk's stat unbounded" (the start hangs);
// "PresenceOf unbounded" (hangs); "a peer's disk skipped on Present" (the
// VM is settled as if it had no overlay).
func TestSettlePITOverlays_ANoAnswerIsNeverNoOverlay(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, s *Server, disk string)
	}{
		{"the disk's own file", func(t *testing.T, _ *Server, disk string) {
			release := make(chan struct{})
			t.Cleanup(overridePITDiskStat(func(p string) (os.FileInfo, error) {
				if p == disk {
					<-release
				}
				return os.Stat(p)
			}))
			t.Cleanup(func() { close(release) })
		}},
		{"the overlay's binding", func(t *testing.T, _ *Server, disk string) {
			blockPITLstat(t, func(p string) bool { return p == pitoverlay.SidecarPath(disk) })
		}},
		{"a disk recorded on another host", func(t *testing.T, s *Server, disk string) {
			if err := s.db.Execute(context.Background(), `UPDATE vm_disks SET host_name = 'peer' WHERE vm_name = 'lvm'`); err != nil {
				t.Fatal(err)
			}
			blockPITLstat(t, func(p string) bool { return p == pitoverlay.Path(disk) })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newStartChainFixture(t)
			t.Cleanup(storage.OverrideFSCallBoundForTest(300 * time.Millisecond))
			disk := filepath.Join(f.pa, "lvm-root.qcow2")
			if err := qcow2.Create(disk, 1<<20, nil); err != nil {
				t.Fatal(err)
			}
			vm := f.insertVM(t, "lvm", "a", disk, "pa", "")
			tc.setup(t, f.s, disk)
			err := within(t, 5*time.Second, "settling the VM's overlays", func() error {
				return f.s.settlePITOverlays(context.Background(), vm)
			})
			wantNoAnswer(t, "settle", err)
		})
	}
}

// The start-up sweep settles each VM's overlays under the VM's lock. A VM
// whose overlay check does not answer is passed over, not waited on: the
// sweep goes on, and the lock — which every start and stop of the VM needs —
// is not held for as long as the server does not answer (lab 2 O-3).
//
// The VM passed over is swept again, slowly, until its storage answers
// (review round 1, M-2): the sweep is what settles a running VM a dead
// daemon left on its overlay.
//
// Mutations: "the sweep looks for the overlay unbounded" — the start waits
// on the lock: red. "no retry" — the sweep ends while the storage is still
// dead: red.
func TestSweepPITOverlays_PassesOverAVMWhoseOverlayDoesNotAnswer(t *testing.T) {
	f, mnt, _ := deadPoolVM(t)
	prevRetry := pitSweepRetry
	pitSweepRetry = 50 * time.Millisecond
	t.Cleanup(func() { pitSweepRetry = prevRetry })
	release := make(chan struct{})
	var once sync.Once
	answer := func() { once.Do(func() { close(release) }) }
	t.Cleanup(answer)
	t.Cleanup(pitoverlay.SetLstatForTest(func(p string) (os.FileInfo, error) {
		if pathWithin(mnt, p) {
			<-release
		}
		return os.Lstat(p)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	swept := make(chan struct{})
	go func() {
		defer close(swept)
		f.s.SweepPITOverlays(ctx, func() (bool, string) { return true, "" })
	}()
	// The lock is not held: a start is refused at once.
	err := within(t, 5*time.Second, "a start during the sweep", func() error {
		_, err := f.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "nvm"})
		return err
	})
	wantNoAnswer(t, "start during the sweep", err)
	select {
	case <-swept:
		t.Fatal("the sweep gave up on the VM while its storage did not answer")
	case <-time.After(500 * time.Millisecond):
	}
	answer()
	select {
	case <-swept:
	case <-time.After(10 * time.Second):
		t.Fatal("the sweep did not finish the VM once its storage answered")
	}
}

// A delete settles the overlays of the disks it keeps: one whose overlay
// check does not answer refuses the delete, retryable, instead of keeping
// the disk without its overlay's writes or waiting on the server.
//
// Mutation "the kept disks' overlays looked for unbounded" — red.
func TestSettleKeptPITOverlays_ANoAnswerRefusesTheDelete(t *testing.T) {
	f, mnt, _ := deadPoolVM(t)
	blockPITLstat(t, func(p string) bool { return pathWithin(mnt, p) })
	vm := vmRecord(t, f.s, "nvm")
	err := within(t, 5*time.Second, "settling a deleted VM's kept overlays", func() error {
		return f.s.settleKeptPITOverlays(context.Background(), vm, true)
	})
	wantNoAnswer(t, "settle kept overlays", err)
}

// A delete that keeps nothing (the disk goes with the VM, overlay and all)
// is not refused because the overlay check does not answer: only kept disks
// are looked at (review round 1, M-3).
//
// Mutation "look before deciding what is kept" — red.
func TestSettleKeptPITOverlays_ADiskTheDeleteRemovesIsNotLookedAt(t *testing.T) {
	f := newStartChainFixture(t)
	t.Cleanup(storage.OverrideFSCallBoundForTest(300 * time.Millisecond))
	disk := filepath.Join(f.pa, "gone-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	vm := f.insertVM(t, "gone", "a", disk, "pa", "")
	if err := f.s.db.Execute(context.Background(), `UPDATE vm_disks SET delete_with_vm = 1 WHERE vm_name = 'gone'`); err != nil {
		t.Fatal(err)
	}
	blockPITLstat(t, func(p string) bool { return p == pitoverlay.Path(disk) })
	err := within(t, 5*time.Second, "settling the kept overlays of a delete that keeps nothing", func() error {
		return f.s.settleKeptPITOverlays(context.Background(), vm, false)
	})
	if err != nil {
		t.Fatalf("a delete that keeps no disk was refused: %v", err)
	}
}

// The common delete — no overlay beside its disk — does not ask whether the
// disk is kept: that reads the header chain of every VM disk on the host
// (review round 2, R-3).
//
// Mutation "ask whether it is kept before looking for the overlay" — the
// other VM's header is read: red.
func TestSettleKeptPITOverlays_NoOverlayReadsNoOtherHeader(t *testing.T) {
	f := newStartChainFixture(t) // bvm's disk is in the global pool
	disk := filepath.Join(f.pa, "plain-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	vm := f.insertVM(t, "plain", "a", disk, "pa", "")
	if err := f.s.db.Execute(context.Background(), `UPDATE vm_disks SET delete_with_vm = 1 WHERE vm_name = 'plain'`); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var read []string
	prev := chainStat
	chainStat = func(p string) (os.FileInfo, error) {
		mu.Lock()
		read = append(read, p)
		mu.Unlock()
		return prev(p)
	}
	t.Cleanup(func() { chainStat = prev })
	if err := f.s.settleKeptPITOverlays(context.Background(), vm, false); err != nil {
		t.Fatalf("settle kept overlays: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(read) != 0 {
		t.Fatalf("a delete with no overlay read disk headers: %v", read)
	}
}

// The start path's other unbounded look at a pool directory (round 3's
// residual): a VM whose installer ISO is in a library on a dead mount. The
// ISO's judgement is bounded like the disk checks, and its no-answer is
// refused as retryable.
//
// Mutation "the CD-ROMs judged unbounded" — the start hangs: red.
func TestStart_AnInstallerISOOnADeadMountIsRefusedNotWaitedOn(t *testing.T) {
	f, mnt, _ := startChainWithDeadNFS(t)
	iso := filepath.Join(mnt, "isos", "installer.iso")
	vm := f.insertVM(t, "isovm", "a", filepath.Join(f.pa, "isovm-root.qcow2"), "pa", "")
	if err := f.s.virt.DefineDomain(`<domain type='kvm'><name>isovm</name><devices>` +
		`<disk type='file' device='cdrom'><source file='` + iso + `'/></disk></devices></domain>`); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	prev := judgeCDROMs
	judgeCDROMs = func(*Server, *corrosion.VMRecord, string) (string, error) {
		<-release // the ISO's stat on the dead mount
		// Released at cleanup, after the test: no real judgement then, which
		// would read other tests' ISO hooks and this test's closed DB.
		return "", errors.New("released")
	}
	t.Cleanup(func() { judgeCDROMs = prev })
	err := within(t, 10*time.Second, "the start's ISO check", func() error { return f.s.verifyVMISOForStart(vm) })
	wantNoAnswer(t, "ISO check", err)
}
