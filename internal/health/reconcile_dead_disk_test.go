package health

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/storage"
)

// stalledStorage stands in for a hard NFS mount whose server has stopped
// answering (lab 2 F-3): a stat or lstat of one of its paths blocks until
// answer is called. Every other path answers at once.
type stalledStorage struct {
	paths   map[string]bool
	release chan struct{}
	once    sync.Once
}

func stallStorage(t *testing.T, paths ...string) *stalledStorage {
	t.Helper()
	s := &stalledStorage{paths: map[string]bool{}, release: make(chan struct{})}
	for _, p := range paths {
		s.paths[p] = true
	}
	t.Cleanup(storage.OverrideFSCallBoundForTest(200 * time.Millisecond))
	t.Cleanup(s.answer)
	return s
}

func (s *stalledStorage) answer() { s.once.Do(func() { close(s.release) }) }

func (s *stalledStorage) stat(p string) (os.FileInfo, error) {
	if s.paths[p] {
		<-s.release
	}
	return os.Stat(p)
}

func (s *stalledStorage) lstat(p string) (os.FileInfo, error) {
	if s.paths[p] {
		<-s.release
	}
	return os.Lstat(p)
}

func (s *stalledStorage) wire(r *Reconciler) {
	r.diskStat = s.stat
	r.diskLstat = s.lstat
}

// answered waits until the calls stuck on p have returned, so a bounded call
// on it is no longer joined to them.
func (s *stalledStorage) answered(t *testing.T, p string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, serr := storage.Bounded("stat", p, func() (os.FileInfo, error) { return os.Stat(p) })
		_, lerr := storage.Bounded("lstat", p, func() (os.FileInfo, error) { return os.Lstat(p) })
		if !storage.IsFSNoAnswer(serr) && !storage.IsFSNoAnswer(lerr) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s still does not answer after the release", p)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// within runs fn and fails the test if it has not returned within d: a pass
// held by a call that does not answer.
func within(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v: it waits on storage that does not answer", what, d)
	}
}

// Lab 2 F-3. The reconciler's start looked at each disk file with an
// unbounded os.Stat before its bounded overlay check. On a dead hard NFS
// mount that stat blocks in the kernel for the whole outage, so the pass
// stopped there: the I-1 deferral was never reached, and every other VM on
// the host waited with it (the lab's pass sat 2m41s in newfstatat).
//
// Now the look is bounded: a disk that does not answer is never "missing"
// (a local start parked in error, a transfer rebuilt blank); the start is
// DEFERRED — "starting" without a proof, "pending" with one, the proof kept —
// the pass goes on to the next VM, and the start runs once the storage
// answers.
//
// Mutation "the disk stat unbounded again" — every case is red on the time
// limit. Mutation "a no-answer is a missing disk" — self-heal and onboot are
// parked in error, the transfer is rebuilt: red.
func TestReconcile_ADiskThatDoesNotAnswerDefersItsStartAndHoldsNoOtherVM(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state string
		spec  string
		proof bool
		first func(r *Reconciler, ctx context.Context)
		// wantState is the row's state while the start is deferred.
		wantState string
		// storageType of vm1's disk. A transfer of a host-local disk sets
		// aside any old copy at its path and rebuilds it (superseded_disk.go),
		// so that case checks only that nothing is renamed or rebuilt while
		// the path does not answer.
		storageType string
		thenStarts  bool
	}{
		{"self-heal", "running", `{"name":"vm1"}`, false, func(r *Reconciler, ctx context.Context) { r.reconcile(ctx) }, "starting", "local", true},
		{"onboot", "stopped", `{"name":"vm1","onboot":true}`, false, func(r *Reconciler, ctx context.Context) { r.StartOnbootVMs(ctx) }, "starting", "local", true},
		{"transfer on a shared pool", "pending", `{"name":"vm1"}`, true, func(r *Reconciler, ctx context.Context) { r.reconcile(ctx) }, "pending", "nfs", true},
		{"transfer of a host-local disk", "pending", `{"name":"vm1"}`, true, func(r *Reconciler, ctx context.Context) { r.reconcile(ctx) }, "pending", "local", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			ctx := context.Background()
			dead := filepath.Join(t.TempDir(), "vm1-root.qcow2")
			healthy := filepath.Join(t.TempDir(), "vm2-root.qcow2")
			for _, p := range []string{dead, healthy} {
				if err := os.WriteFile(p, []byte("the disk"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
				Name: "vm1", HostName: "node-a", State: tc.state, Spec: tc.spec}, nil,
				[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "node-a", Path: dead,
					BackingImage: "base", SizeBytes: 1 << 20, StorageType: tc.storageType}}); err != nil {
				t.Fatal(err)
			}
			// A healthy VM after it in the walk, whose domain is gone too.
			if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
				Name: "vm2", HostName: "node-a", State: "running", Spec: `{"name":"vm2"}`}, nil,
				[]corrosion.DiskRecord{{VMName: "vm2", DiskName: "root", HostName: "node-a", Path: healthy,
					SizeBytes: 1 << 20, StorageType: "local"}}); err != nil {
				t.Fatal(err)
			}
			fake := libvirtfake.New()
			r := NewReconciler("node-a", t.TempDir(), db, fake)
			rebuilt := false
			r.SetAutoPullImage(func(context.Context, string) error { rebuilt = true; return nil })
			if tc.proof {
				if err := corrosion.WriteVMRescheduleProof(ctx, db, corrosion.ActionProof{
					ID: "p1", Action: corrosion.ActionReschedule, TargetKind: "vm",
					TargetName: "vm1", DestHost: "node-a", Coordinator: "node-a",
				}, "vm1", "node-a"); err != nil {
					t.Fatal(err)
				}
				r.SetGate(fakeGate{exec: GateResult{OK: true}, active: true})
			}
			s := stallStorage(t, dead)
			s.wire(r)

			within(t, 3*time.Second, "the first pass", func() { tc.first(r, ctx) })
			if hwStarted(fake, "vm1") {
				t.Fatal("vm1 started while its disk did not answer")
			}
			if rebuilt {
				t.Fatal("a disk that did not answer was treated as missing and its overlay rebuilt")
			}
			vm := requireState(t, db, "vm1", tc.wantState)
			if !strings.Contains(vm.StateDetail, "does not answer") {
				t.Errorf("state detail %q does not say why the start waits", vm.StateDetail)
			}
			if tc.proof && vm.PendingActionID != "p1" {
				t.Errorf("the deferred transfer lost its proof: pending_action_id %q", vm.PendingActionID)
			}
			if tc.name != "onboot" {
				// The pass went on past vm1.
				if !hwStarted(fake, "vm2") {
					t.Fatal("vm2, on healthy storage, waited for vm1's dead disk")
				}
			}
			if _, err := os.Stat(dead); err != nil {
				t.Fatalf("vm1's disk is no longer at its path: %v", err)
			}
			if aside, _ := filepath.Glob(dead + ".superseded-*"); len(aside) != 0 {
				t.Fatalf("a disk that did not answer was set aside: %v", aside)
			}
			if !tc.thenStarts {
				return
			}

			// The storage answers again: the deferred start runs.
			s.answer()
			s.answered(t, dead)
			r.reconcile(ctx)
			if !hwStarted(fake, "vm1") {
				t.Fatal("the deferred start was not re-driven once the storage answered")
			}
			requireState(t, db, "vm1", "running")
			if rebuilt {
				t.Fatal("the disk was rebuilt once its storage answered")
			}
		})
	}
}

// The other looks at a disk file in the reconcile pass are bounded the same
// way (F-3's audit): the define of a stopped VM failover re-keyed here, and
// the set-aside of a disk a failover stranded here. Each answers "not now"
// on a no-answer — nothing defined, nothing renamed — and finishes on a
// later pass.
//
// Mutation "the re-key define's disk stat unbounded" / "the stranded tend's
// lstat unbounded": red on the time limit.
func TestReconcile_TheOtherDiskLooksDoNotWaitOnStorageThatDoesNotAnswer(t *testing.T) {
	t.Run("re-keyed stopped define", func(t *testing.T) {
		db := testReconcilerDB(t)
		ctx := context.Background()
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: "node-a", Address: "10.0.0.1", SSHUser: "root", CertSerial: "s-a", State: "active",
		}); err != nil {
			t.Fatal(err)
		}
		disk := filepath.Join(t.TempDir(), "sv-root.qcow2")
		if err := os.WriteFile(disk, []byte("shared"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: "sv", HostName: "node-a", State: "stopped", StateDetail: corrosion.StoppedRekeyDetail("node-f"),
			CPUActual: 1, MemActual: 256, Spec: `{"name":"sv","cpu":1,"memory_mib":256}`,
		}, nil, []corrosion.DiskRecord{{VMName: "sv", DiskName: "root", HostName: "node-a", Path: disk, StorageType: "nfs"}}); err != nil {
			t.Fatal(err)
		}
		fake := libvirtfake.New()
		r := NewReconciler("node-a", t.TempDir(), db, fake)
		s := stallStorage(t, disk)
		s.wire(r)

		within(t, 3*time.Second, "the pass", func() { r.reconcile(ctx) })
		if fake.DomainExists("sv") {
			t.Fatal("sv was defined while its disk did not answer")
		}
		s.answer()
		s.answered(t, disk)
		r.reconcile(ctx)
		if !fake.DomainExists("sv") {
			t.Fatal("sv was not defined once its disk answered")
		}
	})

	t.Run("stranded disk set-aside", func(t *testing.T) {
		db, _, r, _, path := strandedFixture(t)
		ctx := context.Background()
		recordWeb(t, db, time.Now())
		s := stallStorage(t, path)
		s.wire(r)

		within(t, 3*time.Second, "the pass", func() { r.reconcile(ctx) })
		if !exists(path) {
			t.Fatal("the disk was set aside while its storage did not answer")
		}
		_, ev, ok := strandedRow(t, db, "web", "node-a")
		if !ok || len(ev.Disks) != 1 || ev.Disks[0].Copy != "" {
			t.Fatalf("the stranded record changed while the disk did not answer: ok=%v %+v", ok, ev)
		}
		s.answer()
		s.answered(t, path)
		r.reconcile(ctx)
		if exists(path) {
			t.Fatal("the disk was not set aside once its storage answered")
		}
	})
}
