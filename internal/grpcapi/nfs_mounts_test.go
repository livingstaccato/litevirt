package grpcapi

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/storage"
)

const nfsTestSource = "10.0.0.21:/srv/lv"

// hostMounts is this host's mount table: a fake `mount -t nfs` adds the
// export, unmount (an operator's umount) removes it, and mountErr says why
// a mount fails.
type hostMounts struct {
	mu       sync.Mutex
	dirs     map[string]string // dir -> source
	mountErr string
	mounts   int
	lastOpts string
	gate     chan struct{} // set: the next mountpoint call waits for it
	entered  chan struct{} // told when that call starts waiting
}

func installHostMounts(t *testing.T) *hostMounts {
	t.Helper()
	m := &hostMounts{dirs: map[string]string{}}
	t.Cleanup(storage.OverrideNosymfollowSupportForTest(false))
	t.Cleanup(storage.OverrideMountInfoForTest(m.info))
	t.Cleanup(storage.OverrideNFSMountCommandForTest(m.run))
	return m
}

func (m *hostMounts) info() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b strings.Builder
	b.WriteString("22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n")
	i := 0
	for dir, src := range m.dirs {
		fmt.Fprintf(&b, "%d 22 0:%d / %s rw,nosuid,nodev,noexec,relatime - nfs4 %s rw\n", 100+i, 50+i, dir, src)
		i++
	}
	return []byte(b.String()), nil
}

func (m *hostMounts) run(_ context.Context, name string, args ...string) ([]byte, error) {
	m.mu.Lock()
	if g := m.gate; name == "mountpoint" && g != nil {
		// One-shot: this mountpoint call (a pool delete's teardown) holds
		// until the test releases it.
		m.gate = nil
		m.mu.Unlock()
		m.entered <- struct{}{}
		<-g
		m.mu.Lock()
	}
	defer m.mu.Unlock()
	switch name {
	case "umount":
		delete(m.dirs, args[len(args)-1])
		return nil, nil
	case "mountpoint":
		if _, ok := m.dirs[args[len(args)-1]]; ok {
			return nil, nil
		}
		return nil, mountpointExit32{}
	case "mount":
		if len(args) != 7 || args[1] != "nfs" {
			return nil, fmt.Errorf("unexpected mount %q", args)
		}
		m.mounts++
		m.lastOpts = args[3]
		if m.mountErr != "" {
			return []byte(m.mountErr), errors.New("exit status 32")
		}
		m.dirs[args[6]] = args[5]
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected %s %q", name, args)
}

type mountpointExit32 struct{}

func (mountpointExit32) Error() string { return "exit status 32" }
func (mountpointExit32) ExitCode() int { return 32 }

func (m *hostMounts) umount(dir string) {
	m.mu.Lock()
	delete(m.dirs, dir)
	m.mu.Unlock()
}

func (m *hostMounts) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mounts
}

func (m *hostMounts) setMountErr(s string) {
	m.mu.Lock()
	m.mountErr = s
	m.mu.Unlock()
}

func (m *hostMounts) mounted(dir string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.dirs[dir]
	return ok
}

func nfsPoolRow(t *testing.T, s *Server, name string) string {
	t.Helper()
	return nfsPoolRowAt(t, s, name, nfsTestSource, "")
}

// nfsPoolRowAt adds an nfs pool row on this host, and the empty directory a
// reboot leaves at its mount point.
func nfsPoolRowAt(t *testing.T, s *Server, name, source, target string) string {
	t.Helper()
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: name, Driver: "nfs", Source: source, Target: target, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	dir := storage.NFSPoolMountDir(s.dataDir, storage.Config{Driver: "nfs", Source: source, Target: target})
	if err := os.MkdirAll(dir, 0o755); err != nil { // the empty directory a reboot leaves
		t.Fatal(err)
	}
	return dir
}

func mountCondition(t *testing.T, s *Server, pool string) (corrosion.HealthCondition, bool) {
	t.Helper()
	c, ok, err := corrosion.GetHealthCondition(context.Background(), s.db, nfsPoolEvaluator, condNFSMountMissing,
		"host", pool+"@"+s.hostName)
	if err != nil {
		t.Fatal(err)
	}
	return c, ok
}

func nfsDiskVM(t *testing.T, s *Server, pool, dir string) corrosion.VMRecord {
	t.Helper()
	vm := corrosion.VMRecord{Name: "nfsvm", HostName: s.hostName, State: "stopped", Spec: `{"name":"nfsvm","cpu":1,"memory_mib":256}`}
	if err := corrosion.InsertVM(context.Background(), s.db, vm, nil, []corrosion.DiskRecord{{
		VMName: "nfsvm", DiskName: "root", HostName: s.hostName, StorageType: "nfs", StorageVolume: pool,
		Path: filepath.Join(dir, "nfsvm-root.qcow2"),
	}}); err != nil {
		t.Fatal(err)
	}
	return vm
}

// N-1: after a host reboot the export is not mounted. The pass mounts it,
// the pool stays active, and the next pass mounts nothing.
func TestReconcileNFSMounts_MountsAfterAReboot(t *testing.T) {
	s, _ := provableCreateServer(t)
	m := installHostMounts(t)
	dir := nfsPoolRow(t, s, "shared")
	s.ReconcileNFSMounts(context.Background())
	if !m.mounted(dir) {
		t.Fatalf("the pass did not mount %s", dir)
	}
	if st := poolState(t, s, "shared"); st != "active" {
		t.Fatalf("pool state %q, want active", st)
	}
	if c, ok := mountCondition(t, s, "shared"); ok && c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition raised for a mounted pool: %+v", c)
	}
	s.ReconcileNFSMounts(context.Background())
	if n := m.count(); n != 1 {
		t.Fatalf("%d mounts, want 1", n)
	}
}

// A mount that fails leaves the pool degraded, with the reason in
// nfs_mount_missing (observed, then confirmed); once a mount succeeds the
// pool is active again and the condition resolved.
func TestReconcileNFSMounts_FailedMountDegradesThePoolWithTheReason(t *testing.T) {
	s, _ := provableCreateServer(t)
	m := installHostMounts(t)
	nfsPoolRow(t, s, "shared")
	m.setMountErr("mount.nfs: Connection timed out")
	ctx := context.Background()
	s.ReconcileNFSMounts(ctx)
	if st := poolState(t, s, "shared"); st != PoolStateDegraded {
		t.Fatalf("pool state %q with no mount, want %q", st, PoolStateDegraded)
	}
	c, ok := mountCondition(t, s, "shared")
	if !ok || c.Lifecycle != corrosion.ConditionObserved || !strings.Contains(c.Evidence, "Connection timed out") {
		t.Fatalf("condition %+v found=%v; want observed with the mount's reason", c, ok)
	}
	s.ReconcileNFSMounts(ctx)
	if c, _ := mountCondition(t, s, "shared"); c.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("condition lifecycle %q on the second pass, want confirmed", c.Lifecycle)
	}
	m.setMountErr("")
	s.ReconcileNFSMounts(ctx)
	if st := poolState(t, s, "shared"); st != "active" {
		t.Fatalf("pool state %q once mounted, want active", st)
	}
	if c, _ := mountCondition(t, s, "shared"); c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition lifecycle %q once mounted, want resolved", c.Lifecycle)
	}
}

// An unmount while the daemon runs is the operator's: the pass does not
// mount it back, and reports the pool degraded with that reason.
func TestReconcileNFSMounts_OperatorUnmountMidRunIsHonoured(t *testing.T) {
	for _, mountedAtStart := range []bool{true, false} {
		t.Run(fmt.Sprintf("mountedAtStart=%v", mountedAtStart), func(t *testing.T) {
			s, _ := provableCreateServer(t)
			m := installHostMounts(t)
			dir := nfsPoolRow(t, s, "shared")
			if mountedAtStart {
				m.dirs[dir] = nfsTestSource
			}
			ctx := context.Background()
			s.ReconcileNFSMounts(ctx)
			before := m.count()
			m.umount(dir)
			s.ReconcileNFSMounts(ctx)
			s.ReconcileNFSMounts(ctx)
			if m.mounted(dir) || m.count() != before {
				t.Fatal("the pass mounted back what the operator unmounted")
			}
			if st := poolState(t, s, "shared"); st != PoolStateDegraded {
				t.Fatalf("pool state %q after an unmount, want %q", st, PoolStateDegraded)
			}
			if c, ok := mountCondition(t, s, "shared"); !ok || !strings.Contains(c.Evidence, "unmounted while the daemon ran") {
				t.Fatalf("condition %+v found=%v; want the unmount reason", c, ok)
			}
		})
	}
}

// Never over local data: a mount point holding files is not mounted over,
// and the pool is degraded naming them.
func TestReconcileNFSMounts_NonEmptyMountPointIsNotMountedOver(t *testing.T) {
	s, _ := provableCreateServer(t)
	m := installHostMounts(t)
	dir := nfsPoolRow(t, s, "shared")
	if err := os.WriteFile(filepath.Join(dir, "stray.qcow2"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.ReconcileNFSMounts(context.Background())
	if m.count() != 0 || m.mounted(dir) {
		t.Fatal("the pass mounted over a directory holding files")
	}
	if st := poolState(t, s, "shared"); st != PoolStateDegraded {
		t.Fatalf("pool state %q, want %q", st, PoolStateDegraded)
	}
	if c, ok := mountCondition(t, s, "shared"); !ok || !strings.Contains(c.Evidence, "stray.qcow2") {
		t.Fatalf("condition %+v found=%v; want the local file named", c, ok)
	}
}

// A deleted pool is not mounted back, and its condition is resolved.
func TestReconcileNFSMounts_DeletedPoolIsNotResurrected(t *testing.T) {
	s, _ := provableCreateServer(t)
	m := installHostMounts(t)
	nfsPoolRow(t, s, "shared")
	m.setMountErr("mount.nfs: Connection timed out")
	ctx := context.Background()
	s.ReconcileNFSMounts(ctx)
	if err := corrosion.MarkStoragePoolDeleted(ctx, s.db, s.hostName, "shared"); err != nil {
		t.Fatal(err)
	}
	m.setMountErr("")
	before := m.count()
	s.ReconcileNFSMounts(ctx)
	if m.count() != before {
		t.Fatal("a deleted pool was mounted")
	}
	if _, ok, _ := corrosion.GetStoragePool(ctx, s.db, s.hostName, "shared"); ok {
		t.Fatal("a deleted pool's row was written back")
	}
	if c, _ := mountCondition(t, s, "shared"); c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("a deleted pool's condition is %q, want resolved", c.Lifecycle)
	}
}

// No nfs pool: nothing is mounted or read.
func TestReconcileNFSMounts_NoNFSPoolNoMounts(t *testing.T) {
	s, _ := provableCreateServer(t)
	m := installHostMounts(t)
	iscsiPoolRow(t, s, "san", "10.0.0.5:3260")
	s.ReconcileNFSMounts(context.Background())
	if m.count() != 0 {
		t.Fatal("a mount was run with no nfs pool")
	}
}

// The start path, before any pass (or after one that failed): a VM whose
// disk is on an nfs pool not mounted since the daemon started mounts it.
func TestPrepareHardwareForStart_MountsAMissingNFSPool(t *testing.T) {
	s, _ := provableCreateServer(t)
	m := installHostMounts(t)
	dir := nfsPoolRow(t, s, "shared")
	vm := nfsDiskVM(t, s, "shared", dir)
	if _, err := s.PrepareHardwareForStart(context.Background(), &vm); err != nil {
		t.Fatalf("start preflight: %v", err)
	}
	if !m.mounted(dir) {
		t.Fatal("the start did not mount the pool")
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), &vm); err != nil || m.count() != 1 {
		t.Fatalf("second start: err=%v mounts=%d; want no new mount", err, m.count())
	}
}

// The start path refuses, with a clear message, a VM whose nfs pool the
// operator unmounted (it does not mount it back), one whose mount fails, and
// one whose mount point holds local files (it would start on them, not on the
// export).
func TestPrepareHardwareForStart_RefusesAnAbsentNFSMount(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, s *Server, m *hostMounts, dir string)
		want  string
	}{
		{"operator unmount", func(t *testing.T, s *Server, m *hostMounts, dir string) {
			s.ReconcileNFSMounts(context.Background())
			m.umount(dir)
		}, "unmounted while the daemon ran"},
		{"mount fails", func(t *testing.T, s *Server, m *hostMounts, dir string) {
			m.setMountErr("mount.nfs: Connection timed out")
		}, "Connection timed out"},
		{"local files", func(t *testing.T, s *Server, m *hostMounts, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "nfsvm-root.qcow2"), []byte("stale"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "holds local files"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := provableCreateServer(t)
			m := installHostMounts(t)
			dir := nfsPoolRow(t, s, "shared")
			vm := nfsDiskVM(t, s, "shared", dir)
			tc.setup(t, s, m, dir)
			before := m.count()
			_, err := s.PrepareHardwareForStart(context.Background(), &vm)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), `"shared"`) {
				t.Fatalf("err = %v; want a refusal naming the pool and %q", err, tc.want)
			}
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("code %v, want Unavailable (retried, as the failed start always was)", status.Code(err))
			}
			if tc.name != "mount fails" && m.count() != before {
				t.Fatal("the start mounted")
			}
		})
	}
}

// A daemon-config pool's row carries no mount options: the mount takes them
// from the config definition.
func TestReconcileNFSMounts_ConfigPoolUsesItsConfiguredOptions(t *testing.T) {
	s, _ := provableCreateServer(t)
	m := installHostMounts(t)
	nfsPoolRow(t, s, "shared")
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"shared": {
		Driver: "nfs", Source: nfsTestSource, Options: map[string]string{"options": "vers=3,hard"},
	}})
	s.ReconcileNFSMounts(context.Background())
	if !strings.HasPrefix(m.lastOpts, "vers=3,hard,") {
		t.Fatalf("mounted with %q, want the configured vers=3,hard first", m.lastOpts)
	}
}

// A start does not retry a mount the pass saw fail moments ago: it is
// refused with that failure at once.
func TestPrepareHardwareForStart_NFSHookDoesNotRetryAFreshFailure(t *testing.T) {
	s, _ := provableCreateServer(t)
	m := installHostMounts(t)
	dir := nfsPoolRow(t, s, "shared")
	vm := nfsDiskVM(t, s, "shared", dir)
	m.setMountErr("mount.nfs: Connection timed out")
	s.ReconcileNFSMounts(context.Background())
	before := m.count()
	_, err := s.PrepareHardwareForStart(context.Background(), &vm)
	if err == nil || !strings.Contains(err.Error(), "failed moments ago") || !strings.Contains(err.Error(), "Connection timed out") {
		t.Fatalf("err = %v; want the recent failure", err)
	}
	if m.count() != before {
		t.Fatal("the start retried a mount that failed moments ago")
	}
}

// A pool whose directory lies inside another NFS mount is not mounted at,
// and its VM's start is neither refused nor mounts anything.
func TestPrepareHardwareForStart_PoolInsideAnotherNFSMountIsLeftAlone(t *testing.T) {
	s, _ := provableCreateServer(t)
	m := installHostMounts(t)
	parent := filepath.Join(t.TempDir(), "nfsroot")
	m.dirs[parent] = "10.0.0.21:/srv"
	dir := nfsPoolRowAt(t, s, "shared", nfsTestSource, filepath.Join(parent, "lv"))
	vm := nfsDiskVM(t, s, "shared", dir)
	if _, err := s.PrepareHardwareForStart(context.Background(), &vm); err != nil {
		t.Fatalf("start on a pool inside another NFS mount: %v", err)
	}
	s.ReconcileNFSMounts(context.Background())
	if m.count() != 0 {
		t.Fatal("mounted over a directory inside another NFS mount")
	}
	if st := poolState(t, s, "shared"); st != "active" {
		t.Fatalf("pool state %q, want active", st)
	}
}

// Under nfsMu a start judges again: a mount made meanwhile (by a pass) is not
// made twice; a mount the pass saw fail meanwhile is not retried at once; a
// pool deleted meanwhile is not mounted back.
func TestPrepareHardwareForStart_NFSRejudgesUnderTheLock(t *testing.T) {
	for _, tc := range []struct {
		name    string
		between func(t *testing.T, s *Server, m *hostMounts)
		wantErr string
		mounts  int
	}{
		{"mounted meanwhile", func(t *testing.T, s *Server, m *hostMounts) {
			s.ReconcileNFSMounts(context.Background())
		}, "", 1},
		{"failed meanwhile", func(t *testing.T, s *Server, m *hostMounts) {
			m.setMountErr("mount.nfs: Connection timed out")
			s.ReconcileNFSMounts(context.Background())
		}, "failed moments ago", 1},
		{"deleted meanwhile", func(t *testing.T, s *Server, m *hostMounts) {
			if err := corrosion.MarkStoragePoolDeleted(context.Background(), s.db, s.hostName, "shared"); err != nil {
				t.Error(err)
			}
		}, "deleted or replaced", 0},
		{"re-created at another target meanwhile", func(t *testing.T, s *Server, m *hostMounts) {
			if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
				HostName: s.hostName, Name: "shared", Driver: "nfs", Source: nfsTestSource, Target: t.TempDir(), State: "active",
			}); err != nil {
				t.Error(err)
			}
		}, "deleted or replaced", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := provableCreateServer(t)
			m := installHostMounts(t)
			dir := nfsPoolRow(t, s, "shared")
			vm := nfsDiskVM(t, s, "shared", dir)
			nfsStartBeforeLock = func() { tc.between(t, s, m) }
			t.Cleanup(func() { nfsStartBeforeLock = nil })
			_, err := s.PrepareHardwareForStart(context.Background(), &vm)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("start: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("err = %v; want %q", err, tc.wantErr)
			}
			if m.count() != tc.mounts {
				t.Fatalf("%d mounts, want %d", m.count(), tc.mounts)
			}
		})
	}
}

// A start that finds the export mounted marks it seen: an unmount after it is
// honoured by the pass, even when no pass saw it mounted first.
func TestPrepareHardwareForStart_MarksAMountedExportSeen(t *testing.T) {
	s, _ := provableCreateServer(t)
	m := installHostMounts(t)
	dir := nfsPoolRow(t, s, "shared")
	m.dirs[dir] = nfsTestSource // mounted by a create's Prepare, before any pass
	vm := nfsDiskVM(t, s, "shared", dir)
	if _, err := s.PrepareHardwareForStart(context.Background(), &vm); err != nil {
		t.Fatal(err)
	}
	m.umount(dir)
	s.ReconcileNFSMounts(context.Background())
	if m.count() != 0 || m.mounted(dir) {
		t.Fatal("the pass mounted back an export unmounted after a start saw it")
	}
	if st := poolState(t, s, "shared"); st != PoolStateDegraded {
		t.Fatalf("pool state %q, want %q", st, PoolStateDegraded)
	}
}

// A hand mount of the pool's export spelled another way (a host name where
// the pool has the address) is a mount: the start goes ahead, as on main.
func TestPrepareHardwareForStart_AHandMountSpelledOtherwiseIsAMount(t *testing.T) {
	s, _ := provableCreateServer(t)
	m := installHostMounts(t)
	dir := nfsPoolRow(t, s, "shared")
	m.dirs[dir] = "nas.example:/srv/lv"
	vm := nfsDiskVM(t, s, "shared", dir)
	if _, err := s.PrepareHardwareForStart(context.Background(), &vm); err != nil {
		t.Fatalf("start on a hand-mounted export: %v", err)
	}
	s.ReconcileNFSMounts(context.Background())
	if m.count() != 0 {
		t.Fatal("mounted over a hand mount")
	}
	if st := poolState(t, s, "shared"); st != "active" {
		t.Fatalf("pool state %q with its export hand-mounted, want active", st)
	}
}

// The refusal is counted under its own reason, not a hardware one.
func TestPrepareHardwareForStart_NFSRefusalIsAStorageRefusal(t *testing.T) {
	s, _ := provableCreateServer(t)
	m := installHostMounts(t)
	dir := nfsPoolRow(t, s, "shared")
	vm := nfsDiskVM(t, s, "shared", dir)
	m.setMountErr("mount.nfs: Connection timed out")
	_, err := s.PrepareHardwareForStart(context.Background(), &vm)
	if !errors.Is(err, health.ErrStartStorageNotMounted) || status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v (code %v); want ErrStartStorageNotMounted and Unavailable", err, status.Code(err))
	}
}

// A pool delete holds nfsMu across its teardown and row delete: a pass that
// listed the pool before the delete waits, then finds the row gone and does
// not mount it back.
func TestReconcileNFSMounts_PoolDeleteSerialisesWithThePass(t *testing.T) {
	s, _ := provableCreateServer(t)
	m := installHostMounts(t)
	nfsPoolRow(t, s, "shared")
	release := make(chan struct{})
	m.gate, m.entered = release, make(chan struct{}, 1)
	deleted := make(chan error, 1)
	nfsPassAfterList = func() {
		go func() {
			_, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "shared"})
			deleted <- err
		}()
		<-m.entered // the delete is in its teardown
		time.AfterFunc(200*time.Millisecond, func() { close(release) })
	}
	t.Cleanup(func() { nfsPassAfterList = nil })
	s.ReconcileNFSMounts(context.Background())
	if err := <-deleted; err != nil {
		t.Fatalf("delete: %v", err)
	}
	if m.count() != 0 {
		t.Fatal("the pass mounted a pool deleted while it ran")
	}
}

// I-1: a check that blocks — resolving a symlink into an NFS mount whose
// server does not answer — holds no lock (another pool's delete completes
// meanwhile), and gives up within its bound (the pass goes on to mount the
// other pools).
func TestReconcileNFSMounts_AHungCheckWedgesNothing(t *testing.T) {
	s, _ := provableCreateServer(t)
	m := installHostMounts(t)
	hung := filepath.Join(t.TempDir(), "hung")
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	t.Cleanup(storage.OverrideNFSPathResolverForTest(func(p string) string {
		if p == hung {
			<-release
		}
		return p
	}, 2*time.Second))
	nfsPoolRowAt(t, s, "a-hung", "10.0.0.31:/a", filepath.Join(hung, "lv"))
	okDir := nfsPoolRowAt(t, s, "b-ok", "10.0.0.32:/b", "")
	nfsPoolRowAt(t, s, "c-del", "10.0.0.33:/c", "")
	pass := make(chan struct{})
	go func() {
		s.ReconcileNFSMounts(context.Background())
		close(pass)
	}()
	time.Sleep(300 * time.Millisecond) // the pass is in a-hung's check
	delDone := make(chan error, 1)
	go func() {
		_, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "c-del"})
		delDone <- err
	}()
	select {
	case err := <-delDone:
		if err != nil {
			t.Fatalf("delete: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("a pool delete waited on a pass stuck in a check")
	}
	select {
	case <-pass:
	case <-time.After(10 * time.Second):
		t.Fatal("the pass did not give up on a check that does not finish")
	}
	if !m.mounted(okDir) {
		t.Fatal("the pass did not mount the other pool")
	}
	if c, ok := mountCondition(t, s, "a-hung"); !ok || !strings.Contains(c.Evidence, "did not finish") {
		t.Fatalf("a-hung's condition %+v found=%v; want the check's reason", c, ok)
	}
}

// nfsMu gives up when the waiter's context ends: while a pool delete holds it
// (its teardown stalled), a start that needs a mount is refused, and another
// nfs pool's delete answers Unavailable, both promptly.
func TestNFSMu_WaitersGiveUpWithTheirContext(t *testing.T) {
	s, _ := provableCreateServer(t)
	m := installHostMounts(t)
	dir := nfsPoolRow(t, s, "shared")
	vm := nfsDiskVM(t, s, "shared", dir)
	nfsPoolRowAt(t, s, "held", "10.0.0.41:/held", "")
	nfsPoolRowAt(t, s, "other", "10.0.0.42:/other", "")
	release := make(chan struct{})
	m.gate, m.entered = release, make(chan struct{}, 1)
	held := make(chan error, 1)
	go func() {
		_, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "held"})
		held <- err
	}()
	<-m.entered // the delete holds nfsMu, in its teardown
	time.AfterFunc(3*time.Second, func() { close(release) })
	t.Cleanup(func() { <-held })

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	_, err := s.PrepareHardwareForStart(ctx, &vm)
	if err == nil || !strings.Contains(err.Error(), "did not finish in time") || time.Since(t0) > 2*time.Second {
		t.Fatalf("start while nfsMu is held: err=%v after %v; want a prompt refusal", err, time.Since(t0))
	}
	dctx, dcancel := context.WithTimeout(adminCtx(), 300*time.Millisecond)
	defer dcancel()
	t0 = time.Now()
	_, err = s.DeleteStoragePool(dctx, &pb.DeleteStoragePoolRequest{Name: "other"})
	if status.Code(err) != codes.Unavailable || time.Since(t0) > 2*time.Second {
		t.Fatalf("delete while nfsMu is held: err=%v after %v; want a prompt Unavailable", err, time.Since(t0))
	}
}
