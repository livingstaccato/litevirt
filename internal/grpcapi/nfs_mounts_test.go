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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
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
	defer m.mu.Unlock()
	switch name {
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
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: name, Driver: "nfs", Source: nfsTestSource, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(s.dataDir, "mounts", storage.NFSMountName(nfsTestSource))
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
