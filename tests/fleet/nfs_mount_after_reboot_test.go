// Fleet scenario for an nfs pool's mount after a host reboot (lab 2 finding
// N-1): the host whose export is not mounted mounts it, and while it cannot,
// every node sees the pool as degraded, with the reason, instead of active,
// and a start of a VM on it is refused with that reason through any node.

package fleet

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

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// rebootedMounts is a host's mount table after a reboot: nothing mounted,
// and a mount fails while failMount is set.
type rebootedMounts struct {
	mu        sync.Mutex
	dirs      map[string]string
	failMount bool
	mounts    int
}

type notAMountpoint struct{}

func (notAMountpoint) Error() string { return "exit status 32" }
func (notAMountpoint) ExitCode() int { return 32 }

func (f *rebootedMounts) info() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b strings.Builder
	b.WriteString("22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n")
	i := 0
	for dir, src := range f.dirs {
		fmt.Fprintf(&b, "%d 22 0:%d / %s rw,nosuid,nodev,noexec - nfs4 %s rw\n", 100+i, 50+i, dir, src)
		i++
	}
	return []byte(b.String()), nil
}

func (f *rebootedMounts) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch name {
	case "mountpoint":
		if _, ok := f.dirs[args[len(args)-1]]; ok {
			return nil, nil
		}
		return nil, notAMountpoint{}
	case "mount":
		f.mounts++
		if f.failMount {
			return []byte("mount.nfs: Connection timed out"), errors.New("exit status 32")
		}
		f.dirs[args[len(args)-1]] = args[len(args)-2]
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected %s %q", name, args)
}

func (f *rebootedMounts) set(fail bool) {
	f.mu.Lock()
	f.failMount = fail
	f.mu.Unlock()
}

func TestFleet_NFSPoolNotMountedIsDegradedEverywhereAndRefusesStartsUntilMounted(t *testing.T) {
	mt := &rebootedMounts{dirs: map[string]string{}, failMount: true}
	t.Cleanup(storage.OverrideNosymfollowSupportForTest(false))
	t.Cleanup(storage.OverrideMountInfoForTest(mt.info))
	t.Cleanup(storage.OverrideNFSMountCommandForTest(mt.run))
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 1013})
	owner, peer := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	const source = "10.9.9.21:/srv/lv"
	if err := corrosion.UpsertStoragePool(ctx, owner.DB, corrosion.StoragePoolRecord{
		HostName: owner.Name, Name: "shared", Driver: "nfs", Source: source, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	dir := storage.NFSPoolMountDir(filepath.Join(c.tmpRoot, owner.Name, "data"), storage.Config{Driver: "nfs", Source: source})
	if err := os.MkdirAll(dir, 0o755); err != nil { // the empty directory a reboot leaves
		t.Fatal(err)
	}
	vm := corrosion.VMRecord{Name: "nfsvm", HostName: owner.Name, State: "stopped", CPUActual: 1, MemActual: 256,
		Spec: `{"name":"nfsvm","cpu":1,"memory_mib":256}`}
	if err := corrosion.InsertVM(ctx, owner.DB, vm, nil, []corrosion.DiskRecord{{
		VMName: "nfsvm", DiskName: "root", HostName: owner.Name, StorageType: "nfs", StorageVolume: "shared",
		Path: filepath.Join(dir, "nfsvm-root.qcow2"), SizeBytes: 1 << 30, TargetDev: "vda",
	}}); err != nil {
		t.Fatal(err)
	}

	stateOnPeer := func() string {
		resp, err := c.SelfClient(peer).ListStoragePools(ctx, &pb.ListStoragePoolsRequest{})
		if err != nil {
			return ""
		}
		for _, p := range resp.Pools {
			if p.Host == owner.Name && p.Name == "shared" {
				return p.State
			}
		}
		return ""
	}
	conditionOnPeer := func() (corrosion.HealthCondition, bool) {
		cond, ok, err := corrosion.GetHealthCondition(ctx, peer.DB, "nfs_pool", "nfs_mount_missing", "host", "shared@"+owner.Name)
		return cond, ok && err == nil
	}

	owner.Server.ReconcileNFSMounts(ctx)
	eventually(t, 20*time.Second, "the peer to see the pool degraded with the reason", func() bool {
		cond, ok := conditionOnPeer()
		return stateOnPeer() == "degraded" && ok && cond.Lifecycle != corrosion.ConditionResolved &&
			strings.Contains(cond.Evidence, "Connection timed out")
	})

	// The owner's start is refused with the reason, and the guest is not
	// started on the empty local directory.
	_, err := c.SelfClient(owner).StartVM(ctx, &pb.StartVMRequest{Name: "nfsvm"})
	if err == nil || !strings.Contains(err.Error(), `nfs pool "shared"`) || !strings.Contains(err.Error(), "not mounted") {
		t.Fatalf("lv start nfsvm with its export not mounted: %v; want a refusal naming the pool", err)
	}
	if st, _ := owner.Virt.DomainState("nfsvm"); st == "running" {
		t.Fatal("nfsvm was started with its export not mounted")
	}

	mt.set(false)
	owner.Server.ReconcileNFSMounts(ctx)
	eventually(t, 20*time.Second, "the peer to see the pool active and the condition resolved", func() bool {
		cond, ok := conditionOnPeer()
		return stateOnPeer() == "active" && ok && cond.Lifecycle == corrosion.ConditionResolved
	})
	if _, err := owner.Server.PrepareHardwareForStart(ctx, &vm); err != nil {
		t.Fatalf("start preflight once mounted: %v", err)
	}
}
