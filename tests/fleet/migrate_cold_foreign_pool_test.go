// Fleet scenario: a cold migration of a stopped VM whose host-local disk sits in
// the SOURCE host's default pool, when the target's default pool is elsewhere.
//
// A witness founded by a current build keeps its default pool at
// <data_dir>/pools/default; the workers of an older cluster keep theirs at
// <data_dir>/disks. The disk of a VM promoted onto such a witness is in the
// first, and the documented way out (lv migrate <vm> <worker> --cold) was
// refused by the worker: `disk path ... is not in a disk-artifact root`,
// because the receiver judged the path by its OWN roots only. The same refusal
// hit a cold migration off any host whose default pool differs from the
// target's. The source's replicated pool rows now count, and nothing else
// widens: a path outside them, or in a pool row that names the target's state,
// is still refused.

package fleet

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

type foreignPoolScenario struct {
	c        *Cluster
	src, dst *Node
	pool     string // the source's default pool directory
	disk     string // the recorded path of the VM's host-local disk
	payload  []byte
}

// newForeignPoolScenario is a stopped VM fp1 on node 0 whose disk is at path
// (default: in node 0's pools/default), with a storage_pools row for node 0's
// default pool at pool and node 1's default pool at its own disks dir.
func newForeignPoolScenario(t *testing.T, diskPath func(pool, dstData string) string, srcPoolTarget func(pool, dstData string) string) *foreignPoolScenario {
	t.Helper()
	c := New(t, Options{Nodes: 2, SharedCRDT: true, SharedDataDir: true})
	c.openClusterPolicyGate()
	t.Cleanup(c.Stop)
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		n.Server.SetHostDiskRootForTest(filepath.Join(c.tmpRoot, "fs-"+n.Name))
	}
	srcData := filepath.Join(c.tmpRoot, "shared-data")
	dstData := srcData // one data_dir string on every host, as in production
	fp := &foreignPoolScenario{c: c, src: src, dst: dst, pool: filepath.Join(srcData, "pools", "default")}
	fp.disk = diskPath(fp.pool, dstData)
	ctx := context.Background()
	for _, p := range []corrosion.StoragePoolRecord{
		{HostName: src.Name, Name: "default", Driver: "local", Target: srcPoolTarget(fp.pool, dstData), State: "active"},
		{HostName: dst.Name, Name: "default", Driver: "local", Target: filepath.Join(dstData, "disks"), State: "active"},
	} {
		if err := corrosion.UpsertStoragePool(ctx, src.DB, p); err != nil {
			t.Fatal(err)
		}
	}
	// The source has its default pool where its row says (the daemon loads it).
	src.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"default": {Driver: "local", Target: srcPoolTarget(fp.pool, dstData)}})
	fp.payload = make([]byte, 1<<20+77)
	for i := range fp.payload {
		fp.payload[i] = byte(i*13 + 5)
	}
	sp := filepath.Join(c.tmpRoot, "fs-"+src.Name, fp.disk)
	if err := os.MkdirAll(filepath.Dir(sp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sp, fp.payload, 0o600); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "fp1", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{
		Name: "fp1", HostName: src.Name, State: "stopped", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{
		{VMName: "fp1", DiskName: "root", HostName: src.Name, Path: fp.disk, SizeBytes: int64(len(fp.payload)),
			StorageType: "local", StorageVolume: "default", TargetDev: "vda"},
	}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := src.Virt.DefineDomain(`<domain type='kvm'><name>fp1</name><uuid>21111111-2222-4333-8444-555555555555</uuid><devices>` +
		`<disk type='file' device='disk'><driver name='qemu' type='raw'/><source file='` + fp.disk + `'/><target dev='vda'/></disk>` +
		`</devices></domain>`); err != nil {
		t.Fatalf("define source domain: %v", err)
	}
	return fp
}

func (fp *foreignPoolScenario) migrate() error {
	st, err := fp.c.SelfClient(fp.src).MigrateVM(context.Background(), &pb.MigrateVMRequest{
		VmName: "fp1", TargetHost: fp.dst.Name, Strategy: pb.MigrateStrategy_MIGRATE_COLD,
	})
	if err != nil {
		return err
	}
	for {
		if _, rerr := st.Recv(); rerr == io.EOF {
			return nil
		} else if rerr != nil {
			return rerr
		}
	}
}

// The disk is in the source's default pool, which is not under the target's
// disks dir: the move goes, with the disk's bytes, at the same path.
//
// Red on ba91f3c21: the target refuses the copy, `disk path ... is not in a
// disk-artifact root`.
//
// Mutation: ReceiveMigrationDisk back to withinDiskArtifactRoot - the move is
// refused and this goes red.
func TestFleet_ColdMigrationFromAHostWhoseDefaultPoolDiffersFromTheTargets(t *testing.T) {
	fp := newForeignPoolScenario(t,
		func(pool, _ string) string { return filepath.Join(pool, "fp1-root.qcow2") },
		func(pool, _ string) string { return pool })
	if err := fp.migrate(); err != nil {
		t.Fatalf("migrate --cold off a host whose default pool is elsewhere: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(fp.c.tmpRoot, "fs-"+fp.dst.Name, fp.disk))
	if err != nil || string(got) != string(fp.payload) {
		t.Fatalf("the disk did not arrive intact on %s (err %v, %d bytes)", fp.dst.Name, err, len(got))
	}
	vm, _ := corrosion.GetVM(context.Background(), fp.dst.DB, "fp1")
	if vm == nil || vm.HostName != fp.dst.Name || vm.State != "stopped" {
		t.Fatalf("fp1 after the move = %+v, want it stopped on %s", vm, fp.dst.Name)
	}
}

// The widening is only the source's own pool directories: a disk record whose
// path is outside every pool of the source, one that climbs out of its pool
// with .., and a pool row that names the target's data directory are all still
// refused, and nothing reaches the target.
//
// Mutation: accept any absolute path in withinMigrationDiskRoot, or drop
// poolDirTouchesState - the matching case goes red.
func TestFleet_ColdMigrationStillRefusesPathsOutsideTheSourcesPools(t *testing.T) {
	cases := []struct {
		name string
		disk func(pool, dstData string) string
		pool func(pool, dstData string) string
	}{
		{"outside the source's pools",
			func(pool, _ string) string { return filepath.Join(filepath.Dir(pool), "elsewhere", "fp1-root.qcow2") },
			func(pool, _ string) string { return pool }},
		{"climbing out of the pool",
			func(pool, _ string) string { return filepath.Join(pool, "..", "..", "elsewhere", "fp1-root.qcow2") },
			func(pool, _ string) string { return pool }},
		{"a pool row naming the target's data directory",
			func(_, dstData string) string { return filepath.Join(dstData, "state.db") },
			func(_, dstData string) string { return dstData }},
		{"a pool row naming the filesystem root",
			func(_, dstData string) string { return filepath.Join(dstData, "state.db") },
			func(_, _ string) string { return "/" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp := newForeignPoolScenario(t, tc.disk, tc.pool)
			err := fp.migrate()
			if err == nil || !strings.Contains(err.Error(), "not in a disk-artifact root") {
				t.Fatalf("migrate with a disk %s = %v, want the disk-artifact root refusal", tc.name, err)
			}
			if _, serr := os.Stat(filepath.Join(fp.c.tmpRoot, "fs-"+fp.dst.Name, fp.disk)); !os.IsNotExist(serr) {
				t.Errorf("a refused copy still put a file on %s (stat: %v)", fp.dst.Name, serr)
			}
			vm, _ := corrosion.GetVM(context.Background(), fp.src.DB, "fp1")
			if vm == nil || vm.HostName != fp.src.Name {
				t.Errorf("fp1 after the refused move = %+v, want it still on %s", vm, fp.src.Name)
			}
		})
	}
}
