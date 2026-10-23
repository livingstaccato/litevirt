// Fleet scenario: a storage_pools row naming a host is acted on only when that
// host stands behind it (internal/pooltrust).
//
// storage_pools is replicated, and the apply checks no origin: a row that one
// member writes naming ANOTHER host reaches that host through the real push
// loop like any other. Before the trust ledger, the named host took such a
// row as one of its own pools, and a cold-migration receive, an upload or a
// content delete then wrote or removed files as root wherever the row
// pointed. Three nodes: node-0 is the member that forges, node-1 the host it
// names, node-2 an operator's entry node. Only a real multi-node fleet carries
// the forged row by replication and drives the receive from another daemon.
package fleet

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/pooltrust"
)

// The forged row, replicated from node-0, names a directory on node-1
// outside its pool areas. node-1 refuses it for a cold-migration receive
// (even with it in its in-memory pool map, where the daemon's refresh used to
// put every row), for an upload and for a content delete driven through
// node-2; nothing is written or removed there. A pool created for node-1
// through node-2 is recorded in node-1's ledger, not node-2's, and works.
// `lv pool trust` through node-2 makes the forged directory node-1's pool, and
// the same migration then lands its disk there — the positive control that
// shows the refusals above are the trust check and nothing else.
//
// Mutations: drop the trust check from poolRefusal — the receive lands the
// disk in the forged directory and the upload writes there, red; drop the
// ledger Record from CreateStoragePool — the created pool's upload is
// refused, red.
func TestFleet_PoolTrust_AForgedRowIsNoDiskRootAcrossTheCluster(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.openClusterPolicyGate()
	t.Cleanup(c.Stop)
	ctx := context.Background()
	attacker, target, entry := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	for _, n := range c.Nodes {
		pt, err := pooltrust.Open(filepath.Join(c.tmpRoot, n.Name, "data"), n.PKIDir)
		if err != nil {
			t.Fatal(err)
		}
		n.Server.SetPoolTrust(pt)
		n.Server.SetHostDiskRootForTest(filepath.Join(c.tmpRoot, "fs-"+n.Name))
	}
	onHost := func(n *Node, p string) string { return filepath.Join(c.tmpRoot, "fs-"+n.Name, p) }

	// A stopped VM on node-0 whose disk is in the directory the forged row
	// names: the receive on node-1 is asked to create it there.
	pwn := filepath.Join(c.tmpRoot, "srv-pwn")
	disk := filepath.Join(pwn, "os1-root.qcow2")
	payload := []byte(strings.Repeat("attacker-chosen bytes ", 4096))
	if err := os.MkdirAll(filepath.Dir(onHost(attacker, disk)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(onHost(attacker, disk), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "os1", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, attacker.DB, corrosion.VMRecord{
		Name: "os1", HostName: attacker.Name, State: "stopped", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{
		{VMName: "os1", DiskName: "root", HostName: attacker.Name, Path: disk, SizeBytes: int64(len(payload)), StorageType: "dir", TargetDev: "vda"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := attacker.Virt.DefineDomain(`<domain type='kvm'><name>os1</name><uuid>11111111-2222-4333-8444-555555555556</uuid><devices>` +
		`<disk type='file' device='disk'><driver name='qemu' type='raw'/><source file='` + disk + `'/><target dev='vda'/></disk>` +
		`</devices></domain>`); err != nil {
		t.Fatal(err)
	}

	// The forgery: node-0 writes a row naming node-1, and replication carries it.
	if err := corrosion.UpsertStoragePool(ctx, attacker.DB, corrosion.StoragePoolRecord{
		HostName: target.Name, Name: "pwn", Driver: "dir", Target: pwn, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(pwn, "victim.iso")
	if err := os.MkdirAll(pwn, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("victim"), 0o644); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	if _, ok, _ := corrosion.GetStoragePool(ctx, target.DB, target.Name, "pwn"); !ok {
		t.Fatal("the forged row did not reach node-1 by replication")
	}
	// What the daemon's pool refresh did with every row naming the host.
	target.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"pwn": {Driver: "dir", Target: pwn}})

	migrate := func() error {
		st, err := c.SelfClient(attacker).MigrateVM(ctx, &pb.MigrateVMRequest{
			VmName: "os1", TargetHost: target.Name, Strategy: pb.MigrateStrategy_MIGRATE_COLD,
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
	if err := migrate(); err == nil {
		t.Error("receive: node-1 accepted a cold-migration disk into a forged row's directory")
	} else {
		t.Logf("receive refused: %v", err)
	}
	if _, err := os.Lstat(onHost(target, disk)); err == nil {
		t.Fatal("receive: node-1 created a file in a forged row's directory")
	}

	operator := c.SelfClient(entry)
	upload := func(pool, name string) error {
		up, err := operator.UploadStoragePoolContent(ctx)
		if err != nil {
			return err
		}
		if err := up.Send(&pb.UploadStoragePoolContentRequest{PoolName: pool, Host: target.Name, Filename: name}); err != nil {
			return err
		}
		if err := up.Send(&pb.UploadStoragePoolContentRequest{Chunk: []byte(name)}); err != nil {
			return err
		}
		_, err = up.CloseAndRecv()
		return err
	}
	if err := upload("pwn", "pwn.iso"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("upload into the forged row's directory through node-2: %v, want FailedPrecondition", err)
	}
	if _, err := os.Lstat(filepath.Join(pwn, "pwn.iso")); err == nil {
		t.Error("upload: a file was written into the forged row's directory")
	}
	if _, err := operator.DeleteStoragePoolContent(ctx, &pb.DeleteStoragePoolContentRequest{PoolName: "pwn", Host: target.Name, Filename: "victim.iso"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("content delete in the forged row's directory through node-2: %v, want FailedPrecondition", err)
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "victim" {
		t.Errorf("content delete changed %s: %q %v", victim, b, err)
	}
	target.Server.JudgePoolTrust(ctx)
	if row, found, _ := corrosion.GetHealthCondition(ctx, target.DB, "pool_trust", "pool_row_untrusted", "host", target.Name); !found ||
		row.Lifecycle == corrosion.ConditionResolved || !strings.Contains(row.Evidence, `"pwn"`) {
		t.Errorf("node-1's pool_row_untrusted = %+v (found %t), want raised naming pwn", row, found)
	}

	// A pool created for node-1 through node-2 runs on node-1: its ledger
	// records it, node-2's does not, and it works.
	made := filepath.Join(c.tmpRoot, "srv-made")
	if err := os.MkdirAll(made, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := operator.CreateStoragePool(ctx, &pb.CreateStoragePoolRequest{Name: "made", Driver: "dir", Target: made, Host: target.Name}); err != nil {
		t.Fatalf("create a pool for node-1 through node-2: %v", err)
	}
	if _, ok := target.Server.PoolTrust().Entry("made"); !ok {
		t.Error("node-1's ledger does not record the pool created for it")
	}
	if _, ok := entry.Server.PoolTrust().Entry("made"); ok {
		t.Error("node-2's ledger records a pool it forwarded, not one of its own")
	}
	c.WaitConverged(t, convergeTimeout) // node-2 reads the row before it forwards
	if err := upload("made", "ok.iso"); err != nil {
		t.Errorf("upload into the pool created for node-1: %v", err)
	}

	// `lv pool trust pwn --host node-1`, through node-2: node-1 stands behind
	// the row now, and the same receive lands.
	if _, err := operator.TrustStoragePool(ctx, &pb.TrustStoragePoolRequest{Name: "pwn", Host: target.Name, Driver: "dir", Target: pwn}); err != nil {
		t.Fatalf("trust the row on node-1 through node-2: %v", err)
	}
	if _, ok := target.Server.PoolTrust().Entry("pwn"); !ok {
		t.Fatal("node-1's ledger does not record the confirmed pool")
	}
	if _, ok := entry.Server.PoolTrust().Entry("pwn"); ok {
		t.Error("node-2's ledger records the confirmation it forwarded")
	}
	deadline := time.Now().Add(10 * time.Second)
	var merr error
	for time.Now().Before(deadline) {
		if merr = migrate(); merr == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if merr != nil {
		t.Fatalf("the positive control: the migration into the confirmed pool failed: %v", merr)
	}
	if got, err := os.ReadFile(onHost(target, disk)); err != nil || string(got) != string(payload) {
		t.Fatalf("the positive control: the disk did not land in the confirmed pool on node-1 (%v)", err)
	}
	target.Server.JudgePoolTrust(ctx)
	if row, _, _ := corrosion.GetHealthCondition(ctx, target.DB, "pool_trust", "pool_row_untrusted", "host", target.Name); row.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("node-1's pool_row_untrusted is %s once the row is confirmed, want resolved", row.Lifecycle)
	}
}
