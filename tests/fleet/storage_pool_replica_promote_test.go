// Fleet scenario: a VM's cross-host replicas, kept in a pool on the replica
// host's <data_dir>/disks (an older cluster's default pool), stay promotable.
//
// The replication runner on the VM's host copies the disk into the peer's
// pool over the real UploadStoragePoolContent RPC; failover's automatic
// promotion and an operator's manual one then list the peer's pool over a
// real peer call and relay the promotion there. Only two real nodes prove
// the replica lands where the relayed promotion looks for it.
package fleet

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

func TestFleet_ReplicaInADisksPoolIsPromotableAcrossHosts(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	vmHost, replicaHost := c.Node("node-0"), c.Node("node-1")
	disks := filepath.Join(c.tmpRoot, replicaHost.Name, "data", "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, replicaHost.DB, corrosion.StoragePoolRecord{
		HostName: replicaHost.Name, Name: "default", Driver: "local", Target: disks, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	// Unowned debris an older node's call and on-node root still see.
	if err := os.WriteFile(filepath.Join(disks, "stray.qcow2"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, vm := range []string{"web", "api"} {
		src := filepath.Join(c.tmpRoot, vmHost.Name, vm+"-root-src.qcow2")
		if err := qcow2.Create(src, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		spec, _ := json.Marshal(&pb.VMSpec{Name: vm, Cpu: 1, MemoryMib: 256})
		if err := corrosion.InsertVM(ctx, vmHost.DB, corrosion.VMRecord{
			Name: vm, HostName: vmHost.Name, State: "running", Spec: string(spec),
		}, nil, []corrosion.DiskRecord{{
			VMName: vm, DiskName: "root", HostName: vmHost.Name, Path: src, SizeBytes: 1 << 20, StorageType: "local",
		}}); err != nil {
			t.Fatal(err)
		}
		sched := corrosion.BackupScheduleRecord{
			VMName: vm, Scope: "vm", Repo: "default", Cron: "0 * * * *", Enabled: true,
			Type: "replication", TargetPool: "default", TargetHost: replicaHost.Name, KeepReplicas: 1,
		}
		if err := corrosion.UpsertBackupSchedule(ctx, vmHost.DB, sched); err != nil {
			t.Fatal(err)
		}
		// Two runs: the second prunes the first through the peer.
		for _, ago := range []time.Duration{20 * time.Minute, 10 * time.Minute} {
			if err := vmHost.Server.RunReplication(ctx, sched, time.Now().Add(-ago)); err != nil {
				t.Fatalf("replicate %s to %s: %v", vm, replicaHost.Name, err)
			}
		}
		var reps []string
		ents, _ := os.ReadDir(disks)
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), vm+"-root-") && strings.HasSuffix(e.Name(), ".qcow2") {
				reps = append(reps, e.Name())
			}
		}
		if len(reps) != 1 {
			t.Fatalf("%s's replicas among the disks = %v, want the newest one (kept 1)", vm, reps)
		}
	}

	if err := vmHost.Server.AutoPromoteReplica(ctx, "web", "", 0); err != nil {
		t.Errorf("automatic promotion of web's replica on %s: %v", replicaHost.Name, err)
	}
	st, err := c.SelfClient(vmHost).PromoteReplica(ctx, &pb.PromoteReplicaRequest{VmName: "api", Force: true})
	if err == nil {
		for {
			if _, err = st.Recv(); err != nil {
				break
			}
		}
		if err == io.EOF {
			err = nil
		}
	}
	if err != nil {
		t.Errorf("manual promotion of api's replica on %s: %v", replicaHost.Name, err)
	}
	for _, vm := range []string{"web", "api"} {
		if !replicaHost.Virt.DomainExists(vm) {
			t.Errorf("%s was not promoted on %s", vm, replicaHost.Name)
		}
	}

	// A bearerless host-certificate call and root on the node itself see and
	// change every file, as on main. (Every fleet node listens on 127.0.0.1,
	// so both classify as on-node root here; a remote bearerless peer is
	// covered by TestPoolRound6_BearerlessHostCertCallersSeeEverything.)
	list := func(cl pb.LiteVirtClient) []string {
		resp, err := cl.ListStoragePoolContents(ctx, &pb.ListStoragePoolContentsRequest{PoolName: "default", Host: replicaHost.Name})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		var out []string
		for _, f := range resp.GetContents() {
			out = append(out, f.GetName())
		}
		sort.Strings(out)
		return out
	}
	if got := list(c.PeerClient(vmHost, replicaHost)); !slices.Contains(got, "stray.qcow2") {
		t.Errorf("an older node's bearerless listing = %v, lacks stray.qcow2", got)
	}
	root := c.SelfClient(replicaHost)
	if got := list(root); !slices.Contains(got, "stray.qcow2") {
		t.Errorf("on-node root's listing = %v, lacks stray.qcow2", got)
	}
	if _, err := root.DeleteStoragePoolContent(ctx, &pb.DeleteStoragePoolContentRequest{PoolName: "default", Host: replicaHost.Name, Filename: "stray.qcow2"}); err != nil {
		t.Errorf("on-node root deleting an unowned file: %v", err)
	}
}
