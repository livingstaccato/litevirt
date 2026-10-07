// Fleet scenario: cross-host replication into a pool another project shares.
//
// Project A's VM "web" (disk "1") on node 0 replicates into the global pool
// "dr" on node 1, where project B keeps its VM "web-1" (disk "root") — its live
// disk and its replicas. A's replicas used to be "web-1-<time>.qcow2" in the
// pool and were found by the "web-1-" prefix, so A's pruning on node 1 deleted
// B's files and A's promotion could boot one. Now node 0 uploads each replica
// with its record, node 1 writes it into A's own directory of the pool's
// replica area, and pruning and promotion select by those records only.
//
// Everything crosses real gRPC under the nodes' host certificates: the upload
// with its replica header, PruneReplicas, and ListReplicas behind promotion.

package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

func TestFleet_CrossHostReplicationNeverTouchesAnotherProjectsFiles(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	ctx := context.Background()
	src, dst := c.Nodes[0], c.Nodes[1]

	dr := t.TempDir()
	if err := corrosion.UpsertStoragePool(ctx, dst.DB, corrosion.StoragePoolRecord{
		HostName: dst.Name, Name: "dr", Driver: "dir", Target: dr, State: "active",
	}); err != nil {
		t.Fatalf("UpsertStoragePool: %v", err)
	}

	// Project B on node 1: a stopped VM whose live disk is in dr, and replicas.
	bFiles := map[string][]byte{}
	for _, name := range []string{"web-1-root.qcow2", "web-1-root-20261001-000000.qcow2", "web-1-root-20261002-000000.qcow2"} {
		p := filepath.Join(dr, name)
		if err := qcow2.Create(p, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(p)
		bFiles[name] = data
	}
	bSpec, _ := json.Marshal(&pb.VMSpec{Name: "web-1", Project: "b", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, dst.DB, corrosion.VMRecord{
		Name: "web-1", HostName: dst.Name, State: "stopped", Project: "b", Spec: string(bSpec),
	}, nil, []corrosion.DiskRecord{{
		VMName: "web-1", DiskName: "root", HostName: dst.Name, Path: filepath.Join(dr, "web-1-root.qcow2"),
		StorageType: "dir", StorageVolume: "dr",
	}}); err != nil {
		t.Fatalf("InsertVM web-1: %v", err)
	}

	// Project A on node 0: VM "web", one disk "1".
	own := filepath.Join(t.TempDir(), "web-1.qcow2")
	if err := qcow2.Create(own, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	aSpec, _ := json.Marshal(&pb.VMSpec{Name: "web", Project: "a", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{
		Name: "web", HostName: src.Name, State: "stopped", Project: "a", Spec: string(aSpec),
	}, nil, []corrosion.DiskRecord{{
		VMName: "web", DiskName: "1", HostName: src.Name, Path: own, StorageType: "local",
	}}); err != nil {
		t.Fatalf("InsertVM web: %v", err)
	}

	sched := corrosion.BackupScheduleRecord{
		VMName: "web", Repo: "dr", Type: "replication", TargetPool: "dr", TargetHost: dst.Name, KeepReplicas: 1,
	}
	for i := 0; i < 3; i++ {
		if err := src.Server.RunReplication(ctx, sched, time.Date(2026, 10, 5, 12, i, 0, 0, time.UTC)); err != nil {
			t.Fatalf("RunReplication %d: %v", i, err)
		}
	}

	for name, want := range bFiles {
		got, err := os.ReadFile(filepath.Join(dr, name))
		if err != nil {
			t.Errorf("project B's %s is gone from node 1: %v", name, err)
		} else if !bytes.Equal(got, want) {
			t.Errorf("project B's %s was overwritten", name)
		}
	}

	// A's own replicas: recorded in the replica area, pruned to the newest one.
	var aReplicas []string
	_ = filepath.WalkDir(filepath.Join(dr, ".replicas"), func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() && strings.HasSuffix(p, ".qcow2") {
			if _, rerr := os.Stat(p + ".json"); rerr == nil {
				aReplicas = append(aReplicas, filepath.Base(p))
			}
		}
		return nil
	})
	if len(aReplicas) != 1 || aReplicas[0] != "1-20261005-120200.qcow2" {
		t.Errorf("A's recorded replicas on node 1 = %v, want only the newest", aReplicas)
	}

	// Promotion selects from A's records only: B's file is not A's replica.
	st, err := c.SelfClient(src).PromoteReplica(ctx, &pb.PromoteReplicaRequest{
		VmName: "web", TargetPool: "dr", TargetHost: dst.Name,
		Replica: "web-1-root-20261001-000000.qcow2", NewName: "stolen", NoLocalize: true,
	})
	if err == nil {
		for {
			if _, err = st.Recv(); err != nil {
				break
			}
		}
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("promoting A's VM from B's file on node 1: got %v, want NotFound", err)
	}
}
