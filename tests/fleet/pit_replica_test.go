// Fleet scenario: a replica that is not point-in-time is marked as such on the
// host that RECEIVES it, and automatic promotion there holds the VM.
//
// The VM runs on node-0 and replicates to node-1's pool over the real
// PushReplica RPC. node-0 can make no point-in-time copy (its snapshot layer
// fails, and the fleet has no backup sessions), so it falls back to main's
// -U copy. The mark travels in the pushed record; the coordinator's
// promotion lists node-1's replicas over a real peer call, finds only a
// not-point-in-time one and holds the VM rather than relaying a promotion;
// an operator's promotion with the accept flag relays and runs on node-1.
// Only two real nodes prove the mark survives the wire and is read back on
// the other side.
package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Mutation "mark dropped on the receiver": PushReplica records the replica
// without NotPointInTime — red.
func TestFleet_NotPointInTimeReplicaIsMarkedAcrossHostsAndHeld(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	vmHost, replicaHost := c.Node("node-0"), c.Node("node-1")
	vmHost.Virt.SetPITFailures(errors.New("snapshot refused"), nil)
	dr := filepath.Join(c.tmpRoot, replicaHost.Name, "data", "dr")
	if err := os.MkdirAll(dr, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, replicaHost.DB, corrosion.StoragePoolRecord{
		HostName: replicaHost.Name, Name: "dr", Driver: "local", Target: dr, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(c.tmpRoot, vmHost.Name, "web-root.qcow2")
	if err := qcow2.Create(src, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, vmHost.DB, corrosion.VMRecord{
		Name: "web", HostName: vmHost.Name, State: "running", Spec: string(spec),
	}, nil, []corrosion.DiskRecord{{
		VMName: "web", DiskName: "root", HostName: vmHost.Name, Path: src, SizeBytes: 1 << 20, StorageType: "local",
	}}); err != nil {
		t.Fatal(err)
	}
	sched := corrosion.BackupScheduleRecord{
		VMName: "web", Scope: "vm", Repo: "dr", Cron: "0 * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: replicaHost.Name, KeepReplicas: 2, AutoPromote: true,
	}
	if err := corrosion.UpsertBackupSchedule(ctx, vmHost.DB, sched); err != nil {
		t.Fatal(err)
	}
	if err := vmHost.Server.RunReplication(ctx, sched, time.Now().Add(-5*time.Minute)); err != nil {
		t.Fatalf("replicate web to %s: %v", replicaHost.Name, err)
	}

	// The record on node-1 carries the mark.
	var marked []string
	_ = filepath.WalkDir(filepath.Join(dr, ".replicas"), func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() && strings.HasSuffix(p, ".json") {
			data, _ := os.ReadFile(p)
			var rec struct {
				File           string `json:"file"`
				NotPointInTime bool   `json:"not_point_in_time"`
			}
			if json.Unmarshal(data, &rec) == nil && rec.NotPointInTime {
				marked = append(marked, rec.File)
			}
		}
		return nil
	})
	if len(marked) != 1 {
		t.Fatalf("not-point-in-time records on %s = %v, want the one replica", replicaHost.Name, marked)
	}

	// Automatic promotion, seen from node-0, holds.
	err := vmHost.Server.AutoPromoteReplica(ctx, "web", "", 0)
	if err == nil || !strings.Contains(err.Error(), "--accept-not-point-in-time") {
		t.Fatalf("automatic promotion = %v, want it held with the manual command", err)
	}
	if replicaHost.Virt.DomainExists("web") {
		t.Fatal("web was promoted from a not-point-in-time replica")
	}

	// The operator's promotion with the flag relays and runs.
	st, err := c.SelfClient(vmHost).PromoteReplica(ctx, &pb.PromoteReplicaRequest{VmName: "web", Force: true, AcceptNotPointInTime: true})
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
		t.Fatalf("manual promotion with --accept-not-point-in-time: %v", err)
	}
	if !replicaHost.Virt.DomainExists("web") {
		t.Errorf("web was not promoted on %s", replicaHost.Name)
	}
}
