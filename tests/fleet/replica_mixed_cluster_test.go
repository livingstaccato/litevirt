// Fleet scenario: a failover coordinated by a host still on main's build
// (3e4ba50b), during a rolling upgrade, promotes the newest replica.
//
// A new-build sender writes a replica into the receiver's replica area, which
// a main-build host cannot see: its coordinator lists the replica host's pool
// with its host certificate and takes the lexically newest top-level file
// named <vm>-<disk>-* (main's findReplicaHost). While such a host is in the
// cluster, the sender also writes main's top-level replica, so that choice
// is the newest data rather than a replica frozen at the upgrade.
package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

// mainCoordinatorChoice is the replica main's failover coordinator promotes
// for (vm, disk) in pool on host: main's findReplicaHost
// (internal/grpcapi/promote.go:444-489 at 3e4ba50b) lists the pool over a
// host-certificate peer call (poolContentNames, promote.go:492-526), keeps
// the names isReplicaOf accepts (promote.go:429-433: "<vm>-<disk>-" and
// .qcow2 or .raw) and takes the lexically greatest (promote.go:474).
func mainCoordinatorChoice(t *testing.T, cl pb.LiteVirtClient, pool, host, vm, disk string) string {
	t.Helper()
	resp, err := cl.ListStoragePoolContents(context.Background(), &pb.ListStoragePoolContentsRequest{PoolName: pool, Host: host})
	if err != nil {
		t.Fatalf("main coordinator's listing of %s on %s: %v", pool, host, err)
	}
	best := ""
	for _, c := range resp.GetContents() {
		n := c.GetName()
		if strings.HasPrefix(n, fmt.Sprintf("%s-%s-", vm, disk)) &&
			(strings.HasSuffix(n, ".qcow2") || strings.HasSuffix(n, ".raw")) && n > best {
			best = n
		}
	}
	return best
}

func TestFleet_AMainBuildCoordinatorPromotesTheNewestReplica(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	vmHost, replicaHost, mainHost := c.Node("node-0"), c.Node("node-1"), c.Node("node-2")
	// node-2 is on main's build: no replica area, so no ListReplicas.
	for _, m := range []string{"ListReplicas", "PushReplica", "PruneReplicas"} {
		mainHost.DoNotImplement(m)
	}

	pool := filepath.Join(c.tmpRoot, replicaHost.Name, "data", "pools", "dr")
	if err := os.MkdirAll(pool, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, replicaHost.DB, corrosion.StoragePoolRecord{
		HostName: replicaHost.Name, Name: "dr", Driver: "local", Target: pool, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	// The replica main's runner wrote before the upgrade
	// (replication_runner.go:222 at 3e4ba50b: "<vm>-<disk>-<ts>.qcow2").
	upgradeTS := time.Now().Add(-2 * time.Hour).UTC().Format("20060102-150405")
	stale := fmt.Sprintf("web-root-%s.qcow2", upgradeTS)
	if err := qcow2.Create(filepath.Join(pool, stale), 1<<20, nil); err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(c.tmpRoot, vmHost.Name, "web-root-src.qcow2")
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
		Type: "replication", TargetPool: "dr", TargetHost: replicaHost.Name, KeepReplicas: 2,
	}
	if err := corrosion.UpsertBackupSchedule(ctx, vmHost.DB, sched); err != nil {
		t.Fatal(err)
	}
	runAt := time.Now().Add(-5 * time.Minute)
	if err := vmHost.Server.RunReplication(ctx, sched, runAt); err != nil {
		t.Fatalf("replicate web to %s: %v", replicaHost.Name, err)
	}
	ts := runAt.UTC().Format("20060102-150405")

	// The new build's replica, in the area.
	var area string
	_ = filepath.WalkDir(filepath.Join(pool, ".replicas"), func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		var rec struct {
			VM    string `json:"vm"`
			File  string `json:"file"`
			Taken string `json:"taken"`
		}
		if data, rerr := os.ReadFile(p); rerr == nil && json.Unmarshal(data, &rec) == nil && rec.VM == "web" && rec.Taken == ts {
			area = filepath.Join(filepath.Dir(p), rec.File)
		}
		return nil
	})
	if area == "" {
		t.Fatalf("the run at %s left no replica in the area", ts)
	}

	choice := mainCoordinatorChoice(t, c.PeerClient(mainHost, replicaHost), "dr", replicaHost.Name, "web", "root")
	if want := fmt.Sprintf("web-root-%s.qcow2", ts); choice != want {
		t.Fatalf("a main-build coordinator would promote %q, want the newest replica %q (the one before the upgrade is %q)", choice, want, stale)
	}
	got, err := os.ReadFile(filepath.Join(pool, choice))
	if err != nil {
		t.Fatal(err)
	}
	if want, err := os.ReadFile(area); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("the top-level replica %s is not the area's replica of the same run (%v)", choice, err)
	}

	// Main relays the promotion, naming that replica, to the host holding it
	// (relayPromote, promote.go:532 at 3e4ba50b); this build promotes it.
	st, err := c.PeerClient(mainHost, replicaHost).PromoteReplica(ctx, &pb.PromoteReplicaRequest{
		VmName: "web", TargetPool: "dr", TargetHost: replicaHost.Name, Replica: choice, Force: true,
	})
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
		t.Fatalf("promoting %s relayed from a main-build coordinator: %v", choice, err)
	}
	if !replicaHost.Virt.DomainExists("web") {
		t.Fatalf("web was not promoted on %s", replicaHost.Name)
	}
}
