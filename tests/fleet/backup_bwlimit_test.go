package fleet

import (
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// remoteBackupContainer backs up owner's container into the sink's repo
// "main" by calling the SINK (the remote-backup path: the owner archives and
// streams the manifest back). Returns the wall time and the manifest ts.
func remoteBackupContainer(t *testing.T, c *Cluster, sink, owner *Node, name string, jobBps int64) (time.Duration, string) {
	t.Helper()
	start := time.Now()
	st, err := c.SelfClient(sink).BackupContainer(context.Background(), &pb.BackupContainerRequest{
		Name: name, HostName: owner.Name, RepoPath: "main", BwlimitBytesPerSec: jobBps,
	})
	if err != nil {
		t.Fatalf("BackupContainer: %v", err)
	}
	ts := ""
	for {
		p, rerr := st.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatalf("BackupContainer stream: %v", rerr)
		}
		if p.ManifestTs != "" {
			ts = p.ManifestTs
		}
	}
	if ts == "" {
		t.Fatal("remote backup produced no manifest")
	}
	return time.Since(start), ts
}

// A backup bandwidth limit configured for a repo on the host that holds it
// (backup_bwlimits) governs a remote backup into that repo, although the
// reading and sending happen on the container's own host, whose config has no
// limit. The sink hands its limit to the owner with the forwarded request.
//
// 1 MiB of payload at 512 KiB/s is >= 2s to read and >= 2s more to send, so
// the limited backup takes well over 2s; the same backup unlimited takes a
// fraction of that.
func TestFleet_BackupBWLimit_TargetLimitGovernsRemoteBackup(t *testing.T) {
	// Shared CRDT: the sink must see the owner's container row to forward.
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	sink, owner := c.Nodes[0], c.Nodes[1]
	const name = "ct-bw"

	createContainer(t, c, owner, name)
	owner.CT.Seed(name, strings.Repeat("0123456789abcdef", 1<<16)) // 1 MiB
	repoDir := stagingRepo(t)
	sink.Server.SetBackupRepos(map[string]string{"main": repoDir})

	// Control: no limit anywhere.
	fast, ts := remoteBackupContainer(t, c, sink, owner, name, 0)
	if fast >= 1500*time.Millisecond {
		t.Fatalf("unlimited remote backup took %v; the harness is too slow for the timing assertion below", fast)
	}
	repo, err := pbsstore.Open(repoDir)
	if err != nil {
		t.Fatal(err)
	}
	// "rootfs" is the manifest disk name of a container archive.
	if _, err := repo.GetManifest(name, ts, "rootfs"); err != nil {
		t.Fatalf("the remote backup did not land in the sink repo: %v", err)
	}

	// The sink's target limit, and nothing on the owner.
	sink.Server.SetBackupBandwidthLimits(map[string]int64{"main": 512 << 10})
	slow, _ := remoteBackupContainer(t, c, sink, owner, name, 0)
	if slow < 2*time.Second {
		t.Fatalf("remote backup into a repo limited to 512KiB/s on its sink took %v for 1 MiB; the limit did not reach the owning host", slow)
	}

	// A job's own limit applies with no target limit at all.
	sink.Server.SetBackupBandwidthLimits(nil)
	slow, _ = remoteBackupContainer(t, c, sink, owner, name, 512<<10)
	if slow < 2*time.Second {
		t.Fatalf("remote backup with --bwlimit 512KiB/s took %v for 1 MiB; the job limit was not applied", slow)
	}
}

// The same for a VM: the repo sink's target limit reaches the owning host,
// which reads the (stopped VM's) disk and sends the chunks.
func TestFleet_BackupBWLimit_TargetLimitGovernsRemoteVMBackup(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	sink, owner := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	const name = "vm-bw"

	diskPath := filepath.Join(t.TempDir(), "root.img")
	payload := make([]byte, 1<<20)
	_, _ = rand.Read(payload)
	if err := os.WriteFile(diskPath, payload, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, owner.DB, corrosion.VMRecord{
		Name: name, HostName: owner.Name, State: "stopped", Spec: `{"name":"` + name + `"}`,
	}, nil, []corrosion.DiskRecord{{
		VMName: name, DiskName: "root", HostName: owner.Name, Path: diskPath,
		SizeBytes: 1 << 20, StorageType: "local",
	}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	repoDir := stagingRepo(t)
	sink.Server.SetBackupRepos(map[string]string{"main": repoDir})

	backup := func(ts string) time.Duration {
		t.Helper()
		start := time.Now()
		st, err := c.SelfClient(sink).BackupSnapshot(ctx, &pb.BackupSnapshotRequest{
			VmName: name, RepoPath: "main", Timestamp: ts,
		})
		if err != nil {
			t.Fatalf("BackupSnapshot: %v", err)
		}
		done := false
		for {
			p, rerr := st.Recv()
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				t.Fatalf("BackupSnapshot stream: %v", rerr)
			}
			if p.Phase == pb.BackupSnapshotProgress_DONE {
				done = true
			}
		}
		if !done {
			t.Fatal("remote VM backup did not complete")
		}
		return time.Since(start)
	}

	if d := backup("2026-10-10T01:00:00Z"); d >= 1500*time.Millisecond {
		t.Fatalf("unlimited remote VM backup took %v; too slow for the assertion below", d)
	}
	sink.Server.SetBackupBandwidthLimits(map[string]int64{"main": 512 << 10})
	if d := backup("2026-10-10T02:00:00Z"); d < 2*time.Second {
		t.Fatalf("remote VM backup into a repo limited to 512KiB/s on its sink took %v for 1 MiB; the limit did not reach the owning host", d)
	}
}
