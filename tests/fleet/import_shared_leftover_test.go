// Fleet scenario: an import that crashed on one host, re-imported on another
// into a pool both share.
//
// Each host's placement record — which files its imports wrote, in what state
// — is host-local, so only the host whose import crashed can prove a leftover
// is a dead import's. The re-importing host asks the hosts sharing the pool
// (ImportLeftoverStatus, peer-only, over real mTLS) and takes the file for a
// leftover only on a yes; a host that does not answer, or whose import is
// still running, leaves it refused. A single-package test structurally cannot
// reach this: the question crosses two daemons' records and a real peer RPC.

package fleet

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// stubQemuImgFleet puts a qemu-img on PATH that answers info with a small raw
// image and converts by copying.
func stubQemuImgFleet(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	shim := "#!/bin/sh\n" +
		"if [ \"$1\" = info ]; then echo '{\"format\":\"raw\",\"virtual-size\":1048576}'; exit 0; fi\n" +
		"prev=\"\"; last=\"\"\n" +
		"for a; do prev=\"$last\"; last=\"$a\"; done\n" +
		"cp \"$prev\" \"$last\"\n"
	if err := os.WriteFile(filepath.Join(dir, "qemu-img"), []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

// importOn runs ImportVM of a one-disk Proxmox VM on n into pool, over n's
// real gRPC server.
func importOn(t *testing.T, c *Cluster, n *Node, name, pool string) error {
	t.Helper()
	raw := filepath.Join(t.TempDir(), "disk0.raw")
	if err := os.WriteFile(raw, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	stream, err := c.SelfClient(n).ImportVM(context.Background())
	if err != nil {
		return err
	}
	if err := stream.Send(&pb.ImportVMRequest{
		Name: name, SourceFormat: "proxmox", TargetPool: pool,
		Chunk:   []byte("name: " + name + "\ncores: 1\nmemory: 512\nscsi0: local-lvm:" + name + "-disk-0,size=1M\n"),
		DiskMap: map[string]string{"scsi0": raw},
	}); err != nil {
		return err
	}
	if err := stream.CloseSend(); err != nil {
		return err
	}
	for {
		if _, err := stream.Recv(); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func TestFleet_Import_ACrashOnOneHostIsReimportedOnAnotherIntoASharedPool(t *testing.T) {
	stubQemuImgFleet(t)
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, c *Cluster, crashed *Node, path string)
		allow bool
	}{
		{name: "the crashed host vouches", allow: true, setup: func(t *testing.T, _ *Cluster, crashed *Node, p string) {
			if _, err := crashed.Server.RecordImportLeftoverForTest(p, "web", false); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "its import is still running", setup: func(t *testing.T, _ *Cluster, crashed *Node, p string) {
			release, err := crashed.Server.RecordImportLeftoverForTest(p, "web", true)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(release)
		}},
		{name: "it does not answer", setup: func(t *testing.T, _ *Cluster, crashed *Node, p string) {
			if _, err := crashed.Server.RecordImportLeftoverForTest(p, "web", false); err != nil {
				t.Fatal(err)
			}
			crashed.HookUnary("ImportLeftoverStatus", func(context.Context, any, grpc.UnaryHandler) (any, error) {
				return nil, status.Error(codes.Unavailable, "host down")
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(t, Options{Nodes: 2, SharedCRDT: true, NamePrefix: "imp" + strings.ReplaceAll(tc.name, " ", "") + "-"})
			crashed, again := c.Nodes[0], c.Nodes[1]
			shared := t.TempDir()
			for _, n := range c.Nodes {
				if err := corrosion.UpsertStoragePool(context.Background(), n.DB, corrosion.StoragePoolRecord{
					HostName: n.Name, Name: "shared", Driver: "dir", Target: shared, State: "active",
				}); err != nil {
					t.Fatal(err)
				}
			}
			// What the crash left: the disk, placed and recorded on the
			// crashed host, written moments ago.
			left := filepath.Join(shared, "web-root.qcow2")
			if err := os.WriteFile(left, []byte("crashed on "+crashed.Name), 0o600); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, c, crashed, left)

			err := importOn(t, c, again, "web", "shared")
			aside, _ := filepath.Glob(left + ".orphan-*")
			if tc.allow {
				if err != nil {
					t.Fatalf("re-import on %s over %s's dead import's leftover: %v", again.Name, crashed.Name, err)
				}
				if len(aside) != 1 {
					t.Fatalf("leftover kept as %v", aside)
				}
				if b, _ := os.ReadFile(aside[0]); string(b) != "crashed on "+crashed.Name {
					t.Fatalf("the leftover kept aside holds %q", b)
				}
				return
			}
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("got %v, want a refusal", err)
			}
			if len(aside) != 0 {
				t.Fatalf("moved aside: %v", aside)
			}
			if b, _ := os.ReadFile(left); string(b) != "crashed on "+crashed.Name {
				t.Fatalf("the file now holds %q", b)
			}
		})
	}
}
