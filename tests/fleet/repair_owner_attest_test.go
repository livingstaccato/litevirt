package fleet

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// declinedCommit is the state a migration whose ownership commit declined
// leaves (RepointMigratedVM): db's row names cn, where it runs, while its disk
// rows — a shared root and a shared data1 — still name b, the source, which
// is active and in service. It returns data1's path.
func declinedCommit(t *testing.T, c *Cluster, b, cn *Node) string {
	t.Helper()
	ctx := context.Background()
	dir := filepath.Join(c.tmpRoot, "nfs-attest")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	root, data1 := filepath.Join(dir, "db-root.qcow2"), filepath.Join(dir, "db-data1.qcow2")
	for _, p := range []string{root, data1} {
		if err := qcow2.Create(p, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "db", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, cn.DB, corrosion.VMRecord{Name: "db", HostName: cn.Name, State: "running", Spec: string(spec),
		CPUActual: 1, MemActual: 256}, nil, []corrosion.DiskRecord{
		{VMName: "db", DiskName: "root", HostName: b.Name, Path: root, StorageType: "nfs", StorageVolume: "nfs", TargetDev: "vda", Bus: "virtio"},
		{VMName: "db", DiskName: "data1", HostName: b.Name, Path: data1, StorageType: "nfs", StorageVolume: "nfs", TargetDev: "vdb", Bus: "virtio"},
	}); err != nil {
		t.Fatal(err)
	}
	cn.Virt.SetState("db", "running")
	return data1
}

func rowHosts(t *testing.T, n *Node) map[string]string {
	t.Helper()
	disks, err := corrosion.GetVMDisks(context.Background(), n.DB, "db")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, d := range disks {
		out[d.DiskName] = d.HostName
	}
	return out
}

// Review c2b: `lv doctor repair-owner` re-homes the shared disk rows a
// declined migration commit left naming the active source once that source
// attests, under its start lock, that no domain defined there uses each disk
// — the gentler remedy than fence-confirming a host in service. The source
// then refuses to start a domain using a released path. Every way the
// attestation can fail refuses the repair and leaves the rows: the source
// still has a domain using the disk, it runs a build without the RPC, or it
// cannot be reached.
//
// Mutation "no attestation" (repair-owner never asks: an active host is
// refused like any other) — red on "the source attests". Mutation "attest
// without looking" (AttestSharedDiskUnused answers unused without listing
// the domains) — red on "the source still uses it".
func TestFleet_RepairOwnerReHomesADeclinedCommitsRowsOnTheSourcesAttestation(t *testing.T) {
	for _, arm := range []string{"the source attests", "the source still uses it", "an older source", "the source unreachable"} {
		t.Run(arm, func(t *testing.T) {
			c := New(t, Options{Nodes: 3, SharedCRDT: true})
			ctx := context.Background()
			b, cn := c.Nodes[1], c.Nodes[2]
			data1 := declinedCommit(t, c, b, cn)
			switch arm {
			case "the source still uses it":
				xml, err := lv.GenerateDomainXML(lv.VMConfig{Name: "leftover", CPU: 1, MemoryMiB: 256,
					Disks: []lv.DiskConfig{{Name: "data1", Path: data1, Bus: "virtio", TargetDev: "vda"}}})
				if err != nil {
					t.Fatal(err)
				}
				if err := b.Virt.DefineDomain(xml); err != nil {
					t.Fatal(err)
				}
			case "an older source":
				restore := b.DoNotImplement("AttestSharedDiskUnused")
				defer restore()
			case "the source unreachable":
				c.SetLinkFaultBoth(b, cn, LinkFault{BlockAll: true})
			}

			_, err := c.SelfClient(cn).RepairVMOwner(ctx, &pb.RepairVMOwnerRequest{Name: "db", Host: cn.Name})
			if arm != "the source attests" {
				if err == nil || !strings.Contains(err.Error(), "`lv host fence-confirm "+b.Name+"`") {
					t.Fatalf("repair-owner = %v, want it refused, naming fence-confirm", err)
				}
				if h := rowHosts(t, cn); h["root"] != b.Name || h["data1"] != b.Name {
					t.Fatalf("the refused repair moved rows: %v", h)
				}
				return
			}
			if err != nil {
				t.Fatalf("repair-owner with %s's attestation: %v", b.Name, err)
			}
			if h := rowHosts(t, cn); h["root"] != cn.Name || h["data1"] != cn.Name {
				t.Fatalf("rows after the repair = %v, want them on %s", h, cn.Name)
			}
			// The source never starts a domain using a released disk now.
			if err := corrosion.InsertVM(ctx, b.DB, corrosion.VMRecord{Name: "intruder", HostName: b.Name, State: "stopped", Spec: `{"name":"intruder","cpu":1,"memory_mib":256}`,
				CPUActual: 1, MemActual: 256}, nil, nil); err != nil {
				t.Fatal(err)
			}
			xml, err := lv.GenerateDomainXML(lv.VMConfig{Name: "intruder", CPU: 1, MemoryMiB: 256,
				Disks: []lv.DiskConfig{{Name: "data1", Path: data1, Bus: "virtio", TargetDev: "vda"}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := b.Virt.DefineDomain(xml); err != nil {
				t.Fatal(err)
			}
			if _, err := c.SelfClient(b).StartVM(ctx, &pb.StartVMRequest{Name: "intruder"}); err == nil ||
				!strings.Contains(err.Error(), "released") {
				t.Fatalf("a start on %s of a domain using the released data1 = %v, want it refused", b.Name, err)
			}
		})
	}
}
