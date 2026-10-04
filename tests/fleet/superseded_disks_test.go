// Fleet scenario for `lv host superseded-disks <host>`: the disk copies a
// failover start set aside on a host are that host's files, so the request is
// answered there, whichever node the operator asks.

package fleet

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Asked on node-0 about node-1, the listing names node-1's copies with the VM
// each came from and why it is held, and --purge removes there the ones not
// held, leaving the held one and the live disk.
//
// Mutation: answer from the asked node instead of forwarding — node-0 has no
// copies and the listing is empty. Purge held copies too — the failed VM's
// copy goes.
func TestFleet_SupersededDisksListAndPurgeOnTheHostThatHoldsThem(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	defer c.Stop()
	ctx := context.Background()
	asked, holder := c.Nodes[0], c.Nodes[1]

	disks := filepath.Join(c.tmpRoot, holder.Name, "data", "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	set := time.Now().Add(-30 * 24 * time.Hour).UTC().Format("20060102T150405.000000000Z")
	paths := map[string]string{}
	for vm, state := range map[string]string{"ran": "running", "broke": "error"} {
		paths[vm] = filepath.Join(disks, vm+"-root.qcow2")
		if err := corrosion.InsertVM(ctx, asked.DB, corrosion.VMRecord{Name: vm, HostName: holder.Name, State: state, Spec: "{}"},
			nil, []corrosion.DiskRecord{{VMName: vm, DiskName: "root", HostName: holder.Name, Path: paths[vm], StorageType: "local"}}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(paths[vm]+".superseded-"+set, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(paths["ran"], []byte("live"), 0o600); err != nil {
		t.Fatal(err)
	}

	lv := c.SelfClient(asked)
	resp, err := lv.SupersededDisks(ctx, &pb.SupersededDisksRequest{Host: holder.Name})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if resp.Host != holder.Name || len(resp.Disks) != 2 {
		t.Fatalf("listing = %+v, want %s's two copies", resp, holder.Name)
	}
	held := map[string]string{}
	for _, d := range resp.Disks {
		held[d.VmName] = d.Held
		if d.Removed {
			t.Fatalf("a listing removed %s", d.Path)
		}
	}
	if held["ran"] != "" || held["broke"] == "" {
		t.Fatalf("held = %v, want only broke's copy held", held)
	}

	resp, err = lv.SupersededDisks(ctx, &pb.SupersededDisksRequest{Host: holder.Name, Purge: true})
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	for _, d := range resp.Disks {
		if d.Removed != (d.VmName == "ran") {
			t.Fatalf("purge result %+v: want only ran's copy removed", d)
		}
	}
	if _, err := os.Stat(paths["ran"] + ".superseded-" + set); !os.IsNotExist(err) {
		t.Fatalf("ran's copy is still there after the purge (stat err %v)", err)
	}
	for _, p := range []string{paths["broke"] + ".superseded-" + set, paths["ran"]} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s was removed by the purge: %v", p, err)
		}
	}
}
