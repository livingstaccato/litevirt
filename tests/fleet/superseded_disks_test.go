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
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// Asked on node-0 about node-1, the listing names node-1's copies with the VM
// each came from, why it is held or retained, and --purge removes there only
// the copies whose VM is gone. A copy whose VM exists is removed only when
// named (--remove), and a held one not even then. The live disk is never
// touched.
//
// Mutations: answer from the asked node instead of forwarding — node-0 has no
// copies and the listing is empty; purge retained copies too — ran's copy goes
// on the bare purge and the test is red; purge held copies — broke's copy
// goes.
func TestFleet_SupersededDisksListPurgeAndRemoveOnTheHostThatHoldsThem(t *testing.T) {
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
	gone := filepath.Join(disks, "deleted-root.qcow2.superseded-"+set) // its VM was deleted
	if err := os.WriteFile(gone, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths["ran"], []byte("live"), 0o600); err != nil {
		t.Fatal(err)
	}

	lv := c.SelfClient(asked)
	resp, err := lv.SupersededDisks(ctx, &pb.SupersededDisksRequest{Host: holder.Name})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if resp.Host != holder.Name || len(resp.Disks) != 3 {
		t.Fatalf("listing = %+v, want %s's three copies", resp, holder.Name)
	}
	held, retained := map[string]string{}, map[string]string{}
	for _, d := range resp.Disks {
		held[d.VmName], retained[d.VmName] = d.Held, d.Retained
		if d.Removed {
			t.Fatalf("a listing removed %s", d.Path)
		}
	}
	if held["ran"] != "" || held["broke"] == "" || retained["ran"] == "" || retained[""] != "" {
		t.Fatalf("held = %v, retained = %v: want broke's copy held, ran's retained, the deleted VM's neither", held, retained)
	}

	// What an older host sees of a named request: purge with an age no copy
	// has. It removes nothing.
	resp, err = lv.SupersededDisks(ctx, &pb.SupersededDisksRequest{Host: holder.Name, Purge: true, OlderThanSec: grpcapi.SupersededNamedOnlySec})
	if err != nil {
		t.Fatalf("named-only purge: %v", err)
	}
	for _, d := range resp.Disks {
		if d.Removed {
			t.Fatalf("a purge older than any copy removed %s", d.Path)
		}
	}

	resp, err = lv.SupersededDisks(ctx, &pb.SupersededDisksRequest{Host: holder.Name, Purge: true})
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	for _, d := range resp.Disks {
		if d.Removed != (d.VmName == "") {
			t.Fatalf("purge result %+v: want only the deleted VM's copy removed", d)
		}
	}
	for _, p := range []string{paths["ran"] + ".superseded-" + set, paths["broke"] + ".superseded-" + set, paths["ran"]} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s was removed by the purge: %v", p, err)
		}
	}

	// Named, ran's copy goes; broke's, held, does not.
	resp, err = lv.SupersededDisks(ctx, &pb.SupersededDisksRequest{Host: holder.Name, Purge: true,
		OlderThanSec: grpcapi.SupersededNamedOnlySec, RemovePaths: []string{paths["ran"] + ".superseded-" + set}})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(paths["ran"] + ".superseded-" + set); !os.IsNotExist(err) {
		t.Fatalf("ran's named copy is still there after --remove (stat err %v)", err)
	}
	if _, err := lv.SupersededDisks(ctx, &pb.SupersededDisksRequest{Host: holder.Name, Purge: true,
		OlderThanSec: grpcapi.SupersededNamedOnlySec, RemovePaths: []string{paths["broke"] + ".superseded-" + set}}); err == nil {
		t.Fatal("a held copy was removed by name")
	}
	for _, p := range []string{paths["broke"] + ".superseded-" + set, paths["ran"]} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s was removed: %v", p, err)
		}
	}
}
