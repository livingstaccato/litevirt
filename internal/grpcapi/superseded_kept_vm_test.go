package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// keptFilesOfWeb leaves, on s's host, what a create of web after
// `lv rm --keep-disks web` leaves: the earlier web's root disk and seed at
// .kept- names (the seed stamped for the earlier web, stampedFor), and the
// new web, whose spec uuid is web-2, recording the disk's path. It returns
// the .kept- disk and seed.
func keptFilesOfWeb(t *testing.T, s *Server, stampedFor string) (string, string) {
	t.Helper()
	path := filepath.Join(s.dataDir, "disks", "web-root.qcow2")
	iso := lv.CloudInitISOPath(s.dataDir, "web")
	for _, d := range []string{filepath.Dir(path), filepath.Dir(iso)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	keptDisk := path + ".kept-20261001T000000.000000000Z"
	keptSeed := iso + ".kept-20261001T000000.000000000Z"
	for _, f := range []string{keptDisk, keptSeed, path, iso} {
		if err := os.WriteFile(f, []byte(f), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := cloudinit.StampSeed(keptSeed, stampedFor); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: "web", HostName: s.hostName, State: "running", Spec: `{"uuid":"web-2"}`,
	}, nil, []corrosion.DiskRecord{{VMName: "web", DiskName: "root", HostName: s.hostName, Path: path, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	return keptDisk, keptSeed
}

func keptEntries(t *testing.T, s *Server) map[string]*pb.SupersededDisk {
	t.Helper()
	resp, err := s.SupersededDisks(adminCtx(), &pb.SupersededDisksRequest{})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*pb.SupersededDisk{}
	for _, d := range resp.Disks {
		out[d.Path] = d
	}
	return out
}

// `lv host superseded-disks` names the VM a kept disk or seed is of, and
// that VM's state while one of the name exists, rather than "-" (lab 2,
// abort proof, surprise 3).
//
// Mutation: drop nameKeptCopy — the VM column is empty, red.
func TestSupersededDisks_NamesTheVMOfAKeptFile(t *testing.T) {
	s := hotplugDiskServer(t)
	keptDisk, keptSeed := keptFilesOfWeb(t, s, "web-1")
	got := keptEntries(t, s)
	for _, p := range []string{keptDisk, keptSeed} {
		d := got[p]
		if d == nil || !d.Kept || d.VmName != "web" || d.VmState != "running" {
			t.Errorf("%s: %+v; want it kept, of VM web (running)", p, d)
		}
	}
}

// A kept file is an earlier web's, not the web that exists now: a kept disk
// always, a seed stamped for the earlier incarnation, and a seed whose stamp
// is empty (its owner not known); a seed stamped for the web that exists now
// is not marked (re-review surprise 3).
//
// Mutations: never mark a seed, or mark one stamped for the live web — red.
func TestSupersededDisks_MarksAKeptFileAsAnEarlierVMs(t *testing.T) {
	for _, tc := range []struct {
		name, stamp string
		earlier     bool
	}{{"stamped for the earlier web", "web-1", true}, {"stamp empty", "", true}, {"stamped for the web now", "web-2", false}} {
		t.Run(tc.name, func(t *testing.T) {
			s := hotplugDiskServer(t)
			keptDisk, keptSeed := keptFilesOfWeb(t, s, "x")
			// StampSeed("") removes the stamp; an empty stamp is a 0-byte file.
			if err := os.WriteFile(cloudinit.SeedOwnerPath(keptSeed), []byte(tc.stamp), 0o600); err != nil {
				t.Fatal(err)
			}
			got := keptEntries(t, s)
			if d := got[keptDisk]; d == nil || !d.EarlierVm {
				t.Errorf("kept disk: %+v; want it marked an earlier web's", d)
			}
			if d := got[keptSeed]; d == nil || d.EarlierVm != tc.earlier {
				t.Errorf("kept seed: %+v; want earlier_vm=%v", d, tc.earlier)
			}
		})
	}
}
