package grpcapi

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// thinQemuImg is a qemu-img whose every disk is a thin one: info reports a
// virtual size of virtual bytes, measure says a qcow2 of it needs required
// bytes, and convert copies the file. It records each call in calls.
func thinQemuImg(t *testing.T, virtual, required uint64) {
	t.Helper()
	dir := t.TempDir()
	shim := "#!/bin/sh\n" +
		fmt.Sprintf("if [ \"$1\" = info ]; then echo '{\"format\":\"raw\",\"virtual-size\":%d}'; exit 0; fi\n", virtual) +
		fmt.Sprintf("if [ \"$1\" = measure ]; then echo '{\"required\":%d,\"fully-allocated\":%d}'; exit 0; fi\n", required, virtual) +
		"prev=\"\"; last=\"\"\n" +
		"for a; do prev=\"$last\"; last=\"$a\"; done\n" +
		"cp \"$prev\" \"$last\"\n"
	if err := writeFileHelper(dir+"/qemu-img", []byte(shim)); err != nil {
		t.Fatal(err)
	}
	if err := chmodHelper(dir+"/qemu-img", 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+envPath())
}

// C-1. An import reserves what it writes, not what its disks declare. A
// 1 TiB thin disk holding 40 GiB of data imports into a pool with 500 GiB
// free, as it did on main; one whose conversion qemu-img measures past the
// free space is still refused before it writes.
func TestImportVM_AThinDiskReservesWhatItWritesNotItsCapacity(t *testing.T) {
	const (
		tib   = uint64(1) << 40
		gib   = uint64(1) << 30
		total = 2 * tib
	)
	for _, c := range []struct {
		name     string
		required uint64
		ok       bool
	}{
		{"40 GiB of data in a 1 TiB disk", 40 * gib, true},
		{"600 GiB of data in a 1 TiB disk", 600 * gib, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := testServer(t)
			s.dataDir = t.TempDir()
			admissionHost(t, s)
			s.virt = libvirtfake.New()
			// 500 GiB free.
			s.diskSpaceOverride = func(string) (uint64, uint64, error) {
				return 500 * gib, total, nil
			}
			thinQemuImg(t, tib, c.required)
			raw := t.TempDir() + "/disk0.raw"
			if err := writeFileHelper(raw, []byte("thin disk's data")); err != nil {
				t.Fatal(err)
			}
			st := &fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{{
				Name: "thin", SourceFormat: "proxmox",
				Chunk:   []byte("name: thin\ncores: 1\nmemory: 512\nscsi0: local-lvm:thin-disk-0,size=1T\n"),
				DiskMap: map[string]string{"scsi0": raw},
			}}}
			err := s.ImportVM(st)
			rec, _ := corrosion.GetVM(context.Background(), s.db, "thin")
			if c.ok {
				if err != nil {
					t.Fatalf("a 1 TiB thin disk holding 40 GiB into 500 GiB free: %v", err)
				}
				if rec == nil {
					t.Fatal("imported, but no row")
				}
				return
			}
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "converting disk") {
				t.Fatalf("a conversion measured past the free space: %v, want a refusal for the conversion", err)
			}
			if rec != nil {
				t.Fatal("a refused import left a row")
			}
		})
	}
}
