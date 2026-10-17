package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/cloudinit"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A create writes its seed durably and stamps it only after: the seed's
// bytes, then its name, reach the disk before its stamp is written, so a
// stamp that survives a power cut never names an empty or truncated seed
// (abort round 3, concern 1). Both create branches: user-data, and the
// auto-generated seed of an image.
//
// Mutations: drop the seed's file sync (cloudinit.writeISO) — red; stamp
// before the seed is written (vm.go) — red.
func TestCreateVM_TheSeedIsDurableBeforeItsStamp(t *testing.T) {
	for _, tc := range []struct{ name, userData string }{
		{"user-data", "#cloud-config\n"},
		{"auto", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stageGenisoimage(t)
			s, _, _ := isoServer(t)
			iso := lv.CloudInitISOPath(s.dataDir, "w")
			dir := filepath.Dir(iso)
			steps := cloudinit.ObserveSeedWrites(t, dir)
			if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, "w", tc.userData)); err != nil {
				t.Fatalf("CreateVM: %v", err)
			}
			got := steps()
			tmp := "sync " + filepath.Join(dir, "."+filepath.Base(iso)+".")
			want := []string{tmp, "rename " + iso, "syncdir " + dir, tmp, "rename " + cloudinit.SeedOwnerPath(iso), "syncdir " + dir}
			ok := len(got) == len(want)
			for i := 0; ok && i < len(want); i++ {
				if want[i] == tmp {
					ok = strings.HasPrefix(got[i], tmp) && strings.HasSuffix(got[i], ".tmp")
				} else {
					ok = got[i] == want[i]
				}
			}
			if !ok {
				t.Fatalf("seed write steps = %q;\nwant the seed synced, renamed, its directory synced, then the same for its stamp: %q", got, want)
			}
		})
	}
}
