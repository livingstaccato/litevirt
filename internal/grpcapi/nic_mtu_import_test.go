package grpcapi

import (
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A Proxmox NIC's mtu= is imported once nic_mtu is open, under the feature's
// grant, and the domain carries it; before the latch it is dropped with a
// warning and the import still succeeds.
//
// Mutation: import the MTU whatever the gate says — the unlatched case goes
// red (the writer refuses it without a grant).
func TestImportVM_NICMTU(t *testing.T) {
	for name, on := range map[string]bool{"latched": true, "unlatched": false} {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			s.dataDir = t.TempDir()
			admissionHost(t, s)
			fake := libvirtfake.New()
			fake.SetBridgeMTU("vmbr0", 9000)
			s.virt = fake
			gate := newMTUGate(t, on)
			s.SetReleaseFeatureGate(gate)
			st := &fakeImportStream{ctx: adminCtx()}
			if err := importSmallVMStream(t, s, st, "imp-mtu", "net0: virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0,mtu=9000"); err != nil {
				t.Fatalf("ImportVM: %v", err)
			}
			mtu := loadStoredSpec(t, s, "imp-mtu").Network[0].GetMtu()
			x, _ := fake.DumpXMLInactive("imp-mtu")
			var warnings string
			if n := len(st.sent); n > 0 {
				warnings = strings.Join(st.sent[n-1].GetWarnings(), "\n")
			}
			if on {
				if mtu != 9000 || !strings.Contains(x, `<mtu size="9000">`) || gate.times(capabilities.FeatureNICMTU) == 0 {
					t.Errorf("latched: stored mtu %d, asked %d\n%s", mtu, gate.times(capabilities.FeatureNICMTU), x)
				}
				return
			}
			if mtu != 0 || strings.Contains(x, "<mtu") || !strings.Contains(warnings, "not imported") {
				t.Errorf("unlatched: stored mtu %d, warnings:\n%s\n%s", mtu, warnings, x)
			}
		})
	}
}

// importSmallVMStream is importSmallVM on a stream the caller reads back.
func importSmallVMStream(t *testing.T, s *Server, st *fakeImportStream, name string, extraConf ...string) error {
	t.Helper()
	stubQemuImg(t)
	raw := t.TempDir() + "/disk0.raw"
	if err := writeFileHelper(raw, make([]byte, 1<<20)); err != nil {
		t.Fatalf("write staged disk: %v", err)
	}
	conf := "name: " + name + "\ncores: 1\nmemory: 512\nscsi0: local-lvm:" + name + "-disk-0,size=1G\n"
	for _, line := range extraConf {
		conf += line + "\n"
	}
	st.frames = append(st.frames, &pb.ImportVMRequest{Name: name, SourceFormat: "proxmox",
		Chunk: []byte(conf), DiskMap: map[string]string{"scsi0": raw}})
	return s.ImportVM(st)
}
