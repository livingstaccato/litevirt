package grpcapi

import (
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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

// An imported MTU its bridge here does not equal refuses the import as an
// operator error, naming the bridge, and leaves no row.
func TestImportVM_NICMTUMismatchIsFailedPrecondition(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	admissionHost(t, s)
	fake := libvirtfake.New()
	fake.SetBridgeMTU("vmbr0", 1500)
	s.virt = fake
	s.SetReleaseFeatureGate(newMTUGate(t, true))
	err := importSmallVMStream(t, s, &fakeImportStream{ctx: adminCtx()}, "imp-mis", "net0: virtio=AA:BB:CC:DD:EE:02,bridge=vmbr0,mtu=9000")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "does not match bridge vmbr0 MTU 1500") {
		t.Errorf("import onto a 1500 bridge: %v", err)
	}
	if fake.DomainExists("imp-mis") {
		t.Error("the refused import left a domain")
	}
}

// stubQemuImgRecording is stubQemuImg that also appends each subcommand it is
// run with to the returned file, so a test can tell whether a disk was
// converted.
func stubQemuImgRecording(t *testing.T) (calls string) {
	t.Helper()
	dir := t.TempDir()
	calls = dir + "/calls"
	shim := "#!/bin/sh\n" +
		"echo \"$1\" >> '" + calls + "'\n" +
		"if [ \"$1\" = info ]; then echo '{\"format\":\"raw\",\"virtual-size\":1048576}'; exit 0; fi\n" +
		"if [ \"$1\" = measure ]; then echo '{\"required\":134217728,\"fully-allocated\":134217728}'; exit 0; fi\n" +
		"prev=\"\"; last=\"\"\n" +
		"for a; do prev=\"$last\"; last=\"$a\"; done\n" +
		"cp \"$prev\" \"$last\"\n"
	if err := writeFileHelper(dir+"/qemu-img", []byte(shim)); err != nil {
		t.Fatalf("write qemu-img stub: %v", err)
	}
	if err := chmodHelper(dir+"/qemu-img", 0o755); err != nil {
		t.Fatalf("chmod stub: %v", err)
	}
	t.Setenv("PATH", dir+":"+envPath())
	return calls
}

// An imported MTU this host's bridge does not equal is refused BEFORE any disk
// is converted, not after a conversion that is then thrown away. Before the
// latch the same source still imports, its MTU dropped: the early check never
// refuses what the import accepts today.
//
// Mutation: drop the pre-conversion check (leave only the render's) — the
// latched case converts first and goes red.
func TestImportVM_NICMTUMismatchRefusedBeforeConversion(t *testing.T) {
	for name, on := range map[string]bool{"latched": true, "unlatched": false} {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			s.dataDir = t.TempDir()
			admissionHost(t, s)
			fake := libvirtfake.New()
			fake.SetBridgeMTU("vmbr0", 1500)
			s.virt = fake
			s.SetReleaseFeatureGate(newMTUGate(t, on))
			calls := stubQemuImgRecording(t)
			raw := t.TempDir() + "/disk0.raw"
			if err := writeFileHelper(raw, make([]byte, 1<<20)); err != nil {
				t.Fatal(err)
			}
			conf := "name: imp-early\ncores: 1\nmemory: 512\nscsi0: local-lvm:imp-early-disk-0,size=1G\n" +
				"net0: virtio=AA:BB:CC:DD:EE:03,bridge=vmbr0,mtu=9000\n"
			st := &fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{{Name: "imp-early", SourceFormat: "proxmox",
				Chunk: []byte(conf), DiskMap: map[string]string{"scsi0": raw}}}}
			err := s.ImportVM(st)
			converted := false
			if b, rerr := os.ReadFile(calls); rerr == nil {
				converted = strings.Contains(string(b), "convert")
			}
			if !on {
				if err != nil || !converted || !fake.DomainExists("imp-early") {
					t.Fatalf("unlatched: err=%v converted=%v, want the import to succeed with its MTU dropped", err, converted)
				}
				return
			}
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "does not match bridge vmbr0 MTU 1500") {
				t.Fatalf("latched: %v, want FailedPrecondition naming the bridge", err)
			}
			if converted {
				t.Error("the disk was converted before the NIC MTU was checked")
			}
		})
	}
}
