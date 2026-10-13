package grpcapi

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/opjournal"
	"github.com/litevirt/litevirt/internal/vfio"
)

// unattachedRig is lab L1's leftover from an older build: running vm1 owns a VF
// that sits on its host driver and is in neither copy of vm1's domain.
func unattachedRig(t *testing.T) (*Server, *libvirtfake.Fake, *pciBindFakeFS, string) {
	t.Helper()
	const vf = "0000:41:10.1"
	s := hotplugDiskServer(t)
	fake := s.virt.(*libvirtfake.Fake)
	fs := newPCIBindFakeFS()
	t.Cleanup(vfio.SetFS(fs))
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	fake.SetState("vm1", libvirtfake.StateRunning)
	seedPCIDevice(t, ctx, s, vf, false)
	if err := corrosion.AssignPCIDevice(ctx, s.db, s.hostName, vf, "vm1"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	return s, fake, fs, vf
}

func TestSweepUnattachedPCIOwnership_ReleasesAnOlderBuildsLeak(t *testing.T) {
	s, _, _, vf := unattachedRig(t)
	ctx := adminCtx()

	released, reported := s.SweepUnattachedPCIOwnership(ctx)
	if len(released) != 1 || released[0] != vf {
		t.Fatalf("released = %v, reported = %v; want %s released", released, reported, vf)
	}
	if owned := ownedBy(t, ctx, s, "vm1"); owned[vf] {
		t.Fatalf("%s is still owned by vm1 after the sweep", vf)
	}
}

// Every case in which the device is not provably a leak: it must stay owned,
// never released. Only a device PROVEN absent from both copies of the domain that
// still cannot be released (here: still bound to vfio-pci) is reported; a VM the
// sweep skips (in use, mid-operation, hardware_v2 intents, unreadable domain) is
// skipped silently, since a report there would tell the operator to detach a
// device a guest may be using (review S1).
func TestSweepUnattachedPCIOwnership_KeepsWhatItCannotProve(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, s *Server, fake *libvirtfake.Fake, fs *pciBindFakeFS, vf string)
		// silent: nothing may be reported.
		silent bool
	}{
		{"the live domain does not parse", func(t *testing.T, _ *Server, fake *libvirtfake.Fake, _ *pciBindFakeFS, _ string) {
			fake.SetActiveXML("vm1", `<domain type='kvm'><name>vm1</name><devices><hostdev`)
		}, true},
		{"the persistent domain does not parse", func(t *testing.T, _ *Server, fake *libvirtfake.Fake, _ *pciBindFakeFS, _ string) {
			fake.SetActiveXML("vm1", `<domain type='kvm'><name>vm1</name><devices></devices></domain>`)
			fake.SetInactiveXML("vm1", `<domain type='kvm'><name>vm1</name><devices><hostdev`)
		}, true},
		{"in the live and persistent copies", func(t *testing.T, s *Server, fake *libvirtfake.Fake, _ *pciBindFakeFS, vf string) {
			if err := fake.AttachHostdev("vm1", vf); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"in the persistent copy only", func(t *testing.T, s *Server, fake *libvirtfake.Fake, _ *pciBindFakeFS, vf string) {
			if err := fake.AttachHostdev("vm1", vf); err != nil {
				t.Fatal(err)
			}
			x, _ := fake.DumpXMLInactive("vm1")
			fake.SetActiveXML("vm1", `<domain type='kvm'><name>vm1</name><devices></devices></domain>`)
			fake.SetInactiveXML("vm1", x)
		}, true},
		{"in the live copy only", func(t *testing.T, s *Server, fake *libvirtfake.Fake, _ *pciBindFakeFS, vf string) {
			if err := fake.AttachHostdev("vm1", vf); err != nil {
				t.Fatal(err)
			}
			x, _ := fake.DumpXML("vm1")
			fake.SetInactiveXML("vm1", `<domain type='kvm'><name>vm1</name><devices></devices></domain>`)
			fake.SetActiveXML("vm1", x)
		}, true},
		{"an operation holds the VM", func(t *testing.T, s *Server, _ *libvirtfake.Fake, _ *pciBindFakeFS, _ string) {
			if err := s.db.Execute(context.Background(), `UPDATE vms SET active_operation_id = ? WHERE name = ?`, "op-1", "vm1"); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"a device lease is open", func(t *testing.T, s *Server, _ *libvirtfake.Fake, _ *pciBindFakeFS, vf string) {
			if err := s.opJournal.Write(opjournal.Entry{
				OperationID: deviceLeaseOpID("vm1"), ResourceID: "vm1", Kind: deviceLeaseKind,
				Stage: deviceLeaseStageInProgress, Artifacts: map[string]string{"addresses": vf},
			}); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"the VM lock is held", func(t *testing.T, s *Server, _ *libvirtfake.Fake, _ *pciBindFakeFS, _ string) {
			t.Cleanup(s.lockVM("vm1"))
		}, true},
		{"still bound to vfio-pci", func(t *testing.T, _ *Server, _ *libvirtfake.Fake, fs *pciBindFakeFS, vf string) {
			fs.bound[vf] = true
		}, false},
		{"the VM has PCI intents", func(t *testing.T, s *Server, _ *libvirtfake.Fake, _ *pciBindFakeFS, _ string) {
			seedAddressIntent(t, s, "vm1", "dev-1", "0000:42:00.0")
		}, true},
		{"the domain cannot be read", func(t *testing.T, _ *Server, fake *libvirtfake.Fake, _ *pciBindFakeFS, _ string) {
			fake.FailDumpXMLInactive = func(string) error { return errString("libvirt down") }
		}, true},
		{"the VM is migrating", func(t *testing.T, s *Server, _ *libvirtfake.Fake, _ *pciBindFakeFS, _ string) {
			if err := s.db.Execute(context.Background(), `UPDATE vms SET state = ? WHERE name = ?`, "migrating", "vm1"); err != nil {
				t.Fatal(err)
			}
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, fake, fs, vf := unattachedRig(t)
			ctx := adminCtx()
			tc.setup(t, s, fake, fs, vf)

			released, reported := s.SweepUnattachedPCIOwnership(ctx)
			if len(released) != 0 {
				t.Fatalf("released %v; want nothing released", released)
			}
			if !ownedBy(t, ctx, s, "vm1")[vf] {
				t.Fatalf("%s lost its owner", vf)
			}
			if tc.silent && len(reported) != 0 {
				t.Fatalf("reported %v for a device that is in use", reported)
			}
			if !tc.silent && (len(reported) != 1 || !strings.Contains(reported[0], vf)) {
				t.Fatalf("reported = %v; want one report naming %s", reported, vf)
			}
		})
	}
}

// TestSweepUnattachedPCIOwnership_AHardwareV2VMsHeldDevicesRaiseNoWarning is
// review S1's regression check: on a hardware_v2 cluster every VM has PCI
// intents, and the sweep used to WARN for each of their devices — including ones
// a running guest holds — telling the operator to `lv detach-pci` them, on every
// daemon start and every rescan.
func TestSweepUnattachedPCIOwnership_AHardwareV2VMsHeldDevicesRaiseNoWarning(t *testing.T) {
	s, fake, fs, vf := unattachedRig(t)
	ctx := adminCtx()
	seedAddressIntent(t, s, "vm1", "dev-1", vf)
	if err := fake.AttachHostdevWithAlias("vm1", vf, "ua-dev-1-m0"); err != nil {
		t.Fatal(err)
	}
	fs.bound[vf] = true

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	released, reported := s.SweepUnattachedPCIOwnership(ctx)
	slog.SetDefault(prev)

	if len(released) != 0 || len(reported) != 0 {
		t.Fatalf("released %v, reported %v; want neither for a device its guest holds", released, reported)
	}
	if strings.Contains(buf.String(), "level=WARN") {
		t.Fatalf("the sweep warned about a device its guest holds:\n%s", buf.String())
	}
	if !ownedBy(t, ctx, s, "vm1")[vf] {
		t.Fatalf("%s lost its owner", vf)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
