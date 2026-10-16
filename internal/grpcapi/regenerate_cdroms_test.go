package grpcapi

import (
	"encoding/xml"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// cdromDisk is one <disk device='cdrom'> of a domain definition, as the guest
// sees it: the file, where it is attached, and that it is read-only.
type cdromDisk struct {
	File, Dev, Bus string
	ReadOnly       bool
}

func domainCDROMDisks(t *testing.T, domXML string) []cdromDisk {
	t.Helper()
	var dom struct {
		Disks []struct {
			Device string `xml:"device,attr"`
			Source struct {
				File string `xml:"file,attr"`
			} `xml:"source"`
			Target struct {
				Dev string `xml:"dev,attr"`
				Bus string `xml:"bus,attr"`
			} `xml:"target"`
			ReadOnly *struct{} `xml:"readonly"`
		} `xml:"devices>disk"`
	}
	if err := xml.Unmarshal([]byte(domXML), &dom); err != nil {
		t.Fatalf("parse domain XML: %v\n%s", err, domXML)
	}
	var out []cdromDisk
	for _, d := range dom.Disks {
		if d.Device != "cdrom" {
			continue
		}
		out = append(out, cdromDisk{File: d.Source.File, Dev: d.Target.Dev, Bus: d.Target.Bus, ReadOnly: d.ReadOnly != nil})
	}
	return out
}

// regenCreate creates image VM name with a cloud-init seed (and, with iso,
// an installer ISO), stops it, and returns the CD-ROMs CreateVM defined it
// with, after checking the seed is among them.
func regenCreate(t *testing.T, s *Server, fake *libvirtfake.Fake, name, iso string) []cdromDisk {
	t.Helper()
	req := seedCreateRequest(t, s, name, "#cloud-config\nhostname: "+name+"\n")
	if iso != "" {
		req.Spec.Iso = iso
		req.Spec.Project = "acme"
	}
	if _, err := s.CreateVM(adminCtx(), req); err != nil {
		t.Fatalf("CreateVM %s: %v", name, err)
	}
	created := domainCDROMDisks(t, fake.DefinedXML(name))
	seed := lv.CloudInitISOPath(s.dataDir, name)
	want := 1
	if iso != "" {
		want = 2
	}
	hasSeed := false
	for _, c := range created {
		hasSeed = hasSeed || c.File == seed
	}
	if !hasSeed || len(created) != want {
		t.Fatalf("setup: CreateVM defined %s with CD-ROMs %+v, want %d with the seed %s", name, created, want, seed)
	}
	if _, err := s.StopVM(adminCtx(), &pb.StopVMRequest{Name: name, Force: true}); err != nil {
		t.Fatalf("StopVM %s: %v", name, err)
	}
	return created
}

// regenISOServer is a create server with the seed stand-in and an uploaded
// installer ISO, default/installer.iso, that project acme may use.
func regenISOServer(t *testing.T) (*Server, *libvirtfake.Fake) {
	t.Helper()
	stageGenisoimage(t)
	s, fake, _ := isoServer(t)
	_ = acmeOperator(t, s)
	_ = disksDefaultPool(t, s)
	if err := uploadAs(adminCtx(), s, "default", "installer.iso", isoBody); err != nil {
		t.Fatalf("upload installer.iso: %v", err)
	}
	return s, fake
}

// claimOwnedOnlyGPU gives vm a passthrough device by ownership alone — no
// intent — which makes every reconcileDomainDefinition of it a full
// regenerate rather than a patch of the prior definition.
func claimOwnedOnlyGPU(t *testing.T, s *Server, vm string) {
	t.Helper()
	ctx := adminCtx()
	if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: s.hostName, Address: "0000:02:00.0", Type: "gpu",
	}); err != nil {
		t.Fatalf("observe: %v", err)
	}
	if ok, err := corrosion.ClaimPCIDevice(ctx, s.db, s.hostName, "0000:02:00.0", vm); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
}

// A full regenerate of a VM's domain — UpdateVM's (a guest-agent toggle,
// --restart-if-needed, compose's redefine_hardware) and the reconcile
// primitive's (a stopped-VM device change on a VM with an ownership-only
// passthrough device, a start re-judging shared disks) — built the domain
// without the cloud-init seed and the installer ISO: neither is a vm_disks
// row, and the seed is set on the create's VMConfig alone. The VM lost its
// NoCloud datasource (hostname, network-config) on its next boot, and its
// installer. Each regenerate now defines the CD-ROMs the create did: same
// file, same target, same bus, read-only.
//
// Mutation: drop the keepCDROMs call from either regenerate — its subtest
// goes red.
func TestRegenerate_KeepsTheCDROMsCreateAttached(t *testing.T) {
	paths := map[string]func(t *testing.T, s *Server, name string){
		"UpdateVM": func(t *testing.T, s *Server, name string) {
			if _, err := s.UpdateVM(adminCtx(), &pb.UpdateVMRequest{Name: name, GuestAgent: proto.Bool(true)}); err != nil {
				t.Fatalf("UpdateVM: %v", err)
			}
		},
		"reconcile": func(t *testing.T, s *Server, name string) {
			claimOwnedOnlyGPU(t, s, name)
			if err := s.reconcileDomainDefinition(adminCtx(), mustGetVM(t, s, name), nil); err != nil {
				t.Fatalf("reconcileDomainDefinition: %v", err)
			}
		},
	}
	for path, regenerate := range paths {
		for _, iso := range []string{"", "default/installer.iso"} {
			sub := path + "/seed"
			if iso != "" {
				sub += "+installer"
			}
			t.Run(sub, func(t *testing.T) {
				s, fake := regenISOServer(t)
				created := regenCreate(t, s, fake, "rg", iso)
				regenerate(t, s, "rg")
				after := fake.DefinedXML("rg")
				if path == "reconcile" && domainHostdevCount(t, after) == 0 {
					t.Fatalf("setup: the reconcile did not regenerate (no ownership hostdev):\n%s", after)
				}
				if got := domainCDROMDisks(t, after); !reflect.DeepEqual(got, created) {
					t.Errorf("regenerated CD-ROMs = %+v, want what CreateVM defined: %+v\n%s", got, created, after)
				}
			})
		}
	}
}

func domainHostdevCount(t *testing.T, domXML string) int {
	t.Helper()
	var dom struct {
		Hostdevs []struct{} `xml:"devices>hostdev"`
	}
	if err := xml.Unmarshal([]byte(domXML), &dom); err != nil {
		t.Fatalf("parse domain XML: %v", err)
	}
	return len(dom.Hostdevs)
}

// A definition an earlier regenerate already stripped of its seed gets it
// back on the next one, when the seed on this host is this VM's
// (cloudinit.SeedIsFor). A seed that is another VM's — one left by a deleted
// VM of the name — is not attached: it would boot that VM's user-data.
//
// Mutation: attach the seed whenever the file exists — the foreign subtest
// goes red. Attach it only when the prior definition had it — the stripped
// subtest goes red.
func TestRegenerate_ASeedThisVMOwnsIsAttachedEvenWhenTheDefinitionLostIt(t *testing.T) {
	for _, tc := range []struct {
		name     string
		foreign  bool
		wantSeed bool
	}{
		{"stripped", false, true},
		{"foreign", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fake := regenISOServer(t)
			created := regenCreate(t, s, fake, "rg", "")
			seed := lv.CloudInitISOPath(s.dataDir, "rg")
			// The definition as an earlier regenerate left it: no CD-ROM.
			stripped := removeCDROMs(t, fake.DefinedXML("rg"))
			if len(domainCDROMDisks(t, stripped)) != 0 {
				t.Fatalf("setup: the stripped definition still has CD-ROMs:\n%s", stripped)
			}
			if err := fake.DefineDomain(stripped); err != nil {
				t.Fatal(err)
			}
			if tc.foreign {
				if err := cloudinit.StampSeed(seed, "another-vm-uuid"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.UpdateVM(adminCtx(), &pb.UpdateVMRequest{Name: "rg", GuestAgent: proto.Bool(true)}); err != nil {
				t.Fatalf("UpdateVM: %v", err)
			}
			got := domainCDROMDisks(t, fake.DefinedXML("rg"))
			if tc.wantSeed && !reflect.DeepEqual(got, created) {
				t.Errorf("the VM's own seed was not attached again: CD-ROMs %+v, want %+v", got, created)
			}
			if !tc.wantSeed && len(got) != 0 {
				t.Errorf("another VM's seed was attached: %+v", got)
			}
		})
	}
}

// removeCDROMs drops every <disk device="cdrom"> element from domXML.
func removeCDROMs(t *testing.T, domXML string) string {
	t.Helper()
	out := domXML
	for {
		start := strings.Index(out, `device="cdrom"`)
		if start < 0 {
			return out
		}
		start = strings.LastIndex(out[:start], "<disk")
		end := strings.Index(out[start:], "</disk>")
		if start < 0 || end < 0 {
			t.Fatalf("unterminated cdrom disk:\n%s", out)
		}
		out = out[:start] + out[start+end+len("</disk>"):]
	}
}
