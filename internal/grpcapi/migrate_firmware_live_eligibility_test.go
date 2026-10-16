package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

const (
	fwLiveUUID     = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	fwLiveAttempt1 = "a7000000-0000-4000-8000-000000000001"
	fwLiveAttempt2 = "a7000000-0000-4000-8000-000000000002"
)

// stubFWCode is a host's LiveFirmwareHost, as stage A and Prepare read it.
type stubFWCode struct {
	installed  lv.InstalledFirmwareCode
	checkErr   error // the first condition of Check that fails
	checks     int   // Check calls
	running    lv.FirmwareRuntime
	runningErr error
	gotXML     string // the live XML RunningFirmwareCode was given
}

func (c *stubFWCode) Check(context.Context) (lv.InstalledFirmwareCode, error) {
	c.checks++
	if c.checkErr != nil {
		return lv.InstalledFirmwareCode{}, c.checkErr
	}
	return c.installed, nil
}

func (c *stubFWCode) RunningFirmwareCode(_ context.Context, liveXML string) (lv.FirmwareRuntime, error) {
	c.gotXML = liveXML
	if c.runningErr != nil {
		return lv.FirmwareRuntime{}, c.runningErr
	}
	return c.running, nil
}

// fwFloorRuntime is a host exactly at every floor (the probe's own OVMF
// fingerprint, which the RPC form replaces).
var fwFloorRuntime = lv.FirmwareRuntime{Libvirt: "10.0.0", QEMU: "8.2.2", Swtpm: "0.7.3", Libtpms: "0.9.3", OVMFFingerprint: "probe-ovmf"}

// fwLiveFixture is a source host running os1, a Secure Boot + vTPM VM with
// one host-local disk, eligible for a live move to dst-host with
// --with-storage. Each stage A row breaks exactly one thing.
type fwLiveFixture struct {
	s    *Server
	virt *libvirtfake.Fake
	code *stubFWCode
	tls  bool
	spec map[string]any
	m    liveFirmwareMove
}

func setFWTestFirmwarePaths(t *testing.T, s *Server) {
	t.Helper()
	dir := t.TempDir()
	fp := lv.FirmwarePaths{}
	for role, p := range map[string]*string{"code": &fp.Code, "vars": &fp.Vars, "secboot": &fp.SecbootCode, "msvars": &fp.MsVars} {
		*p = filepath.Join(dir, role+".fd")
		if err := os.WriteFile(*p, []byte("OVMF "+role), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s.SetFirmwarePaths(fp)
}

// fwLiveDomainXML is os1's running definition: uuid, Secure Boot loader,
// NVRAM at nvram ("" for none), and a TPM emulator backend whose
// persistent_state is ps (no TPM when tpm is false).
func fwLiveDomainXML(uuid, loader, nvram string, tpm bool, ps string) string {
	x := `<domain type='kvm'><name>os1</name><uuid>` + uuid + `</uuid><memory unit='MiB'>1024</memory><vcpu>1</vcpu><os><type>hvm</type>`
	if loader != "" {
		x += `<loader readonly='yes' secure='yes' type='pflash'>` + loader + `</loader>`
	}
	if nvram != "" {
		x += `<nvram>` + nvram + `</nvram>`
	}
	x += `</os><devices>`
	if tpm {
		attr := ""
		if ps != "" {
			attr = ` persistent_state='` + ps + `'`
		}
		x += `<tpm model='tpm-crb'><backend type='emulator' version='2.0'` + attr + `/></tpm>`
	}
	return x + `</devices></domain>`
}

func newFWLiveFixture(t *testing.T) *fwLiveFixture {
	t.Helper()
	f := &fwLiveFixture{tls: true}
	f.s = testServerWithLocks(t)
	f.s.hostName = "src-host"
	setFWTestFirmwarePaths(t, f.s)
	f.virt = libvirtfake.New()
	f.s.virt = f.virt
	f.setXML(fwLiveDomainXML(fwLiveUUID, f.s.firmware.SecbootCode, f.s.fw().NvramPath("os1"), true, "yes"))
	f.code = &stubFWCode{installed: lv.InstalledFirmwareCode{Runtime: fwFloorRuntime}, running: fwFloorRuntime}
	f.s.SetLiveFirmwareHost(f.code)
	f.s.SetMigrationTLS(func() (bool, error) { return f.tls, nil })
	f.spec = map[string]any{"name": "os1", "secure_boot": true, "tpm": true, "firmware": "uefi", "uuid": fwLiveUUID}
	f.m = liveFirmwareMove{
		vm: &corrosion.VMRecord{Name: "os1", HostName: "src-host", State: "running"},
		target: &corrosion.HostRecord{Name: "dst-host", Address: "192.168.1.2", Labels: map[string]string{
			corrosion.LabelTPMCapable: "true", corrosion.LabelSecureBootCapable: "true", corrosion.LabelFwLiveMigrate: "true",
		}},
		withStorage: true,
		disks:       []corrosion.DiskRecord{{VMName: "os1", DiskName: "root", Path: "/var/lib/litevirt/disks/os1.qcow2", StorageType: "local", TargetDev: "vda"}},
	}
	return f
}

// setXML (re)defines os1 with x and leaves it running.
func (f *fwLiveFixture) setXML(x string) {
	f.virt.SetInactiveXML("os1", x)
	f.virt.SetActiveXML("os1", x)
	f.virt.SetState("os1", libvirtfake.StateRunning)
}

func (f *fwLiveFixture) stageA(t *testing.T) (*liveFirmwareEligible, error) {
	t.Helper()
	b, _ := json.Marshal(f.spec)
	f.m.vm.Spec = string(b)
	return f.s.liveFirmwareStageA(context.Background(), f.m)
}

// requireRefusal: err is a FailedPrecondition refusal naming want, and the
// cold move that remains.
func requireRefusal(t *testing.T, err error, want ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("eligible, want a refusal naming %q", want)
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code %v, want FailedPrecondition: %v", status.Code(err), err)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("refusal %q does not say %q", err, w)
		}
	}
	if !strings.Contains(err.Error(), "--cold") {
		t.Fatalf("refusal %q does not name the cold move", err)
	}
}

// requireNoFirmwareRecords: eligibility wrote no firmware move record or
// directory on the host.
func requireNoFirmwareRecords(t *testing.T, s *Server) {
	t.Helper()
	for _, d := range []string{fwmig.InflightDir, fwmig.HoldDir} {
		if _, err := os.Stat(filepath.Join(s.fw().DataDir, d)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s exists after eligibility (stat: %v): eligibility writes nothing", d, err)
		}
	}
}

func fwLiveMarker(vm, uuid string) fwmig.Marker {
	return fwmig.Marker{
		VM: vm, Binding: fwmig.Binding{UUID: uuid, CreatedAt: "2026-10-15T00:00:00Z", Attempt: fwLiveAttempt1},
		Target: "other-host", Route: fwmig.RouteStorageCopy, Phase: fwmig.PhasePreparing, TPM: true, UEFI: true,
		Since: time.Now().UTC(),
	}
}

// TestLiveFirmwareEligibility is T-11 (with T-35's and T-38's stage A rows):
// each stage A row breaks one item of spec §3.2 on an otherwise eligible VM
// and must be refused with that item's own text, the cold move named, and
// nothing written; the stage B and C rows judge the Prepare answer and the
// resolved route.
//
// Mutation: delete any one check — its row goes red.
func TestLiveFirmwareEligibility(t *testing.T) {
	t.Run("A", func(t *testing.T) {
		t.Run("eligible", func(t *testing.T) {
			f := newFWLiveFixture(t)
			// The persistent definition is not what runs: only the running
			// one is judged.
			f.virt.SetInactiveXML("os1", fwLiveDomainXML(fwLiveUUID, "", "", false, ""))
			a, err := f.stageA(t)
			if err != nil {
				t.Fatalf("an eligible VM was refused: %v", err)
			}
			want, _ := f.s.liveFirmwareFingerprint()
			rt := a.runtime
			if rt.Libvirt != "10.0.0" || rt.Qemu != "8.2.2" || rt.Swtpm != "0.7.3" || rt.Libtpms != "0.9.3" || rt.OvmfFingerprint != want || !rt.LiveFirmwareEnabled {
				t.Fatalf("runtime = %+v, want the floors with fingerprint %q", rt, want)
			}
			if !a.applicability.Tpm || !a.applicability.Uefi || !a.storage || a.uuid != fwLiveUUID {
				t.Fatalf("eligible = %+v", a)
			}
			// The running code is checked against the RUNNING definition.
			if live, _ := f.virt.DumpXML("os1"); f.code.gotXML != live {
				t.Fatalf("RunningFirmwareCode got %q, want the running definition", f.code.gotXML)
			}
			requireNoFirmwareRecords(t, f.s)
		})
		rows := []struct {
			name   string
			break_ func(f *fwLiveFixture)
			want   []string
		}{
			// Item 1.
			// Item 1: the host check (its conditions are the daemon's,
			// internal/daemon fw_live_host_test.go); each reason reaches
			// the refusal.
			{"config_off", func(f *fwLiveFixture) { f.code.checkErr = errors.New("migration.live_firmware is off") },
				[]string{"src-host cannot take part: migration.live_firmware is off"}},
			{"installed_unreadable", func(f *fwLiveFixture) {
				f.code.checkErr = errors.New("installed firmware code: swtpm --version: exit 1")
			}, []string{"installed firmware code", "swtpm --version"}},
			{"floor_unmet", func(f *fwLiveFixture) {
				rt := fwFloorRuntime
				rt.QEMU = "8.2.1"
				f.code.checkErr = lv.FirmwareFloorsMet(rt)
			}, []string{"qemu 8.2.1 is below"}},
			{"libvirt_guests", func(f *fwLiveFixture) { f.code.checkErr = errors.New("libvirt-guests: ON_SHUTDOWN=suspend") },
				[]string{"ON_SHUTDOWN=suspend"}},
			{"host_unwired", func(f *fwLiveFixture) { f.s.SetLiveFirmwareHost(nil) }, []string{"cannot check its own live firmware runtime"}},
			// Item 2.
			{"source_paused", func(f *fwLiveFixture) { f.virt.SetPaused("os1") }, []string{"paused"}},
			{"source_shut_off", func(f *fwLiveFixture) { f.virt.SetState("os1", libvirtfake.StateShutdown) }, []string{"not running"}},
			{"state_unreadable", func(f *fwLiveFixture) {
				f.virt.FailDomainStateReason = func(string) error { return errors.New("libvirtd gone") }
			}, []string{"libvirtd gone"}},
			{"no_spec_uuid", func(f *fwLiveFixture) { delete(f.spec, "uuid") }, []string{"no uuid"}},
			{"uuid_differs", func(f *fwLiveFixture) {
				f.spec["uuid"] = "aaaaaaaa-bbbb-4ccc-8ddd-000000000000"
			}, []string{"has uuid", fwLiveUUID}},
			{"xml_unreadable", func(f *fwLiveFixture) {
				f.virt.FailDumpXML = func(string) error { return errors.New("dumpxml broke") }
			}, []string{"dumpxml broke"}},
			{"xml_without_tpm", func(f *fwLiveFixture) {
				f.setXML(fwLiveDomainXML(fwLiveUUID, f.s.firmware.SecbootCode, f.s.fw().NvramPath("os1"), false, ""))
			}, []string{"tpm=true", "tpm=false"}},
			{"xml_without_nvram", func(f *fwLiveFixture) {
				f.setXML(fwLiveDomainXML(fwLiveUUID, f.s.firmware.SecbootCode, "", true, "yes"))
			}, []string{"no loader or NVRAM"}},
			{"xml_without_loader", func(f *fwLiveFixture) {
				f.setXML(fwLiveDomainXML(fwLiveUUID, "", f.s.fw().NvramPath("os1"), true, "yes"))
			}, []string{"no loader or NVRAM"}},
			{"nvram_elsewhere", func(f *fwLiveFixture) {
				f.setXML(fwLiveDomainXML(fwLiveUUID, f.s.firmware.SecbootCode, "/elsewhere/os1_VARS.fd", true, "yes"))
			}, []string{"/elsewhere/os1_VARS.fd"}},
			{"running_code_refused", func(f *fwLiveFixture) {
				f.code.runningErr = errors.New("qemu exe (deleted); restart it (lv stop, lv start)")
			}, []string{"(deleted)"}},
			{"running_code_differs", func(f *fwLiveFixture) { f.code.running.Swtpm = "0.8.0" }, []string{"running code", "installed code"}},
			// Item 3.
			{"persistent_state", func(f *fwLiveFixture) {
				f.setXML(fwLiveDomainXML(fwLiveUUID, f.s.firmware.SecbootCode, f.s.fw().NvramPath("os1"), true, ""))
			}, []string{"persistent_state='yes'", "`lv stop os1`, `lv start os1`"}},
			// Item 4.
			{"snapshot_sidecar", func(f *fwLiveFixture) {
				p := lv.SnapshotFirmwareBundlePath(f.s.dataDir, "os1", "before-upgrade")
				if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
					panic(err)
				}
				if err := os.WriteFile(p, []byte("tar"), 0o600); err != nil {
					panic(err)
				}
			}, []string{"sidecar", "before-upgrade.tar"}},
			// Item 5.
			{"marker", func(f *fwLiveFixture) {
				if err := fwmig.New(f.s.fw().DataDir).PutMarker(fwLiveMarker("os1", fwLiveUUID)); err != nil {
					panic(err)
				}
			}, []string{"firmware move record", fwLiveAttempt1}},
			{"marker_same_uuid_other_name", func(f *fwLiveFixture) {
				if err := fwmig.New(f.s.fw().DataDir).PutMarker(fwLiveMarker("os1-old", fwLiveUUID)); err != nil {
					panic(err)
				}
			}, []string{"firmware move record"}},
			{"hold", func(f *fwLiveFixture) {
				h := fwmig.Hold{VM: "os1", Binding: fwmig.Binding{UUID: fwLiveUUID, CreatedAt: "2026-10-15T00:00:00Z", Attempt: fwLiveAttempt2},
					Source: "other-host", Since: time.Now().UTC(), State: fwmig.HoldPrepared, TPM: true, UEFI: true,
					NvramMaterialised: fwmig.NvramPending}
				if err := fwmig.New(f.s.fw().DataDir).PutHold(h); err != nil {
					panic(err)
				}
			}, []string{"firmware move record", fwLiveAttempt2}},
			{"record_unreadable", func(f *fwLiveFixture) {
				d := filepath.Join(f.s.fw().DataDir, fwmig.InflightDir)
				if err := os.MkdirAll(d, 0o700); err != nil {
					panic(err)
				}
				if err := os.WriteFile(filepath.Join(d, "os1.json"), []byte("{not json"), 0o600); err != nil {
					panic(err)
				}
			}, []string{"cannot be read"}},
			// Item 6.
			{"target_not_tpm", func(f *fwLiveFixture) { delete(f.m.target.Labels, corrosion.LabelTPMCapable) }, []string{"not vTPM-capable"}},
			{"target_not_secureboot", func(f *fwLiveFixture) { f.m.target.Labels[corrosion.LabelSecureBootCapable] = "false" },
				[]string{"not Secure-Boot-capable"}},
			{"target_no_fw_live_label", func(f *fwLiveFixture) { delete(f.m.target.Labels, corrosion.LabelFwLiveMigrate) },
				[]string{corrosion.LabelFwLiveMigrate}},
			// Item 7.
			{"route_local_without_with_storage", func(f *fwLiveFixture) { f.m.withStorage = false }, []string{"--with-storage"}},
			{"route_storage_with_shared_disks", func(f *fwLiveFixture) {
				f.m.disks = append(f.m.disks, corrosion.DiskRecord{VMName: "os1", DiskName: "data", Path: "/mnt/nfs/os1-data.qcow2", StorageType: "nfs", TargetDev: "vdb"})
			}, []string{"shared disks beside host-local", "data"}},
			{"route_storage_without_tls", func(f *fwLiveFixture) {
				f.tls = false
				f.s.SetAllowUnencryptedStorageMigration(true) // does not apply
			}, []string{"migration-TLS", "allow_unencrypted_storage does not apply"}},
		}
		for _, r := range rows {
			t.Run(r.name, func(t *testing.T) {
				f := newFWLiveFixture(t)
				r.break_(f)
				a, err := f.stageA(t)
				if a != nil {
					t.Fatalf("a refusal returned an eligibility: %+v", a)
				}
				requireRefusal(t, err, r.want...)
				if !strings.HasPrefix(r.name, "marker") && r.name != "hold" && r.name != "record_unreadable" {
					requireNoFirmwareRecords(t, f.s)
				}
			})
		}
		t.Run("memory_only_all_shared", func(t *testing.T) {
			f := newFWLiveFixture(t)
			f.m.withStorage = false
			f.tls = false // a tunnelled move needs no migration TLS
			f.m.disks = []corrosion.DiskRecord{{VMName: "os1", DiskName: "root", Path: "/mnt/nfs/os1.qcow2", StorageType: "nfs", TargetDev: "vda"}}
			a, err := f.stageA(t)
			if err != nil || a.storage {
				t.Fatalf("an all-shared VM: %+v, %v; want eligible without a storage copy", a, err)
			}
		})
		t.Run("secure_boot_only", func(t *testing.T) {
			f := newFWLiveFixture(t)
			f.spec["tpm"] = false
			delete(f.m.target.Labels, corrosion.LabelTPMCapable)
			f.setXML(fwLiveDomainXML(fwLiveUUID, f.s.firmware.SecbootCode, f.s.fw().NvramPath("os1"), false, ""))
			a, err := f.stageA(t)
			if err != nil || a.applicability.Tpm || !a.applicability.Uefi {
				t.Fatalf("an SB-only VM: %+v, %v", a, err)
			}
		})
		t.Run("bios_tpm", func(t *testing.T) {
			f := newFWLiveFixture(t)
			f.spec["secure_boot"], f.spec["firmware"] = false, "bios"
			delete(f.m.target.Labels, corrosion.LabelSecureBootCapable)
			f.setXML(fwLiveDomainXML(fwLiveUUID, "", "", true, "yes"))
			a, err := f.stageA(t)
			if err != nil || !a.applicability.Tpm || a.applicability.Uefi {
				t.Fatalf("a BIOS vTPM VM: %+v, %v", a, err)
			}
			// ... and one whose running definition keeps an NVRAM the row
			// does not declare is refused.
			f.setXML(fwLiveDomainXML(fwLiveUUID, "", f.s.fw().NvramPath("os1"), true, "yes"))
			_, err = f.stageA(t)
			requireRefusal(t, err, "keeps no UEFI vars")
		})
	})

	t.Run("B", func(t *testing.T) {
		f := newFWLiveFixture(t)
		a, err := f.stageA(t)
		if err != nil {
			t.Fatal(err)
		}
		ok := func() *pb.PrepareLiveFirmwareTargetResponse {
			rt := proto.Clone(a.runtime).(*pb.FirmwareRuntime)
			return &pb.PrepareLiveFirmwareTargetResponse{DstRuntime: rt, DstApplicability: &pb.FirmwareApplicability{Tpm: true, Uefi: true}}
		}
		t.Run("equal", func(t *testing.T) {
			if err := liveFirmwareStageB("os1", "dst-host", a, ok(), nil); err != nil {
				t.Fatalf("equal runtimes and applicability: %v", err)
			}
		})
		t.Run("unimplemented", func(t *testing.T) {
			err := liveFirmwareStageB("os1", "dst-host", a, nil, status.Error(codes.Unimplemented, "unknown method PrepareLiveFirmwareTarget"))
			requireRefusal(t, err, "must be migrated cold", "target dst-host runs a build without live firmware migration")
		})
		t.Run("other_error_kept", func(t *testing.T) {
			err := liveFirmwareStageB("os1", "dst-host", a, nil, status.Error(codes.Unavailable, "connection refused"))
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("a Prepare error became %v", err)
			}
			// It says what the target said, and names the cold move (merge
			// review m-2).
			for _, w := range []string{"connection refused", "--cold"} {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("a Prepare error %q does not say %q", err, w)
				}
			}
		})
		t.Run("no_runtime", func(t *testing.T) {
			r := ok()
			r.DstRuntime = nil
			requireRefusal(t, liveFirmwareStageB("os1", "dst-host", a, r, nil), "without its runtime")
		})
		t.Run("no_applicability", func(t *testing.T) {
			r := ok()
			r.DstApplicability = nil
			requireRefusal(t, liveFirmwareStageB("os1", "dst-host", a, r, nil), "applicability")
		})
		t.Run("runtime_differs", func(t *testing.T) {
			r := ok()
			r.DstRuntime.Qemu = "8.2.3"
			requireRefusal(t, liveFirmwareStageB("os1", "dst-host", a, r, nil), "qemu differs")
		})
		t.Run("target_live_firmware_off", func(t *testing.T) {
			r := ok()
			r.DstRuntime.LiveFirmwareEnabled = false
			requireRefusal(t, liveFirmwareStageB("os1", "dst-host", a, r, nil), "migration.live_firmware is off there")
		})
		for _, c := range []struct {
			name     string
			tpm, efi bool
		}{{"applicability_tpm", false, true}, {"applicability_uefi", true, false}} {
			t.Run(c.name, func(t *testing.T) {
				r := ok()
				r.DstApplicability = &pb.FirmwareApplicability{Tpm: c.tpm, Uefi: c.efi}
				requireRefusal(t, liveFirmwareStageB("os1", "dst-host", a, r, nil), "differs between the hosts' rows")
			})
		}
	})

	t.Run("C", func(t *testing.T) {
		target := corrosion.HostRecord{Name: "dst-host", Address: "192.168.1.2"}
		cluster := migrationRoute{addr: "192.168.1.2"}
		mignet := migrationRoute{addr: "10.20.0.2", direct: true, onNetwork: true}
		for _, c := range []struct {
			name    string
			storage bool
			r       migrationRoute
			bothTLS bool
			mignet  bool
			want    fwmig.Route
			refuse  string
		}{
			{"storage_cluster_tls", true, cluster, true, false, fwmig.RouteStorageCopy, ""},
			{"storage_without_tls", true, cluster, false, false, "", "would not be encrypted"},
			{"storage_over_mignet", true, migrationRoute{addr: "10.20.0.2", onNetwork: true}, true, true, "", "cluster address 192.168.1.2"},
			{"tunnelled", false, cluster, false, false, fwmig.RouteTunnelled, ""},
			{"tunnelled_elsewhere", false, migrationRoute{addr: "10.20.0.2"}, false, false, "", "cluster address 192.168.1.2"},
			{"mignet_while_off", false, mignet, true, false, "", "not yet allowed"}, // and names no internal test id (m-3)
			{"mignet_when_on", false, mignet, true, true, fwmig.RouteMigrationNetwork, ""},
			{"mignet_without_tls", false, mignet, false, true, "", "TLS on both hosts"},
			{"direct_off_network", false, migrationRoute{addr: "192.168.1.2", direct: true}, true, true, "", "migration network"},
		} {
			t.Run(c.name, func(t *testing.T) {
				defer setMignetRouteForTest(c.mignet)()
				got, err := liveFirmwareStageC("os1", target, c.storage, c.r, c.bothTLS)
				if c.refuse != "" {
					requireRefusal(t, err, c.refuse)
					if strings.Contains(err.Error(), "E-9") {
						t.Fatalf("refusal %q names an internal test id", err)
					}
					return
				}
				if err != nil || got != c.want {
					t.Fatalf("route %v, %v; want %v", got, err, c.want)
				}
			})
		}
	})
}

func setMignetRouteForTest(on bool) func() {
	old := liveFirmwareMignetRoute
	liveFirmwareMignetRoute = on
	return func() { liveFirmwareMignetRoute = old }
}

// TestLiveFirmwareEligibility_Unequal is T-13's comparison half (spec §3.2
// item 9): a runtime field that differs either way — the target newer or
// older — refuses, naming the field and both values; the layout half of the
// fingerprint is compared before the OVMF content half; an empty or
// unreadable field never compares equal; testedFirmwarePairs is empty and,
// when it holds a pair, admits exactly that pair.
//
// Mutation: compare `>=`; skip a field; compare the OVMF content before the
// layout; treat an empty field as equal; ignore testedFirmwarePairs — red.
func TestLiveFirmwareEligibility_Unequal(t *testing.T) {
	base := func() *pb.FirmwareRuntime {
		return &pb.FirmwareRuntime{Libvirt: "10.0.0", Qemu: "8.2.2", Swtpm: "0.7.3", Libtpms: "0.9.3",
			OvmfFingerprint: "layout:L1 ovmf:O1", LiveFirmwareEnabled: true}
	}
	if err := compareFirmwareRuntimes(base(), base()); err != nil {
		t.Fatalf("equal runtimes: %v", err)
	}
	if len(testedFirmwarePairs) != 0 {
		t.Fatalf("testedFirmwarePairs has %d entries; v1 ships it empty", len(testedFirmwarePairs))
	}
	for _, c := range []struct {
		field        string
		set          func(r *pb.FirmwareRuntime, v string)
		older, newer string
		name, src    string
	}{
		{"libvirt", func(r *pb.FirmwareRuntime, v string) { r.Libvirt = v }, "9.9.9", "10.0.1", "libvirt", "10.0.0"},
		{"qemu", func(r *pb.FirmwareRuntime, v string) { r.Qemu = v }, "8.2.1", "8.2.3", "qemu", "8.2.2"},
		{"swtpm", func(r *pb.FirmwareRuntime, v string) { r.Swtpm = v }, "0.7.2", "0.7.4", "swtpm", "0.7.3"},
		{"libtpms", func(r *pb.FirmwareRuntime, v string) { r.Libtpms = v }, "0.9.2", "0.9.4", "libtpms", "0.9.3"},
		{"layout", func(r *pb.FirmwareRuntime, v string) { r.OvmfFingerprint = "layout:" + v + " ovmf:O1" }, "L0", "L2", "firmware layout", "L1"},
		{"ovmf", func(r *pb.FirmwareRuntime, v string) { r.OvmfFingerprint = "layout:L1 ovmf:" + v }, "O0", "O2", "ovmf_fingerprint", "O1"},
	} {
		t.Run(c.field, func(t *testing.T) {
			for _, v := range []string{c.older, c.newer} {
				dst := base()
				c.set(dst, v)
				err := compareFirmwareRuntimes(base(), dst)
				if err == nil {
					t.Fatalf("target %s %s against source %s was accepted", c.field, v, c.src)
				}
				for _, w := range []string{c.name, c.src, v} {
					if !strings.Contains(err.Error(), w) {
						t.Fatalf("%q does not name %q", err, w)
					}
				}
				// Either direction.
				if err := compareFirmwareRuntimes(dst, base()); err == nil {
					t.Fatalf("source %s %s against target %s was accepted", c.field, v, c.src)
				}
			}
			// Empty on either side is never equal, even to empty.
			for _, pair := range [][2]string{{"", ""}, {"x", ""}} {
				src, dst := base(), base()
				if c.field == "layout" || c.field == "ovmf" {
					src.OvmfFingerprint, dst.OvmfFingerprint = pair[0], pair[1]
				} else {
					c.set(src, pair[0])
					c.set(dst, pair[1])
				}
				if err := compareFirmwareRuntimes(src, dst); err == nil {
					t.Fatalf("%s %q against %q was accepted", c.field, pair[0], pair[1])
				}
			}
		})
	}
	t.Run("layout_named_first", func(t *testing.T) {
		dst := base()
		dst.OvmfFingerprint = "layout:L2 ovmf:O2"
		err := compareFirmwareRuntimes(base(), dst)
		if err == nil || !strings.Contains(err.Error(), "firmware layout") {
			t.Fatalf("both halves differ: %v; want the layout named", err)
		}
	})
	t.Run("tested_pair", func(t *testing.T) {
		src, dst := base(), base()
		dst.Qemu = "8.2.3"
		testedFirmwarePairs[[2]firmwareRuntimeKey{runtimeKey(src), runtimeKey(dst)}] = true
		defer delete(testedFirmwarePairs, [2]firmwareRuntimeKey{runtimeKey(src), runtimeKey(dst)})
		if err := compareFirmwareRuntimes(src, dst); err != nil {
			t.Fatalf("a tested pair was refused: %v", err)
		}
		other := base()
		other.Qemu = "8.2.4"
		if err := compareFirmwareRuntimes(src, other); err == nil {
			t.Fatal("a pair outside testedFirmwarePairs was accepted")
		}
	})
}

// TestLiveFirmwareFingerprint: the fingerprint a host sends splits back into
// its layout and OVMF content halves; the same OVMF content at other paths
// differs in the layout half only, and other content in the OVMF half only.
//
// Mutation: drop either half; hash paths into the OVMF half — red.
func TestLiveFirmwareFingerprint(t *testing.T) {
	s := testServer(t)
	setFWTestFirmwarePaths(t, s)
	fp, err := s.liveFirmwareFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	l1, o1, ok := splitLiveFirmwareFingerprint(fp)
	if !ok || l1 != s.firmwareLayoutFingerprint() {
		t.Fatalf("fingerprint %q: layout %q ok %v, want %q", fp, l1, ok, s.firmwareLayoutFingerprint())
	}
	// The same content at other paths.
	moved := s.firmware
	dir := t.TempDir()
	for _, p := range []*string{&moved.Code, &moved.Vars, &moved.SecbootCode, &moved.MsVars} {
		b, err := os.ReadFile(*p)
		if err != nil {
			t.Fatal(err)
		}
		*p = filepath.Join(dir, filepath.Base(*p))
		if err := os.WriteFile(*p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	orig := s.firmware
	s.SetFirmwarePaths(moved)
	fp2, _ := s.liveFirmwareFingerprint()
	l2, o2, _ := splitLiveFirmwareFingerprint(fp2)
	if l2 == l1 || o2 != o1 {
		t.Fatalf("same OVMF at other paths: layout %q→%q, ovmf %q→%q; want only the layout to change", l1, l2, o1, o2)
	}
	// Other content at the same paths.
	s.SetFirmwarePaths(orig)
	if err := os.WriteFile(orig.SecbootCode, []byte("another OVMF build"), 0o644); err != nil {
		t.Fatal(err)
	}
	fp3, _ := s.liveFirmwareFingerprint()
	l3, o3, _ := splitLiveFirmwareFingerprint(fp3)
	if l3 != l1 || o3 == o1 {
		t.Fatalf("other OVMF content: layout %q→%q, ovmf %q→%q; want only the OVMF half to change", l1, l3, o1, o3)
	}
	// An unreadable configured file is an error, never a fingerprint.
	if err := os.Remove(orig.MsVars); err != nil {
		t.Fatal(err)
	}
	if fp, err := s.liveFirmwareFingerprint(); err == nil {
		t.Fatalf("a missing OVMF file gave fingerprint %q", fp)
	}
	for _, bad := range []string{"", "layout:L ovmf:", "layout: ovmf:O", "L O", "sha256:ab12"} {
		if _, _, ok := splitLiveFirmwareFingerprint(bad); ok {
			t.Fatalf("%q split as a fingerprint", bad)
		}
	}
}

// TestPbFirmwareRuntime: the runtime a live firmware move sends carries the
// host's live firmware fingerprint in place of the probe's own OVMF one (which
// is over the host's own dataDir, not the layout's), with
// live_firmware_enabled; an unreadable OVMF file is an error.
//
// Mutation: send the probe's own OVMF fingerprint; drop live_firmware_enabled — red.
func TestPbFirmwareRuntime(t *testing.T) {
	f := newFWLiveFixture(t)
	f.s.SetFirmwareLayoutDirForTest(t.TempDir())
	rt, err := f.s.pbFirmwareRuntime(probeRuntime(t, f.s))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := f.s.liveFirmwareFingerprint()
	if rt.Qemu != "8.2.2" || rt.OvmfFingerprint != want || !rt.LiveFirmwareEnabled {
		t.Fatalf("runtime %+v, want fingerprint %q and live_firmware_enabled", rt, want)
	}
	if err := os.Remove(f.s.firmware.MsVars); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.pbFirmwareRuntime(fwFloorRuntime); err == nil {
		t.Fatal("an unreadable OVMF file gave a runtime")
	}
}

// TestFirmwareRouteOverride is T-37 (spec §6.0): a live firmware move's
// storage copy always goes to the cluster address; its memory-only move goes
// through the tunnel while the D-3 mignet entry is off and keeps the
// migration network route once it is on. Every route the override gives
// passes stage C.
//
// Mutation: return chooseMigrationRoute's result unchanged — red.
func TestFirmwareRouteOverride(t *testing.T) {
	target := corrosion.HostRecord{Name: "dst-host", Address: "192.168.1.2"}
	cluster := migrationRoute{addr: "192.168.1.2"}
	mignetStorage := migrationRoute{addr: "10.20.0.2", onNetwork: true}
	mignetMemory := migrationRoute{addr: "10.20.0.2", direct: true, onNetwork: true}
	t.Run("StorageAlwaysCluster", func(t *testing.T) {
		for _, on := range []bool{false, true} {
			restore := setMignetRouteForTest(on)
			for _, in := range []migrationRoute{mignetStorage, cluster} {
				got := firmwareRouteOverride(in, routeStorage, target)
				if got != cluster {
					t.Fatalf("mignet entry %v: storage %+v → %+v, want the cluster address", on, in, got)
				}
				if r, err := liveFirmwareStageC("os1", target, true, got, true); err != nil || r != fwmig.RouteStorageCopy {
					t.Fatalf("stage C refused the override's storage route: %v %v", r, err)
				}
			}
			restore()
		}
	})
	t.Run("MemoryTunnelWhileMignetOff", func(t *testing.T) {
		defer setMignetRouteForTest(false)()
		for _, in := range []migrationRoute{mignetMemory, cluster} {
			got := firmwareRouteOverride(in, routeMemory, target)
			if got != cluster {
				t.Fatalf("memory %+v → %+v, want the tunnel on the cluster address", in, got)
			}
			if r, err := liveFirmwareStageC("os1", target, false, got, true); err != nil || r != fwmig.RouteTunnelled {
				t.Fatalf("stage C refused the override's tunnelled route: %v %v", r, err)
			}
		}
	})
	t.Run("MemoryMignetWhenOn", func(t *testing.T) {
		defer setMignetRouteForTest(true)()
		got := firmwareRouteOverride(mignetMemory, routeMemory, target)
		if got != mignetMemory {
			t.Fatalf("memory over the migration network → %+v with the entry on", got)
		}
		if r, err := liveFirmwareStageC("os1", target, false, got, true); err != nil || r != fwmig.RouteMigrationNetwork {
			t.Fatalf("stage C refused the migration network route: %v %v", r, err)
		}
		// A fallback chooseMigrationRoute already took stays the tunnel.
		if got := firmwareRouteOverride(cluster, routeMemory, target); got != cluster {
			t.Fatalf("tunnel → %+v", got)
		}
	})
	t.Run("ColdUnchanged", func(t *testing.T) {
		if got := firmwareRouteOverride(mignetStorage, routeCold, target); got != mignetStorage {
			t.Fatalf("cold %+v → %+v", mignetStorage, got)
		}
	})
}

// TestChooseLiveFirmwareRoute: on a host with migration.network, the live
// firmware route is the override's, and moving the data off the network is
// said on the VM's events.
//
// Mutation: return chooseMigrationRoute's answer; drop the event — red.
func TestChooseLiveFirmwareRoute(t *testing.T) {
	defer setMignetRouteForTest(false)()
	target := corrosion.HostRecord{Name: "dst-host", Address: "192.168.1.2"}
	for _, c := range []struct {
		name string
		kind routeKind
		why  string
	}{{"storage", routeStorage, "does not copy storage"}, {"memory", routeMemory, "until its stream is verified"}} {
		t.Run(c.name, func(t *testing.T) {
			s := testServer(t)
			s.migrationNetwork = "10.20.0.0/24"
			s.SetLocalIPsForTest(func() ([]net.IP, error) { return []net.IP{net.ParseIP("10.20.0.50")}, nil })
			got := s.chooseLiveFirmwareRoute(context.Background(), "os1", target, "10.20.0.2", c.kind, true)
			if got != (migrationRoute{addr: "192.168.1.2"}) {
				t.Fatalf("route %+v, want the cluster address", got)
			}
			evs, _ := corrosion.ListVMEvents(context.Background(), s.db, "os1", 10, "")
			found := false
			for _, e := range evs {
				if e.Type == "vm.migrate.network_fallback" && strings.Contains(e.Detail, c.why) && strings.Contains(e.Detail, "live firmware") {
					found = true
				}
			}
			if !found {
				t.Fatalf("no live firmware network_fallback event saying %q: %+v", c.why, evs)
			}
		})
	}
}
