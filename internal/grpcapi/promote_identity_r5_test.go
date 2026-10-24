package grpcapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// renamedRetry runs the retry of a renamed promotion whose first attempt
// defined and started vm1-p from domXML, then crashed before its "started"
// checkpoint (its marker is there).
func renamedRetry(t *testing.T, domXML string) (*Server, error) {
	t.Helper()
	s, fake := promoteFixture(t)
	s.db.SetClusterPolicyGate(func() bool { return true }) // guards are recorded
	s.SetReleaseFeatureGate(&relGate{t: t, open: true})
	// It runs from the live disk it built: one that runs from none is not
	// adopted (NB-R3).
	domXML = strings.Replace(domXML, "<devices>", "<devices>"+adoptablePromotedDisk(t, s, "replica-pool", "vm1-p"), 1)
	if err := fake.DefineDomain(domXML); err != nil {
		t.Fatal(err)
	}
	if err := fake.StartDomain("vm1-p"); err != nil {
		t.Fatal(err)
	}
	// The marker names the uuid of the domain the attempt defined.
	if err := s.writePromoteMarkerFor("vm1-p", "", domainUUIDFromXML(domXML)); err != nil {
		t.Fatal(err)
	}
	return s, s.PromoteReplica(&pb.PromoteReplicaRequest{
		VmName: "vm1", NewName: "vm1-p", TargetPool: "replica-pool", NoLocalize: true,
	}, &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()})
}

// A renamed promotion's retry that adopts the domain its first attempt
// started records that domain's MACs, by position, for the row's spec, the
// NIC rows and the NIC guards: the guest's NICs are the domain's, and a MAC
// the retry minted names nothing (dupcreate re-review 4, m-1). A domain
// whose NICs are not the spec's in number is not adopted.
//
// Mutation: keep the MACs the retry minted — red.
func TestPromoteReplica_ARenamedRetryAdoptsTheRunningDomainsMACs(t *testing.T) {
	const first = "eeeeeeee-0000-0000-0000-000000000031"
	const mac = "52:54:00:aa:bb:31"
	t.Run("adopted", func(t *testing.T) {
		s, err := renamedRetry(t, fmt.Sprintf("<domain type='kvm'><name>vm1-p</name><uuid>%s</uuid><devices>"+
			"<interface type='bridge'><mac address='%s'/><source bridge='lo'/></interface></devices></domain>", first, mac))
		if err != nil {
			t.Fatalf("renamed promotion retry: %v", err)
		}
		row, _ := corrosion.GetVM(adminCtx(), s.db, "vm1-p")
		if row == nil {
			t.Fatal("no row for the promoted VM")
		}
		var spec pb.VMSpec
		if err := json.Unmarshal([]byte(row.Spec), &spec); err != nil {
			t.Fatal(err)
		}
		if len(spec.Network) != 1 || spec.Network[0].Mac != mac {
			t.Errorf("the adopted VM's spec NICs = %v, want the domain's %s", spec.Network, mac)
		}
		ifaces, _ := corrosion.GetVMInterfaces(adminCtx(), s.db, "vm1-p")
		if len(ifaces) != 1 || ifaces[0].MAC != mac {
			t.Errorf("vm_interfaces = %+v, want the domain's %s", ifaces, mac)
		}
		nics, _ := corrosion.GetVMNICsRaw(adminCtx(), s.db, "vm_nics", "vm1-p")
		if len(nics) != 1 || nics[0].MAC != mac {
			t.Errorf("vm_nics = %+v, want the domain's %s", nics, mac)
		}
		guards, _ := corrosion.ListNICGuards(adminCtx(), s.db)
		n := 0
		for _, g := range guards {
			if g.VMName != "vm1-p" {
				continue
			}
			n++
			if g.MAC != mac {
				t.Errorf("NIC guard names MAC %s, want the domain's %s", g.MAC, mac)
			}
		}
		if n != 1 {
			t.Errorf("%d NIC guards for vm1-p, want 1", n)
		}
	})
	// A domain that is not adopted for what does not clear on a retry is a
	// FailedPrecondition that names the way out (dupcreate verify 5, m-1),
	// and a NIC adopted by position is on the spec NIC's network (n-1).
	for _, tc := range []struct{ name, ifaces string }{
		{"NIC count differs", fmt.Sprintf("<interface type='bridge'><mac address='%s'/><source bridge='lo'/></interface>"+
			"<interface type='bridge'><mac address='52:54:00:aa:bb:32'/><source bridge='lo'/></interface>", mac)},
		{"an interface names no MAC", "<interface type='bridge'><source bridge='lo'/></interface>"},
		{"a NIC on another network", fmt.Sprintf("<interface type='bridge'><mac address='%s'/><source bridge='other'/></interface>", mac)},
		{"a NIC on no bridge", fmt.Sprintf("<interface type='network'><mac address='%s'/><source network='lo'/></interface>", mac)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := renamedRetry(t, fmt.Sprintf("<domain type='kvm'><name>vm1-p</name><uuid>%s</uuid><devices>%s</devices></domain>", first, tc.ifaces))
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("retry adopting a domain whose NICs are not the spec's: %v, want FailedPrecondition", err)
			}
			for _, w := range []string{"virsh destroy vm1-p", "virsh undefine vm1-p", "test-host", "--new-name"} {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("refusal %q does not name %q", err.Error(), w)
				}
			}
			if row, _ := corrosion.GetVM(adminCtx(), s.db, "vm1-p"); row != nil {
				t.Error("a row was written for a domain that was not adopted")
			}
		})
	}
}

// The disk rule knows a Ceph RBD network disk by its pool/image against the
// recorded "rbd:" path, options and all (re-review 4, m-2).
//
// Mutation: read only source file/dev — the rbd cases red.
func TestDomainRunsOnAny_MatchesRBDNetworkDisks(t *testing.T) {
	rbd := func(name string) string {
		return fmt.Sprintf("<domain><devices><disk type='network' device='disk'><source protocol='rbd' name='%s'>"+
			"<host name='10.0.0.1' port='6789'/></source></disk></devices></domain>", name)
	}
	recorded := []string{`rbd:lv/vm1-root:id=litevirt:keyring=/k:mon_host=10.0.0.1\:6789`}
	for _, tc := range []struct {
		name string
		xml  string
		want bool
	}{
		{"same image", rbd("lv/vm1-root"), true},
		{"other image", rbd("lv/vm2-root"), false},
		{"other pool", rbd("other/vm1-root"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := domainRunsOnAny(tc.xml, recorded)
			if err != nil || got != tc.want {
				t.Errorf("domainRunsOnAny = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
	t.Run("a legacy Ceph domain is the VM's", func(t *testing.T) {
		s, fake := promoteFixture(t)
		if err := s.db.Execute(adminCtx(), `UPDATE vm_disks SET path = ?, storage_type = 'ceph' WHERE vm_name = 'vm1'`, recorded[0]); err != nil {
			t.Fatal(err)
		}
		x := strings.Replace(rbd("lv/vm1-root"), "<domain>", "<domain type='kvm'><name>vm1</name><uuid>eeeeeeee-0000-0000-0000-000000000033</uuid>", 1)
		if err := fake.DefineDomain(x); err != nil {
			t.Fatal(err)
		}
		own, _, why, err := s.domainIsVMsOwn(adminCtx(), "vm1", "aaaaaaaa-0000-0000-0000-000000000001", "vm1")
		if err != nil || !own {
			t.Errorf("domainIsVMsOwn = %v, %q, %v; want the VM's own", own, why, err)
		}
	})
}

// When no disk matches, the reason says what was compared: a VM with no disk
// recorded on this host has none to match, and otherwise none of the
// domain's disks is one recorded here (re-review 4, m-2).
//
// Mutation: one fixed reason — red.
func TestDomainIsVMsOwn_SaysWhyNoDiskMatches(t *testing.T) {
	s, fake := promoteFixture(t)
	if err := fake.DefineDomain("<domain type='kvm'><name>vm1</name><uuid>eeeeeeee-0000-0000-0000-000000000034</uuid>" +
		"<devices><disk type='file' device='disk'><source file='/elsewhere.qcow2'/></disk></devices></domain>"); err != nil {
		t.Fatal(err)
	}
	_, _, why, err := s.domainIsVMsOwn(adminCtx(), "vm1", "aaaaaaaa-0000-0000-0000-000000000001", "vm1")
	if err != nil || !strings.Contains(why, "none of its disks") {
		t.Errorf("why = %q, %v; want none of its disks is a recorded one", why, err)
	}
	if err := s.db.Execute(adminCtx(), `UPDATE vm_disks SET host_name = 'dead-host' WHERE vm_name = 'vm1'`); err != nil {
		t.Fatal(err)
	}
	_, _, why, err = s.domainIsVMsOwn(adminCtx(), "vm1", "aaaaaaaa-0000-0000-0000-000000000001", "vm1")
	if err != nil || !strings.Contains(why, "records no disk on") {
		t.Errorf("why = %q, %v; want the row records no disk here", why, err)
	}
}

// The disk rule compares spellings before it looks at any file, and looks
// at a file within sharedDiskStatTimeout: a hard mount whose server is gone
// makes the domain unidentifiable, never hangs the caller (re-review 4,
// n-1).
//
// Mutations: stat before the spelling pass — the spelled case stats, red;
// stat unbounded — the hung case does not return, red.
func TestDomainRunsOnAny_SpellingFirstAndBoundedStat(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var stats atomic.Int32
	prevStat, prevTimeout := statShared, sharedDiskStatTimeout
	statShared = func(string) (os.FileInfo, error) {
		stats.Add(1)
		<-release
		return nil, errors.New("released")
	}
	sharedDiskStatTimeout = 50 * time.Millisecond
	t.Cleanup(func() { statShared, sharedDiskStatTimeout = prevStat, prevTimeout })

	dom := "<domain><devices><disk type='file' device='disk'><source file='/mnt/a.qcow2'/></disk>" +
		"<disk type='file' device='disk'><source file='/mnt/b.qcow2'/></disk></devices></domain>"
	if got, err := domainRunsOnAny(dom, []string{"/mnt/b.qcow2"}); !got || err != nil {
		t.Errorf("spelled match = %v, %v; want true", got, err)
	}
	if n := stats.Load(); n != 0 {
		t.Errorf("%d stats before the spelling matched, want 0", n)
	}
	done := make(chan error, 1)
	go func() {
		_, err := domainRunsOnAny(dom, []string{filepath.Join(t.TempDir(), "c.qcow2")})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("an unreachable disk read as a non-match, want an identification error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("domainRunsOnAny hung on an unreachable disk")
	}
}

// promote --force over a running domain that is not the VM's names the way
// out: `lv stop` when this host owns the VM; when another host does, the
// reconciler stops the local domain on its own, or `virsh destroy` (re-review
// 4, n-2).
//
// Mutation: drop the way out from the refusal — red.
func TestPromoteReplica_ForceRefusalNamesTheWayOut(t *testing.T) {
	for _, tc := range []struct {
		name  string
		away  bool
		wants []string
	}{
		{"owned here", false, []string{"lv stop vm1", "retry"}},
		{"owned elsewhere", true, []string{"dead-host", "a superseded copy of this VM", "reconciler", "virsh destroy vm1", "retry"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fake := promoteFixture(t)
			if tc.away {
				moveVM1Away(t, s)
			}
			if err := fake.DefineDomain("<domain type='kvm'><name>vm1</name><uuid>eeeeeeee-0000-0000-0000-000000000035</uuid></domain>"); err != nil {
				t.Fatal(err)
			}
			if err := fake.StartDomain("vm1"); err != nil {
				t.Fatal(err)
			}
			err := promoteVM1(s, true)
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("--force over a running foreign domain: %v, want FailedPrecondition", err)
			}
			for _, w := range tc.wants {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("refusal %q does not name %q", err.Error(), w)
				}
			}
		})
	}
}

// A recorded path or a domain's disk that cannot be a file (a component of
// it is a file, or its symlinks loop) is not the file the other names: a
// non-match, not an identification error (dupcreate verify 5, n-3).
//
// Mutation: count only ENOENT as a non-match — red.
func TestDomainRunsOnAny_NotADirectoryOrALoopIsANonMatch(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "b"), filepath.Join(dir, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "a"), filepath.Join(dir, "b")); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(dir, "disk.qcow2")
	if err := os.WriteFile(disk, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dom := func(src string) string {
		return "<domain><devices><disk type='file' device='disk'><source file='" + src + "'/></disk></devices></domain>"
	}
	for _, tc := range []struct{ name, src, recorded string }{
		{"recorded path not a directory", disk, filepath.Join(file, "x.qcow2")},
		{"recorded path loops", disk, filepath.Join(dir, "a")},
		{"domain's disk not a directory", filepath.Join(file, "x.qcow2"), disk},
		{"domain's disk loops", filepath.Join(dir, "a"), disk},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := domainRunsOnAny(dom(tc.src), []string{tc.recorded})
			if got || err != nil {
				t.Errorf("domainRunsOnAny = %v, %v; want a non-match", got, err)
			}
		})
	}
}
