package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/storage"
)

// rbdDomain is a domain whose one disk is the Ceph image name on the
// monitors hosts ("" for a source that names none).
func rbdDomain(uuid, name string, hosts ...string) string {
	var h strings.Builder
	for _, m := range hosts {
		host, port, _ := strings.Cut(m, ":")
		if port != "" {
			fmt.Fprintf(&h, "<host name='%s' port='%s'/>", host, port)
		} else {
			fmt.Fprintf(&h, "<host name='%s'/>", host)
		}
	}
	return fmt.Sprintf("<domain type='kvm'><name>vm1</name><uuid>%s</uuid><devices><disk type='network' device='disk'>"+
		"<source protocol='rbd' name='%s'>%s</source></disk></devices></domain>", uuid, name, h.String())
}

// withDefaultCephConf points ceph's default ceph.conf at one naming mon
// ("" for no ceph.conf at all).
func withDefaultCephConf(t *testing.T, mon string) {
	t.Helper()
	dir := t.TempDir()
	if mon != "" {
		if err := os.WriteFile(filepath.Join(dir, "ceph.conf"), []byte("[global]\nmon_host = "+mon+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(storage.OverrideCephConfDirForTest(dir))
}

// A Ceph RBD disk is the recorded one only on the same Ceph cluster: an
// image of the same pool/image on another cluster is another disk. The
// cluster is known by its monitors — the domain's <host> elements, or the
// default ceph.conf's when it names none, against the locator's mon_host,
// its conf's, or the default conf's — and one neither side names a
// monitor for is the default conf's on both.
//
// Mutation: match on pool/image alone — "another cluster" and "default
// against another" red.
func TestDomainRunsOnAny_RBDNeedsTheSameCephCluster(t *testing.T) {
	const pinned = `rbd:lv/vm1-root:id=litevirt:keyring=/k:mon_host=10.0.0.1\:6789`
	for _, tc := range []struct {
		name     string
		hosts    []string
		recorded string
		defConf  string
		want     bool
	}{
		{"same cluster", []string{"10.0.0.1:6789"}, pinned, "", true},
		{"same monitor on its v2 port", []string{"10.0.0.1:3300"}, pinned, "", true},
		{"one shared monitor of several", []string{"10.0.0.7:6789", "10.0.0.1:6789"}, pinned, "", true},
		{"another cluster", []string{"10.0.9.1:6789"}, pinned, "", false},
		{"default against another", nil, pinned, "10.0.9.1:6789", false},
		{"default against the same", nil, pinned, "10.0.0.1:6789", true},
		{"default, unreadable", nil, pinned, "", false},
		{"neither names a monitor", nil, "rbd:lv/vm1-root", "", true},
		{"locator default against another", []string{"10.0.9.1:6789"}, "rbd:lv/vm1-root", "10.0.0.1:6789", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withDefaultCephConf(t, tc.defConf)
			got, err := domainRunsOnAny(rbdDomain("u", "lv/vm1-root", tc.hosts...), []string{tc.recorded})
			if err != nil || got != tc.want {
				t.Errorf("domainRunsOnAny = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

// A rebuild never stops or undefines a domain of the name that runs on an
// image of the VM's pool/image on ANOTHER Ceph cluster: it is not the VM's
// runtime. One on the VM's own cluster (a legacy domain under a uuid
// libvirt chose) still is.
//
// Mutation: match RBD by pool/image alone — the foreign guest is destroyed
// and undefined, red.
func TestRebuildVM_NeverDestroysAnRBDDomainOnAnotherCephCluster(t *testing.T) {
	const recorded = `rbd:lv/vm1-root:id=litevirt:keyring=/k:mon_host=10.0.0.1\:6789`
	const foreign = "eeeeeeee-0000-0000-0000-000000000041"
	withDefaultCephConf(t, "")
	// No real rbd runs: a rebuild that got as far as deleting the disks
	// would reach a Ceph cluster from the test host.
	var ran []string
	t.Cleanup(storage.OverrideCephRunnerForTest(func(_ context.Context, name string, args ...string) ([]byte, error) {
		ran = append(ran, name+" "+strings.Join(args, " "))
		return nil, errors.New("no ceph in this test")
	}))
	t.Run("another cluster", func(t *testing.T) {
		s, fake := promoteFixture(t)
		if err := s.db.Execute(adminCtx(), `UPDATE vm_disks SET path = ?, storage_type = 'ceph' WHERE vm_name = 'vm1'`, recorded); err != nil {
			t.Fatal(err)
		}
		if err := fake.DefineDomain(rbdDomain(foreign, "lv/vm1-root", "10.0.9.1:6789")); err != nil {
			t.Fatal(err)
		}
		if err := fake.StartDomain("vm1"); err != nil {
			t.Fatal(err)
		}
		// This fixture has no image store: a rebuild past the identity
		// check panics in its debris sweep, after the destroy.
		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("the rebuild went past the identity check: %v", r)
				}
			}()
			_, err = s.RebuildVM(adminCtx(), &pb.RebuildVMRequest{Name: "vm1"})
			return err
		}()
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(fmt.Sprint(err), foreign) {
			t.Errorf("rebuild over a domain on another Ceph cluster: %v, want FailedPrecondition naming it", err)
		}
		if u, d := undefinesOf(fake, "vm1"); u != 0 || d != 0 {
			t.Errorf("the foreign guest was undefined %d and destroyed %d times", u, d)
		}
		if len(ran) != 0 {
			t.Errorf("the rebuild ran ceph commands on the VM's image: %q", ran)
		}
		if active, _ := fake.DomainIsActive("vm1"); !active {
			t.Error("the foreign guest no longer runs")
		}
	})
	t.Run("the same cluster", func(t *testing.T) {
		s, fake := promoteFixture(t)
		if err := s.db.Execute(adminCtx(), `UPDATE vm_disks SET path = ?, storage_type = 'ceph' WHERE vm_name = 'vm1'`, recorded); err != nil {
			t.Fatal(err)
		}
		if err := fake.DefineDomain(rbdDomain(foreign, "lv/vm1-root", "10.0.0.1:6789")); err != nil {
			t.Fatal(err)
		}
		own, _, why, err := s.domainIsVMsOwn(adminCtx(), "vm1", "aaaaaaaa-0000-0000-0000-000000000001", "vm1")
		if err != nil || !own {
			t.Errorf("domainIsVMsOwn = %v, %q, %v; want the VM's own", own, why, err)
		}
	})
}

// The edges of the monitor rule: a domain that takes its cluster from a
// <config file> of its own (and names no <host>) is on a cluster this host
// cannot tell, never the default ceph.conf's; a monitor named with no port is
// on a default port (6789 or 3300), not on any port.
//
// Mutations: read a <config file> domain as the default conf's — "own conf
// file" red; let a port-less monitor match any port — "port-less against
// another port" red.
func TestDomainRunsOnAny_RBDIdentityEdges(t *testing.T) {
	withConf := func(conf string, hosts ...string) string {
		x := rbdDomain("u", "lv/vm1-root", hosts...)
		return strings.Replace(x, "</source>", "<config file='"+conf+"'/></source>", 1)
	}
	for _, tc := range []struct {
		name     string
		xml      string
		recorded string
		defConf  string
		want     bool
	}{
		{"own conf file", withConf("/etc/ceph/b.conf"), "rbd:lv/vm1-root", "10.0.0.1:6789", false},
		{"own conf file, pinned locator", withConf("/etc/ceph/b.conf"), `rbd:lv/vm1-root:mon_host=10.0.0.1\:6789`, "10.0.0.1:6789", false},
		{"own conf file and a shared monitor", withConf("/etc/ceph/b.conf", "10.0.0.1:6789"), `rbd:lv/vm1-root:mon_host=10.0.0.1\:6789`, "", true},
		{"port-less against another port", rbdDomain("u", "lv/vm1-root", "10.0.0.1"), `rbd:lv/vm1-root:mon_host=10.0.0.1\:6790`, "", false},
		{"port-less against the default port", rbdDomain("u", "lv/vm1-root", "10.0.0.1"), `rbd:lv/vm1-root:mon_host=10.0.0.1\:6789`, "", true},
		{"port-less against the v2 port", rbdDomain("u", "lv/vm1-root", "10.0.0.1"), `rbd:lv/vm1-root:mon_host=10.0.0.1\:3300`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withDefaultCephConf(t, tc.defConf)
			got, err := domainRunsOnAny(tc.xml, []string{tc.recorded})
			if err != nil || got != tc.want {
				t.Errorf("domainRunsOnAny = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

// A locator that names its litevirt pool is on the monitors that pool has on
// this host now, as a domain defined now is given them: after a rolling
// monitor replacement the domain, still on an old monitor and a kept one, is
// on the same cluster; one on retired monitors only is not.
//
// Mutation: ignore the pool's current monitors — "kept monitor" red.
func TestDomainRunsOnAny_RBDUsesThePoolsCurrentMonitors(t *testing.T) {
	withDefaultCephConf(t, "")
	t.Cleanup(lv.SetCephMonitorResolver(func(pool string) ([]string, bool) {
		if pool != "ceph1" {
			return nil, false
		}
		return []string{"10.0.0.2:6789", "10.0.0.3:6789"}, true
	}))
	const recorded = "rbd:lv/vm1-root:id=litevirt:keyring=/k:lvpool=ceph1"
	for _, tc := range []struct {
		name  string
		hosts []string
		want  bool
	}{
		{"kept monitor", []string{"10.0.0.1:6789", "10.0.0.2:6789"}, true},
		{"retired monitors only", []string{"10.0.0.1:6789"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := domainRunsOnAny(rbdDomain("u", "lv/vm1-root", tc.hosts...), []string{recorded})
			if err != nil || got != tc.want {
				t.Errorf("domainRunsOnAny = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

// A rebuild refused because the domain's rbd image is the VM's pool/image on
// a cluster that is not the VM's says so, naming the monitors, and the way
// out.
//
// Mutation: the generic "none of its disks" reason — red.
func TestDomainIsVMsOwn_NamesTheCephClusterMismatch(t *testing.T) {
	withDefaultCephConf(t, "")
	s, fake := promoteFixture(t)
	if err := s.db.Execute(adminCtx(), `UPDATE vm_disks SET path = ?, storage_type = 'ceph' WHERE vm_name = 'vm1'`,
		`rbd:lv/vm1-root:mon_host=10.0.0.1\:6789`); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(rbdDomain("eeeeeeee-0000-0000-0000-000000000042", "lv/vm1-root", "10.0.9.1:6789")); err != nil {
		t.Fatal(err)
	}
	own, _, why, err := s.domainIsVMsOwn(adminCtx(), "vm1", "aaaaaaaa-0000-0000-0000-000000000001", "vm1")
	if err != nil || own {
		t.Fatalf("domainIsVMsOwn = %v, %v; want not the VM's", own, err)
	}
	for _, want := range []string{"lv/vm1-root", "Ceph cluster", "10.0.9.1:6789"} {
		if !strings.Contains(why, want) {
			t.Errorf("why %q does not name %q", why, want)
		}
	}
}

// The VM's cluster is the ONE monitor source its domain is given
// (rbdDomainSource): the litevirt pool's current monitors, else the
// locator's mon_host, else its conf's. A source that order passes over names
// no cluster of the VM's, so a domain on it is not the VM's: a locator on A
// whose conf names B, or a pool now on A whose locator still names B, is not
// on B.
//
// Mutation: add the passed-over sources to the accepted monitors (the
// union) — both "on B" cases red.
func TestDomainRunsOnAny_RBDOnlyTheRenderedMonitorSource(t *testing.T) {
	withDefaultCephConf(t, "")
	bConf := filepath.Join(t.TempDir(), "b.conf")
	if err := os.WriteFile(bConf, []byte("[global]\nmon_host = 10.0.9.1:6789\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lv.SetCephMonitorResolver(func(pool string) ([]string, bool) {
		if pool != "ceph1" {
			return nil, false
		}
		return []string{"10.0.0.1:6789"}, true
	}))
	monAConfB := `rbd:lv/vm1-root:mon_host=10.0.0.1\:6789:conf=` + bConf
	poolAMonB := `rbd:lv/vm1-root:id=litevirt:keyring=/k:lvpool=ceph1:mon_host=10.0.9.1\:6789`
	for _, tc := range []struct {
		name     string
		hosts    []string
		recorded string
		want     bool
	}{
		{"mon_host A, conf B: on B", []string{"10.0.9.1:6789"}, monAConfB, false},
		{"mon_host A, conf B: on A", []string{"10.0.0.1:6789"}, monAConfB, true},
		{"pool A, mon_host B: on B", []string{"10.0.9.1:6789"}, poolAMonB, false},
		{"pool A, mon_host B: on A", []string{"10.0.0.1:6789"}, poolAMonB, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := domainRunsOnAny(rbdDomain("u", "lv/vm1-root", tc.hosts...), []string{tc.recorded})
			if err != nil || got != tc.want {
				t.Errorf("domainRunsOnAny = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

// A locator whose monitors cannot be known as its domain would be given them
// — a conf that cannot be read, or names no monitor, with no pool and no
// mon_host to stand before it, or an option the renderer refuses (ceph reads
// "mon-host" and "mon host" as mon_host) — is on no cluster this host can
// tell, so no domain is on it, not even one on the default ceph.conf's
// monitors (here, also the option's).
//
// Mutations: read such a locator as the default ceph.conf's — red; ignore
// options the renderer refuses — both "mon-host"/"mon host" cases red.
func TestDomainRunsOnAny_RBDUnknowableLocatorIsNoCluster(t *testing.T) {
	withDefaultCephConf(t, "10.0.0.1:6789")
	empty := filepath.Join(t.TempDir(), "empty.conf")
	if err := os.WriteFile(empty, []byte("[global]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, recorded string
		hosts          []string
	}{
		{"unreadable conf", "rbd:lv/vm1-root:conf=/nonexistent/b.conf", []string{"10.0.0.1:6789"}},
		{"unreadable conf, no host", "rbd:lv/vm1-root:conf=/nonexistent/b.conf", nil},
		{"conf naming no monitor", "rbd:lv/vm1-root:conf=" + empty, []string{"10.0.0.1:6789"}},
		{"conf naming no monitor, no host", "rbd:lv/vm1-root:conf=" + empty, nil},
		{"mon-host, on its monitor", `rbd:lv/vm1-root:mon-host=10.0.0.1\:6789`, []string{"10.0.0.1:6789"}},
		{"mon host, on its monitor", `rbd:lv/vm1-root:mon host=10.0.0.1\:6789`, []string{"10.0.0.1:6789"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := domainRunsOnAny(rbdDomain("u", "lv/vm1-root", tc.hosts...), []string{tc.recorded})
			if err != nil || got {
				t.Errorf("domainRunsOnAny = %v, %v; want false", got, err)
			}
		})
	}
}

// A rebuild never stops or undefines a domain on cluster B because a source
// the VM's own domain is NOT given names B: the locator's conf behind its
// mon_host, or its mon_host behind its pool's current monitors.
//
// Mutation: the union of sources — the foreign guest is destroyed and
// undefined, red.
func TestRebuildVM_NeverDestroysAnRBDDomainOnAPassedOverSource(t *testing.T) {
	const foreign = "eeeeeeee-0000-0000-0000-000000000043"
	withDefaultCephConf(t, "")
	bConf := filepath.Join(t.TempDir(), "b.conf")
	if err := os.WriteFile(bConf, []byte("[global]\nmon_host = 10.0.9.1:6789\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lv.SetCephMonitorResolver(func(pool string) ([]string, bool) {
		if pool != "ceph1" {
			return nil, false
		}
		return []string{"10.0.0.1:6789"}, true
	}))
	var ran []string
	t.Cleanup(storage.OverrideCephRunnerForTest(func(_ context.Context, name string, args ...string) ([]byte, error) {
		ran = append(ran, name+" "+strings.Join(args, " "))
		return nil, errors.New("no ceph in this test")
	}))
	for _, tc := range []struct{ name, recorded string }{
		{"mon_host A, conf B", `rbd:lv/vm1-root:id=litevirt:keyring=/k:mon_host=10.0.0.1\:6789:conf=` + bConf},
		{"pool A, mon_host B", `rbd:lv/vm1-root:id=litevirt:keyring=/k:lvpool=ceph1:mon_host=10.0.9.1\:6789`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ran = nil
			s, fake := promoteFixture(t)
			// ceph1 is on this host, on cluster A, as the resolver says.
			s.addStoragePoolRef("ceph1", StoragePoolRef{Driver: "ceph", Source: "lv",
				Options: map[string]string{"id": "litevirt", "keyring": "/k", "mon_host": "10.0.0.1:6789"}})
			if err := s.db.Execute(adminCtx(), `UPDATE vm_disks SET path = ?, storage_type = 'ceph' WHERE vm_name = 'vm1'`, tc.recorded); err != nil {
				t.Fatal(err)
			}
			if err := fake.DefineDomain(rbdDomain(foreign, "lv/vm1-root", "10.0.9.1:6789")); err != nil {
				t.Fatal(err)
			}
			if err := fake.StartDomain("vm1"); err != nil {
				t.Fatal(err)
			}
			err := func() (err error) {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("the rebuild went past the identity check: %v", r)
					}
				}()
				_, err = s.RebuildVM(adminCtx(), &pb.RebuildVMRequest{Name: "vm1"})
				return err
			}()
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(fmt.Sprint(err), foreign) {
				t.Errorf("rebuild over a domain on cluster B: %v, want FailedPrecondition naming it", err)
			}
			if u, d := undefinesOf(fake, "vm1"); u != 0 || d != 0 {
				t.Errorf("the foreign guest was undefined %d and destroyed %d times", u, d)
			}
			if len(ran) != 0 {
				t.Errorf("the rebuild ran ceph commands on the VM's image: %q", ran)
			}
			if active, _ := fake.DomainIsActive("vm1"); !active {
				t.Error("the foreign guest no longer runs")
			}
			if !fake.DomainExists("vm1") {
				t.Error("the foreign guest is no longer defined")
			}
		})
	}
	t.Run("the rendered source's cluster is still the VM's", func(t *testing.T) {
		s, fake := promoteFixture(t)
		if err := s.db.Execute(adminCtx(), `UPDATE vm_disks SET path = ?, storage_type = 'ceph' WHERE vm_name = 'vm1'`,
			`rbd:lv/vm1-root:id=litevirt:keyring=/k:mon_host=10.0.0.1\:6789:conf=`+bConf); err != nil {
			t.Fatal(err)
		}
		if err := fake.DefineDomain(rbdDomain(foreign, "lv/vm1-root", "10.0.0.1:6789")); err != nil {
			t.Fatal(err)
		}
		own, _, why, err := s.domainIsVMsOwn(adminCtx(), "vm1", "aaaaaaaa-0000-0000-0000-000000000001", "vm1")
		if err != nil || !own {
			t.Errorf("domainIsVMsOwn = %v, %q, %v; want the VM's own", own, why, err)
		}
	})
}

// Right after a restart this host's pool list may not hold a pool its table
// has. The pool's current monitors are still the cluster a domain defined now
// is given — read from the table — never the monitors the locator recorded:
// a domain on those (cluster B) is not the VM's runtime, and one on the
// pool's (cluster A) is.
//
// Mutation: read the pool from the loaded list only, in both
// CephMonitorsForPool and domainIsVMsOwn's pool check — "on B" is taken for
// the VM's, and "on A" is not, red. (Either table read alone keeps it green:
// the pool check loads the list for CephMonitorsForPool.)
func TestDomainIsVMsOwn_RBDPoolInTheTableNotYetLoaded(t *testing.T) {
	withDefaultCephConf(t, "")
	for _, tc := range []struct {
		name string
		mon  string
		want bool
	}{
		{"on B, the locator's recorded monitor", "10.0.9.1:6789", false},
		{"on A, the pool's monitor", "10.0.0.1:6789", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fake := promoteFixture(t)
			if err := corrosion.UpsertStoragePool(adminCtx(), s.db, corrosion.StoragePoolRecord{
				HostName: s.hostName, Name: "ceph1", Driver: "ceph", Source: "lv", State: "active",
				Options: map[string]string{"id": "litevirt", "keyring": "/k", "mon_host": "10.0.0.1:6789"},
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.db.Execute(adminCtx(), `UPDATE vm_disks SET path = ?, storage_type = 'ceph' WHERE vm_name = 'vm1'`,
				`rbd:lv/vm1-root:id=litevirt:keyring=/k:lvpool=ceph1:mon_host=10.0.9.1\:6789`); err != nil {
				t.Fatal(err)
			}
			if err := fake.DefineDomain(rbdDomain("eeeeeeee-0000-0000-0000-000000000044", "lv/vm1-root", tc.mon)); err != nil {
				t.Fatal(err)
			}
			own, _, why, err := s.domainIsVMsOwn(adminCtx(), "vm1", "aaaaaaaa-0000-0000-0000-000000000001", "vm1")
			if err != nil || own != tc.want {
				t.Errorf("domainIsVMsOwn = %v, %q, %v; want %v", own, why, err, tc.want)
			}
		})
	}
}

// A pool of the locator's name that this host has but cannot give monitors
// for (not a ceph pool, or its conf cannot be read) makes the cluster
// unknown: no domain is the VM's by that disk, not even one on the monitors
// the locator recorded.
//
// Mutation: fall back to the locator's mon_host when the pool gives no
// monitors (the renderer's order alone) — both cases red.
func TestDomainIsVMsOwn_RBDPoolWithoutMonitorsIsUnknown(t *testing.T) {
	withDefaultCephConf(t, "")
	for _, tc := range []struct {
		name string
		ref  StoragePoolRef
	}{
		{"not a ceph pool", StoragePoolRef{Driver: "dir", Target: "/var/lib/x"}},
		{"conf unreadable", StoragePoolRef{Driver: "ceph", Source: "lv", Options: map[string]string{"conf": "/nonexistent/c.conf"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fake := promoteFixture(t)
			s.addStoragePoolRef("ceph1", tc.ref)
			if err := s.db.Execute(adminCtx(), `UPDATE vm_disks SET path = ?, storage_type = 'ceph' WHERE vm_name = 'vm1'`,
				`rbd:lv/vm1-root:id=litevirt:keyring=/k:lvpool=ceph1:mon_host=10.0.9.1\:6789`); err != nil {
				t.Fatal(err)
			}
			if err := fake.DefineDomain(rbdDomain("eeeeeeee-0000-0000-0000-000000000045", "lv/vm1-root", "10.0.9.1:6789")); err != nil {
				t.Fatal(err)
			}
			own, _, why, err := s.domainIsVMsOwn(adminCtx(), "vm1", "aaaaaaaa-0000-0000-0000-000000000001", "vm1")
			if err != nil || own {
				t.Errorf("domainIsVMsOwn = %v, %q, %v; want not the VM's", own, why, err)
			}
			if !strings.Contains(why, "ceph1") {
				t.Errorf("why %q does not name the pool", why)
			}
		})
	}
}

// The renderer's monitors for a litevirt pool (CephMonitorsForPool, the
// daemon's lv.SetCephMonitorResolver) are the pool's from this host's table
// when the pool list has not loaded it yet, as a domain defined right after
// a restart must be given them.
//
// Mutation: the loaded list only — no monitors, and the renderer falls back
// to the locator's recorded mon_host, red.
func TestCephMonitorsForPool_ReadsAPoolNotYetLoaded(t *testing.T) {
	s := testServerWithLocks(t)
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: "test-host", Name: "ceph1", Driver: "ceph", Source: "lv", State: "active",
		Options: map[string]string{"mon_host": "10.0.0.1:6789"},
	}); err != nil {
		t.Fatal(err)
	}
	mons, ok := s.CephMonitorsForPool("ceph1")
	if !ok || len(mons) != 1 || mons[0] != "10.0.0.1:6789" {
		t.Errorf("CephMonitorsForPool = %v, %v; want [10.0.0.1:6789]", mons, ok)
	}
}
