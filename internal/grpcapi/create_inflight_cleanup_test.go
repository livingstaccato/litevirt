package grpcapi

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/storage"
)

// foreignTwinOnDefine makes the create's define fail because a domain of the
// name appeared first: one with the same disks as the create's own
// definition, under another uuid, so it names every disk the create made in
// whatever source form the create gave it (a file, a block device, an rbd
// image). then runs once that domain is defined.
func foreignTwinOnDefine(t *testing.T, fake *libvirtfake.Fake, then func()) {
	t.Helper()
	fake.FailDefineDomain = func(x string) error {
		fake.FailDefineDomain = nil
		u := domainUUIDFromXML(x)
		if u == "" {
			t.Fatalf("the create's definition names no uuid:\n%s", x)
		}
		if err := fake.DefineDomain(strings.Replace(x, "<uuid>"+u+"</uuid>", "<uuid>11111111-2222-3333-4444-ababababab01</uuid>", 1)); err != nil {
			t.Fatal(err)
		}
		if then != nil {
			then()
		}
		return errors.New("operation failed: domain already exists")
	}
}

// A failed create leaves every disk a domain of the name it did not define
// names, in every source form a create makes: an rbd image and a zvol
// (a block device) are that domain's too, and their drivers delete nothing.
//
// Mutation: read the foreign domain's sources through DomainDiskSources
// alone (file sources only) — the rbd image and the zvol go, red.
func TestCreateVM_AFailedCreateLeavesAnRBDOrBlockDiskAnotherDomainNames(t *testing.T) {
	t.Run("rbd", func(t *testing.T) {
		f := newCephPoolFixture(t)
		foreignTwinOnDefine(t, f.fake, nil)
		if _, err := f.s.CreateVM(adminCtx(), cephCreateRequest("cephm", &pb.DiskSpec{Name: "data", Size: "1G", Storage: "ceph"})); err == nil {
			t.Fatal("the create was meant to fail at its define")
		}
		if !f.world.has("lv/cephm-data") {
			t.Errorf("the failed create removed the rbd image another domain of the name names (calls %v)", f.world.calls)
		}
	})
	t.Run("zvol", func(t *testing.T) {
		s, fake := provableCreateServer(t)
		var calls []string
		t.Cleanup(storage.OverrideVolumeRunnerForTest(func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			return nil, nil
		}))
		s.addStoragePoolRef("tank", StoragePoolRef{Driver: "zfs", Source: "tank/lv"})
		foreignTwinOnDefine(t, fake, nil)
		if _, err := s.CreateVM(adminCtx(), cephCreateRequest("z1", &pb.DiskSpec{Name: "data", Size: "1G", Storage: "tank"})); err == nil {
			t.Fatal("the create was meant to fail at its define")
		}
		if strings.Contains(strings.Join(calls, "\n"), "destroy") {
			t.Errorf("the failed create destroyed the zvol another domain of the name names (calls %v)", calls)
		}
	})
}

// What a domain of the name names cannot be read: its disk sources, or its
// definition. A failed create then leaves its disks — any of them may be that
// domain's — and removes them as before once nothing of the name is there.
//
// Mutations: read failed sources as none — "sources unreadable" red; take an
// unreadable definition for no domain — "definition unreadable" red.
func TestCreateVM_AFailedCreateLeavesItsDisksWhenTheOtherDomainCannotBeRead(t *testing.T) {
	broken := errors.New("libvirt connection lost")
	for _, tc := range []struct {
		name    string
		breakIt func(*libvirtfake.Fake)
	}{
		{"sources unreadable", func(fake *libvirtfake.Fake) {
			fake.FailDomainDiskSources = func(string) error { return broken }
		}},
		{"definition unreadable", func(fake *libvirtfake.Fake) {
			fake.FailDumpXMLInactive = func(string) error { return broken }
			fake.FailDumpXML = func(string) error { return broken }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stageGenisoimage(t)
			s, fake, _ := isoServer(t)
			const name = "ugr"
			disk := s.images.DiskPath(name, "root")
			fake.FailDefineDomain = func(string) error {
				fake.FailDefineDomain = nil
				// The other domain names no disk the definition shows.
				if err := fake.DefineDomain("<domain type='kvm'><name>" + name + "</name>" +
					"<uuid>11111111-2222-3333-4444-ababababab02</uuid></domain>"); err != nil {
					t.Fatal(err)
				}
				tc.breakIt(fake)
				return errors.New("operation failed: domain already exists")
			}
			if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, "")); err == nil {
				t.Fatal("the create was meant to fail at its define")
			}
			if _, err := os.Stat(disk); err != nil {
				t.Errorf("the failed create removed its disk while what the other domain names could not be read: %v", err)
			}
		})
	}
}

// The protection reads what is there: a domain that names other disks, or
// no domain at all, leaves the failed create's disks to be removed.
func TestForeignDomainDiskPaths_OnlyWhatTheDomainNames(t *testing.T) {
	s, fake := promoteFixture(t)
	if s.foreignDomainDiskPaths("vm9", "self")("/d/vm9-root.qcow2") {
		t.Error("no domain of the name, and a path is protected")
	}
	if err := fake.DefineDomain("<domain type='kvm'><name>vm9</name><uuid>11111111-2222-3333-4444-ababababab03</uuid><devices>" +
		"<disk type='file' device='disk'><source file='/d/other.qcow2'/></disk>" +
		"<disk type='block' device='disk'><source dev='/dev/zvol/tank/other'/></disk>" +
		"<disk type='network' device='disk'><source protocol='rbd' name='lv/other'/></disk>" +
		"</devices></domain>"); err != nil {
		t.Fatal(err)
	}
	fake.SetDiskSource("vm9", "vda", "/d/other.qcow2")
	foreign := s.foreignDomainDiskPaths("vm9", "self")
	for p, want := range map[string]bool{
		"/d/vm9-root.qcow2":       false,
		"/d/other.qcow2":          true,
		"/dev/zvol/tank/other":    true,
		"/dev/zvol/tank/vm9-data": false,
		"rbd:lv/other:id=x":       true,
		"rbd:lv/vm9-data:id=x":    false,
	} {
		if got := foreign(p); got != want {
			t.Errorf("foreign(%s) = %v, want %v", p, got, want)
		}
	}
	if s.foreignDomainDiskPaths("vm9", "11111111-2222-3333-4444-ababababab03")("/d/other.qcow2") {
		t.Error("the create's own domain protects its disks from its own cleanup")
	}
}
