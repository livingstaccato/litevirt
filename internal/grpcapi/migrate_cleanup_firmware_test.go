package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

const (
	cleanupUUIDA = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
	cleanupUUIDB = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
)

// fwCleanupFixture redirects the swtpm base into a temp dir and seeds the
// firmware state of two VMs: A (being cleaned up) and B (a bystander). It
// returns the swtpm base. A's row names hostA; B lives on src-host.
func fwCleanupFixture(t *testing.T, s *Server, hostA string) string {
	t.Helper()
	s.dataDir = t.TempDir()
	base := filepath.Join(t.TempDir(), "libvirt", "swtpm")
	t.Cleanup(lv.SetSwtpmBaseForTest(base))
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "vma", hostA, "stopped",
		`{"name":"vma","tpm":true,"firmware":"uefi","uuid":"`+cleanupUUIDA+`"}`)
	insertTestVMWithSpec(t, ctx, s.db, "vmb", "src-host", "running",
		`{"name":"vmb","tpm":true,"firmware":"uefi","uuid":"`+cleanupUUIDB+`"}`)
	for _, u := range []string{cleanupUUIDA, cleanupUUIDB} {
		d := filepath.Join(lv.LibvirtSwtpmDir(u), "tpm2")
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "tpm2-00.permall"), []byte(u), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, vm := range []string{"vma", "vmb"} {
		p := lv.NvramPath(s.dataDir, vm)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("vars"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return base
}

func assertExists(t *testing.T, p, what string) {
	t.Helper()
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("%s (%s) was removed: %v", what, p, err)
	}
}

func assertGone(t *testing.T, p, what string) {
	t.Helper()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("%s (%s) should have been wiped (err=%v)", what, p, err)
	}
}

// A malformed FirmwareUuid must never reach a RemoveAll: ".." alone used to
// wipe the whole of /var/lib/libvirt.
func TestCleanupMigrationArtifacts_FirmwareUUIDTraversalRefused(t *testing.T) {
	for _, bad := range []string{"..", "../x", "/", "/etc", ".", "../../etc", cleanupUUIDA + "/.."} {
		t.Run(bad, func(t *testing.T) {
			s := testServer(t)
			base := fwCleanupFixture(t, s, "src-host")
			libvirtDir := filepath.Dir(base)
			sibling := filepath.Join(libvirtDir, "x")
			if err := os.MkdirAll(sibling, 0o755); err != nil {
				t.Fatal(err)
			}
			_, err := s.CleanupMigrationArtifacts(adminCtx(), &pb.CleanupMigrationArtifactsRequest{
				VmName: "vma", FirmwareUuid: bad,
			})
			if status.Code(err) != codes.InvalidArgument {
				t.Errorf("FirmwareUuid %q: got %v, want InvalidArgument", bad, err)
			}
			assertExists(t, libvirtDir, "the swtpm base's parent")
			assertExists(t, sibling, "a sibling of the swtpm base")
			assertExists(t, base, "the swtpm base")
			assertExists(t, lv.LibvirtSwtpmDir(cleanupUUIDA), "A's swtpm state")
			assertExists(t, lv.LibvirtSwtpmDir(cleanupUUIDB), "B's swtpm state")
			assertExists(t, lv.NvramPath(s.dataDir, "vma"), "A's NVRAM")
		})
	}
}

// vm.migrate on A must not reach B's TPM: the UUID has to be A's own.
func TestCleanupMigrationArtifacts_OtherVMsFirmwareUUIDRefused(t *testing.T) {
	s := testServer(t)
	fwCleanupFixture(t, s, "src-host")
	_, err := s.CleanupMigrationArtifacts(adminCtx(), &pb.CleanupMigrationArtifactsRequest{
		VmName: "vma", FirmwareUuid: cleanupUUIDB,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("got %v, want InvalidArgument for a UUID that is not vma's", err)
	}
	assertExists(t, lv.LibvirtSwtpmDir(cleanupUUIDB), "B's swtpm state")
	assertExists(t, lv.LibvirtSwtpmDir(cleanupUUIDA), "A's swtpm state")
	assertExists(t, lv.NvramPath(s.dataDir, "vma"), "A's NVRAM")
}

// The legitimate case: a failed migration TO this host left A's firmware here,
// A still belongs to the source, and no domain is defined. That still wipes.
func TestCleanupMigrationArtifacts_OwnFirmwareUUIDWipes(t *testing.T) {
	s := testServer(t)
	s.virt = libvirtfake.New()
	fwCleanupFixture(t, s, "src-host")
	if _, err := s.CleanupMigrationArtifacts(adminCtx(), &pb.CleanupMigrationArtifactsRequest{
		VmName: "vma", FirmwareUuid: cleanupUUIDA, UndefineDomain: true,
	}); err != nil {
		t.Fatalf("CleanupMigrationArtifacts: %v", err)
	}
	assertGone(t, lv.LibvirtSwtpmDir(cleanupUUIDA), "A's swtpm state")
	assertGone(t, lv.NvramPath(s.dataDir, "vma"), "A's NVRAM")
	assertExists(t, lv.LibvirtSwtpmDir(cleanupUUIDB), "B's swtpm state")
}

// The same after this host pre-defined A's domain for the failed migration:
// UndefineDomain removes it first, then the wipe runs.
func TestCleanupMigrationArtifacts_OwnFirmwareUUIDWipesAfterUndefine(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	fwCleanupFixture(t, s, "src-host")
	if err := fake.DefineDomain(`<domain type='kvm'><name>vma</name><uuid>` + cleanupUUIDA + `</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CleanupMigrationArtifacts(adminCtx(), &pb.CleanupMigrationArtifactsRequest{
		VmName: "vma", FirmwareUuid: cleanupUUIDA, UndefineDomain: true,
	}); err != nil {
		t.Fatalf("CleanupMigrationArtifacts: %v", err)
	}
	if fake.DomainExists("vma") {
		t.Fatal("pre-defined domain should have been undefined")
	}
	assertGone(t, lv.LibvirtSwtpmDir(cleanupUUIDA), "A's swtpm state")
}

// A VM that lives here keeps its firmware: its row names this host.
func TestCleanupMigrationArtifacts_LiveVMFirmwareKept_RowHere(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	fwCleanupFixture(t, s, s.hostName)
	if err := fake.DefineDomain(`<domain type='kvm'><name>vma</name><uuid>` + cleanupUUIDA + `</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CleanupMigrationArtifacts(adminCtx(), &pb.CleanupMigrationArtifactsRequest{
		VmName: "vma", FirmwareUuid: cleanupUUIDA, UndefineDomain: true,
	}); err != nil {
		t.Fatalf("CleanupMigrationArtifacts: %v", err)
	}
	if !fake.DomainExists("vma") {
		t.Fatal("the domain of a VM that lives here was undefined")
	}
	assertExists(t, lv.LibvirtSwtpmDir(cleanupUUIDA), "A's swtpm state")
	assertExists(t, lv.NvramPath(s.dataDir, "vma"), "A's NVRAM")
}

// ...or its domain is defined here and the caller did not ask to undefine it.
func TestCleanupMigrationArtifacts_LiveVMFirmwareKept_DomainDefined(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	fwCleanupFixture(t, s, "src-host")
	if err := fake.DefineDomain(`<domain type='kvm'><name>vma</name><uuid>` + cleanupUUIDA + `</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CleanupMigrationArtifacts(adminCtx(), &pb.CleanupMigrationArtifactsRequest{
		VmName: "vma", FirmwareUuid: cleanupUUIDA,
	}); err != nil {
		t.Fatalf("CleanupMigrationArtifacts: %v", err)
	}
	assertExists(t, lv.LibvirtSwtpmDir(cleanupUUIDA), "A's swtpm state")
	assertExists(t, lv.NvramPath(s.dataDir, "vma"), "A's NVRAM")
}

// EnsureFirmwareState keys the same swtpm tree by its request UUID: restoring
// into, or (on an XML-identity mismatch) wiping, another VM's TPM must be
// refused just the same.
func TestEnsureFirmwareState_OtherVMsUUIDRefused(t *testing.T) {
	s := testServer(t)
	s.virt = libvirtfake.New()
	fwCleanupFixture(t, s, "src-host")
	_, err := s.EnsureFirmwareState(diskPeerCtx(t, s), &pb.EnsureFirmwareStateRequest{
		VmName: "vma", Uuid: cleanupUUIDB, Bundle: nvramBundle(t, s.dataDir),
		DomainXml: `<domain type='kvm'><name>vma</name><uuid>` + cleanupUUIDA + `</uuid></domain>`,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("got %v, want InvalidArgument for a UUID that is not vma's", err)
	}
	assertExists(t, filepath.Join(lv.LibvirtSwtpmDir(cleanupUUIDB), "tpm2", "tpm2-00.permall"), "B's swtpm state")
}
