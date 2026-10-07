package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// C-1: on main an older cluster's default pool on <data_dir>/disks held its
// uploads directly in disks/, and the UI offered them as
// /var/lib/litevirt/disks/<name>.iso. A VM made on main with that path keeps
// starting, an Admin's create naming it works, and the pool's reference to it
// works for a VM of any project the global pool serves.
//
// Mutation: make storage.refuseSecretPath refuse disks/ files again — every
// leg goes red.
func TestISOFinal_AMainEraISOInDisksBoots(t *testing.T) {
	s, fake, _ := isoServer(t)
	_ = acmeOperator(t, s)
	disks := disksDefaultPool(t, s)
	iso := filepath.Join(disks, "win11.iso")
	writeLibFile(t, iso, opticalImage("win11"))

	legacyVM(t, s, fake, "old", iso)
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "old")); err != nil {
		t.Fatalf("start of a main-era VM whose ISO is in the default pool on disks/: %v", err)
	}
	if _, err := s.CreateVM(adminCtx(), isoCreate("adm", iso, "")); err != nil {
		t.Fatalf("admin create naming an ISO in disks/: %v", err)
	}
	if _, err := s.CreateVM(adminCtx(), isoCreate("ref", "default/win11.iso", "acme")); err != nil {
		t.Fatalf("create naming the default pool's ISO by reference: %v", err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "ref")); err != nil {
		t.Fatalf("start of a VM naming the default pool's ISO by reference: %v", err)
	}
}

// C-1, the other way: in disks/ beside every project's VM disks, a file a VM
// disk row names, or a replica record gives to a VM, is that VM's disk, even
// named .iso and carrying an ISO 9660 signature (a guest can write one into
// its raw disk); and a file in a directory another project's pool maps is not
// a non-admin's to name.
//
// Mutation: drop refuseVMDiskAsISO from checkISOFile — the disk and the
// replica go red.
func TestISOFinal_AVMDiskInDisksIsNotAnISO(t *testing.T) {
	s, fake, _ := isoServer(t)
	pat := acmeOperator(t, s)
	disks := disksDefaultPool(t, s)
	ctx := context.Background()

	disk := filepath.Join(disks, "bvm-data.iso")
	writeLibFile(t, disk, opticalImage("a guest wrote this"))
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "bvm", DiskName: "data", HostName: s.hostName, Path: disk, StorageType: "local",
	}); err != nil {
		t.Fatal(err)
	}
	replica := filepath.Join(disks, "bvm-root.iso")
	writeLibFile(t, replica, opticalImage("a replica"))
	if err := s.recordPoolReplica(ctx, "default", replicaKey{VM: "bvm", Disk: "root", Project: "other"}, replica); err != nil {
		t.Fatal(err)
	}
	for i, p := range []string{disk, replica} {
		name := "adm" + string(rune('a'+i))
		_, err := s.CreateVM(adminCtx(), isoCreate(name, p, ""))
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("admin create naming VM disk %s as an ISO: got %v, want InvalidArgument", p, err)
		}
		assertNoISODomain(t, s, fake, name, p)
		ref := "default/" + filepath.Base(p)
		name = "ref" + string(rune('a'+i))
		if _, err := s.CreateVM(adminCtx(), isoCreate(name, ref, "acme")); err == nil {
			t.Errorf("create naming VM disk %s by the default pool's reference was not refused", ref)
		}
	}
	legacyVM(t, s, fake, "leak", disk)
	if _, err := s.PrepareHardwareForStart(ctx, vmRecord(t, s, "leak")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start of a VM whose stored ISO is another VM's disk: got %v, want FailedPrecondition", err)
	}

	// Another project's pool maps disks/ too: an unrecorded file there is not
	// a non-admin's, by reference or by path.
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "pb", Driver: "local", Target: disks, Project: "other", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	theirs := filepath.Join(disks, "theirs.iso")
	writeLibFile(t, theirs, opticalImage("theirs"))
	for i, iso := range []string{"default/theirs.iso", theirs} {
		name := "op" + string(rune('a'+i))
		_, err := s.CreateVM(pat, isoCreate(name, iso, "acme"))
		if c := status.Code(err); c != codes.PermissionDenied && c != codes.FailedPrecondition {
			t.Errorf("non-admin create naming another project's file %s: got %v, want a refusal", iso, err)
		}
		assertNoISODomain(t, s, fake, name, theirs)
	}
}

// C-2: /root is root's home. An Admin's ISO there is judged like one under
// /home — an ISO image passes, ~root/.ssh does not — never refused as a
// secret directory, at create and on `lv iso pull --from-host-path`.
//
// Mutation: put /root back in storage.secretRoots — red.
func TestISOFinal_RootsHomeIsAUserDataRoot(t *testing.T) {
	s, _, _ := isoServer(t)
	_ = acmeOperator(t, s)
	_ = projectLibrary(t, s, "acme-isos", "acme")
	for _, call := range []func() error{
		func() error {
			_, err := s.CreateVM(adminCtx(), isoCreate("rootiso", "/root/debian-12.iso", ""))
			return err
		},
		func() error {
			_, err := s.PullISO(adminCtx(), &pb.PullISORequest{Ref: "acme-isos/debian-12.iso", HostPath: "/root/debian-12.iso"})
			return err
		},
	} {
		if err := call(); err != nil && strings.Contains(err.Error(), "holds host secrets") {
			t.Errorf("an ISO in root's home refused as a secret directory: %v", err)
		}
	}
	// The rule, on a stand-in for /root.
	root := filepath.Join(t.TempDir(), "root")
	t.Cleanup(storage.SetUserDataRootsForTest([]string{root}))
	for _, d := range []string{root, filepath.Join(root, ".ssh")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	deb := filepath.Join(root, "debian-12.iso")
	writeLibFile(t, deb, opticalImage("debian"))
	key := filepath.Join(root, ".ssh", "id_ed25519")
	writeLibFile(t, key, "-----BEGIN OPENSSH PRIVATE KEY-----\n")
	link := filepath.Join(root, "key.iso")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateVM(adminCtx(), isoCreate("deb", deb, "")); err != nil {
		t.Fatalf("admin create with an ISO in root's home: %v", err)
	}
	for i, p := range []string{key, link} {
		if _, err := s.CreateVM(adminCtx(), isoCreate("bad"+string(rune('a'+i)), p, "")); status.Code(err) != codes.InvalidArgument {
			t.Errorf("admin create with %s: got %v, want InvalidArgument", p, err)
		}
	}
	if _, err := s.PullISO(adminCtx(), &pb.PullISORequest{Ref: "acme-isos/deb.iso", HostPath: deb}); err != nil {
		t.Errorf("pull of an ISO in root's home: %v", err)
	}
	if _, err := s.PullISO(adminCtx(), &pb.PullISORequest{Ref: "acme-isos/k.iso", HostPath: key}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("pull of ~root/.ssh's key: got %v, want InvalidArgument", err)
	}
}
