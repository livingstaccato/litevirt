package grpcapi

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// isoSourcePeer is the migration source of VM name calling this host: an
// mTLS peer whose certificate names the host the VM's row is on.
func isoSourcePeer(t *testing.T, s *Server, name string) context.Context {
	t.Helper()
	return isoPeer(t, s, vmRecord(t, s, name).HostName)
}

// isoPeer is cluster host cn calling this host over mTLS, as the interceptor
// classifies a peer (with a peer's authority).
func isoPeer(t *testing.T, s *Server, cn string) context.Context {
	t.Helper()
	if h, _ := corrosion.GetHost(context.Background(), s.db, cn); h == nil {
		if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: cn, Address: "10.0.0.9", State: "active"}); err != nil {
			t.Fatalf("InsertHost(%s): %v", cn, err)
		}
	}
	return replicationPeerCtx(cn)
}

// sharedLibraryTarget is a migration target where another project's pool
// maps the directory of the VM's library, so the VM's file there is admitted
// only by its record or by the source's hash of it.
func sharedLibraryTarget(t *testing.T) (*Server, string) {
	t.Helper()
	s, _ := stubTarget(t)
	lib, here := libraryVM(t, s, "mig", "acme")
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "o-disks", Driver: "dir", Target: lib, Project: "other", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	return s, here
}

// I-1(a): the hash that admits a file by its bytes, and records it as the
// VM's, comes only from the VM's owning host. A user's call (vm.migrate on
// their own VM is an Operator's) or another peer's naming the very sha256 of
// another project's file admits nothing and records nothing.
//
// Mutation: drop the peer check in verifyIncomingVMISO — the user's forged
// hash admits the file and the test goes red; drop the owner check — the
// other peer's does.
func TestISOFinal_OnlyTheOwningHostsHashAdmitsAFile(t *testing.T) {
	s, here := sharedLibraryTarget(t)
	forged := func(ctx context.Context) error {
		_, err := s.EnsureDisks(ctx, &pb.EnsureDisksRequest{VmName: "mig", InstallerIsoListed: true,
			InstallerIsoPaths: []string{"/x"}, InstallerIsoRuntime: true,
			InstallerIsoSha256: map[string]string{"/x": sha(isoBody)}})
		return err
	}
	for name, ctx := range map[string]context.Context{
		"a user":                   adminCtx(),
		"a peer that is not owner": isoPeer(t, s, "bystander"),
	} {
		if err := forged(ctx); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s naming the file's sha256: got %v, want FailedPrecondition", name, err)
		}
		if got := identityFiles(t, s); len(got) != 0 {
			t.Fatalf("%s's hash recorded an identity: %v", name, got)
		}
	}
	// The owning host's hash still admits the very bytes it judged.
	if _, err := s.EnsureDisks(isoSourcePeer(t, s, "mig"), &pb.EnsureDisksRequest{VmName: "mig", InstallerIsoListed: true,
		InstallerIsoPaths: []string{here}, InstallerIsoRuntime: true,
		InstallerIsoSha256: map[string]string{here: sha(isoBody)}}); err != nil {
		t.Fatalf("the owning host's hash of the very bytes: %v", err)
	}
}

// I-1(b): a user's listed paths are not read: the host judges the VM's own
// ISO, as on main, and answers nothing about the path named — not its
// existence, nor its target.
//
// Mutation: drop the peer check — the host key path is judged and refused,
// and the test goes red.
func TestISOFinal_AUsersListedPathsAreNotProbed(t *testing.T) {
	s, key := hostTarget(t)
	_, _ = libraryVM(t, s, "mig", "acme")
	r, err := s.EnsureDisks(adminCtx(), &pb.EnsureDisksRequest{VmName: "mig", InstallerIsoListed: true,
		InstallerIsoPaths: []string{key, "/etc/shadow"}, InstallerIsoRuntime: true})
	if err != nil {
		t.Fatalf("a user's EnsureDisks naming paths: %v (the paths were judged)", err)
	}
	if len(r.GetInstallerIsoResolved()) != 0 {
		t.Fatalf("a user's EnsureDisks resolved the paths it named: %v", r.GetInstallerIsoResolved())
	}
	// The source host's listing is still judged.
	if _, err := s.EnsureDisks(isoSourcePeer(t, s, "mig"), &pb.EnsureDisksRequest{VmName: "mig", InstallerIsoListed: true,
		InstallerIsoPaths: []string{key, "/srv/other.iso"}, InstallerIsoRuntime: true}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("the source's listing with the host key: got %v, want FailedPrecondition", err)
	}
}

// I-1(c): a listed path is read under the probe budget: one whose filesystem
// does not answer is refused when the budget runs out, rather than holding
// the call (and a thread) until it does.
//
// Mutation: read the listed path outside deadlined — the call blocks and the
// test goes red.
func TestISOFinal_AListedPathIsReadUnderTheBudget(t *testing.T) {
	s, _ := stubTarget(t)
	_, _ = libraryVM(t, s, "mig", "acme")
	block := make(chan struct{})
	origT := isoDirProbeTimeout
	t.Cleanup(func() { close(block); listedISOBeforeRead = nil; isoDirProbeTimeout = origT })
	isoDirProbeTimeout = 100 * time.Millisecond
	dead := "/srv/dead-nfs/x.iso"
	listedISOBeforeRead = func(p string) {
		if p == dead {
			<-block
		}
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.EnsureDisks(isoSourcePeer(t, s, "mig"), &pb.EnsureDisksRequest{VmName: "mig", InstallerIsoListed: true,
			InstallerIsoPaths: []string{dead, "/srv/other.iso"}, InstallerIsoRuntime: true})
		done <- err
	}()
	select {
	case err := <-done:
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("a listed path that does not answer: got %v, want FailedPrecondition", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("EnsureDisks blocked on a listed path that does not answer")
	}
}
