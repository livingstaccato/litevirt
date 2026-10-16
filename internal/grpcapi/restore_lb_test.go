package grpcapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/lb"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// TestAutoDefineRestoredVM_LBRules (concern 5): a live restore's spec, the
// caller's or the backup's, is held to CreateVM's LB rules: an operator may
// not name an LB TLS file outside lb.CertDir (an admin may), and a stack
// name or LB value CreateVM refuses is refused.
//
// Mutation: drop the validateRestoredLB call — red.
func TestAutoDefineRestoredVM_LBRules(t *testing.T) {
	newServer := func(t *testing.T) (*Server, *pbsstore.Repo) {
		s := testServer(t)
		s.virt = libvirtfake.New()
		s.dataDir = t.TempDir()
		isolateReviewHardwareNetwork(t, s)
		if err := os.WriteFile(filepath.Join(s.dataDir, "overlay.qcow2"), []byte("private modeled overlay"), 0600); err != nil {
			t.Fatal(err)
		}
		repo, err := pbsstore.Init(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return s, repo
	}
	noSend := func(*pb.RestoreLiveProgress) error { return nil }
	spec := func(key, stack string) *pb.VMSpec {
		l := validLBSpec()
		l.Ports[1].Tls.Key = key
		return &pb.VMSpec{Name: "r1", Cpu: 1, MemoryMib: 512, StackName: stack, Loadbalancer: l}
	}
	empty := &pbsstore.Manifest{VMName: "r1", DiskName: "root", TotalSize: 1 << 20}
	embedded := func(sp *pb.VMSpec) *pbsstore.Manifest {
		b, _ := json.Marshal(sp)
		m := *empty
		m.VMSpecJSON = string(b)
		return &m
	}
	operator := userCtx("op", "operator")

	for name, call := range map[string]func(*Server, *pbsstore.Repo) error{
		"caller spec": func(s *Server, repo *pbsstore.Repo) error {
			_, _, err := s.autoDefineRestoredVM(operator, &pb.RestoreLiveRequest{VmName: "r1", Spec: spec("/etc/litevirt/pki/host.key", "shop")}, repo, empty, filepath.Join(s.dataDir, "overlay.qcow2"), "", noSend)
			return err
		},
		"backup's spec": func(s *Server, repo *pbsstore.Repo) error {
			_, _, err := s.autoDefineRestoredVM(operator, &pb.RestoreLiveRequest{VmName: "r1"}, repo, embedded(spec("/root/x.key", "shop")), filepath.Join(s.dataDir, "overlay.qcow2"), "", noSend)
			return err
		},
	} {
		s, repo := newServer(t)
		err := call(s, repo)
		if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), lb.CertDir) {
			t.Errorf("%s: %v, want PermissionDenied naming %s", name, err, lb.CertDir)
		}
	}
	// An admin may name one; that restore goes past the LB check.
	s, repo := newServer(t)
	_, _, err := s.autoDefineRestoredVM(adminCtx(), &pb.RestoreLiveRequest{VmName: "r1", Spec: spec("/root/x.key", "shop")}, repo, empty, filepath.Join(s.dataDir, "overlay.qcow2"), "", noSend)
	if err != nil || !s.virt.DomainExists("r1") {
		t.Fatalf("admin restore did not define and start r1: %v", err)
	}
	// A stack name CreateVM refuses is refused here too.
	s, repo = newServer(t)
	_, _, err = s.autoDefineRestoredVM(adminCtx(), &pb.RestoreLiveRequest{VmName: "r1", Spec: spec(lb.CertDir+"/a.key", "../../x$(id)")}, repo, empty, filepath.Join(s.dataDir, "overlay.qcow2"), "", noSend)
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("traversal stack name: %v, want InvalidArgument", err)
	}
}
