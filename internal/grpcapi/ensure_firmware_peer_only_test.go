package grpcapi

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// EnsureFirmwareState defines caller-supplied domain XML. Only the name and
// uuid of that XML are checked, so a caller could hand it a <qemu:commandline>,
// a host block device or a hostdev — and since every cold move defines its
// domain through it, it is called with no firmware bundle at all. It is the
// target half of a migration a SOURCE DAEMON drives, as ReceiveMigrationDisk
// is: a user holding vm.migrate is refused, and so is a call for a VM whose
// row names this host, where a defined domain is what `lv start` boots.
//
// Mutations: drop requirePeerCert — the user call defines its XML and goes
// red; drop the row-names-here refusal — the peer call does.
func TestEnsureFirmwareState_IsAPeerCallForAVMLivingElsewhere(t *testing.T) {
	xml := `<domain type='kvm'><name>os1</name></domain>`
	for _, tc := range []struct {
		name  string
		owner func(s *Server) string
		peer  bool
		want  codes.Code
	}{
		{"user with vm.migrate", func(*Server) string { return "src-host" }, false, codes.PermissionDenied},
		{"peer, row names this host", func(s *Server) string { return s.hostName }, true, codes.FailedPrecondition},
		{"peer, row names the source", func(*Server) string { return "src-host" }, true, codes.OK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			fake := libvirtfake.New()
			s.virt = fake
			s.dataDir = t.TempDir()
			insertTestVMWithSpec(t, adminCtx(), s.db, "os1", tc.owner(s), "stopped", `{"name":"os1"}`)
			ctx := adminCtx()
			if tc.peer {
				ctx = diskPeerCtx(t, s)
			}
			_, err := s.EnsureFirmwareState(ctx, &pb.EnsureFirmwareStateRequest{VmName: "os1", DomainXml: xml, AttemptId: "a1"})
			if got := status.Code(err); got != tc.want {
				t.Fatalf("EnsureFirmwareState = %v (%v), want %v", got, err, tc.want)
			}
			if defined := fake.DomainExists("os1"); defined != (tc.want == codes.OK) {
				t.Fatalf("domain defined = %v, want %v", defined, tc.want == codes.OK)
			}
		})
	}
}
