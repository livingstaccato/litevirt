package grpcapi

import (
	"context"
	"errors"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ResetAdminPassword is `lv user reset-admin` when the daemon is running.
//
// It is the recovery path for a cluster nobody can log in to, so it cannot ask
// for a credential. What it asks for instead is the host's local root channel:
// the call arrives over loopback presenting THIS host's own certificate and no
// bearer, which the auth interceptor classifies as local-root. Reading host.key
// takes root on this machine, and a loopback source address cannot be spoofed
// from off the box, so that is exactly "root on this host" and nothing wider. A
// peer's certificate, a bearer admin, and the distributable lv-cli certificate
// are all refused — a reset that anyone with a session could run is not a
// recovery path, it is a second password-change RPC with no old password.
//
// It writes the reset and its audit row here, in the daemon, because the daemon
// is the only writer of this host's audit chain: a row written by the CLI
// process forks the chain and is unsigned (TestAudit_SecondProcessRowForksTheChain).
// The CLI sends only a bcrypt hash; the plaintext never leaves the process that
// writes the password file, and neither appears in the row.
func (s *Server) ResetAdminPassword(ctx context.Context, req *pb.ResetAdminPasswordRequest) (*emptypb.Empty, error) {
	if callerPrincipalKind(ctx) != principalKindLocalRoot {
		return nil, status.Error(codes.PermissionDenied,
			"reset-admin is local root only: run `lv user reset-admin` as root on the node, "+
				"which presents the host certificate over loopback")
	}
	if cn := callerMTLSCommonName(ctx); cn != s.hostName {
		return nil, status.Errorf(codes.PermissionDenied,
			"reset-admin must present this host's own certificate (%q), not %q", s.hostName, cn)
	}
	cost, err := bcrypt.Cost([]byte(req.PasswordHash))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "password_hash is not a bcrypt hash: %v", err)
	}
	if cost < auth.BcryptCost {
		return nil, status.Errorf(codes.InvalidArgument,
			"password_hash has bcrypt cost %d, below this cluster's %d", cost, auth.BcryptCost)
	}

	actor := "root@" + s.hostName
	detail := corrosion.ResetAdminAuditDetail("local-root", req.OsUser)
	if err := corrosion.ResetAdminPassword(ctx, s.db, req.PasswordHash); err != nil {
		if errors.Is(err, corrosion.ErrNoLiveAdmin) {
			s.auditAs(ctx, actor, "user.reset-admin", "admin", detail, "denied: no live admin account")
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		s.auditAs(ctx, actor, "user.reset-admin", "admin", detail, "error")
		return nil, status.Errorf(codes.Internal, "reset admin password: %v", err)
	}
	s.auditAs(ctx, actor, "user.reset-admin", "admin", detail, "ok")
	return &emptypb.Empty{}, nil
}
