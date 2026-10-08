package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// localRootCtx is `lv` run as root on the host itself with no CLI bundle: it
// presents the host certificate over loopback.
func localRootCtx(host string) context.Context {
	ctx := context.WithValue(context.Background(), ctxKeyAuthMethod, authMethodMTLS)
	ctx = context.WithValue(ctx, ctxKeyMTLSCommonName, host)
	ctx = context.WithValue(ctx, ctxKeyUsername, "admin")
	ctx = context.WithValue(ctx, ctxKeyRole, "admin")
	return context.WithValue(ctx, ctxKeyPrincipalKind, principalKindLocalRoot)
}

// The lab ran `lv ct restore` on the container's host: the host-cert CLI was
// taken for a peer coordinator and refused for carrying no relocation proof.
// It is local root, an operator restore, as from any other CLI.
func TestRestoreContainer_LocalRootCLIIsAnOperatorRestore(t *testing.T) {
	s, rt, repo, ts, _, _ := setupProofRestore(t)
	s.gate = fakeServerGate{execOK: true, enforced: true}
	// The host's own row: its certificate is a trusted host CN.
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "self", Address: "127.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: localRootCtx("self")}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{Name: "ct1", RepoPath: repo, Timestamp: ts}, rs); err != nil {
		t.Fatalf("local-root restore: %v", err)
	}
	if _, ok := rt.imported["ct1"]; !ok {
		t.Fatal("nothing imported")
	}
	if row, _ := corrosion.GetContainer(context.Background(), s.db, "self", "ct1"); row == nil {
		t.Fatal("no row")
	}
}

// A remote peer with no proof under enforcement is still refused.
func TestRestoreContainer_RemotePeerWithoutProofStillRefused(t *testing.T) {
	s, _, repo, ts, _, _ := setupProofRestore(t)
	s.gate = fakeServerGate{execOK: true, enforced: true}
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: mtlsAdminCtx("peer-1")}
	err := s.RestoreContainer(&pb.RestoreContainerRequest{Name: "ct1", RepoPath: repo, Timestamp: ts}, rs)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("peer restore without proof: %v", err)
	}
}

// Restore has no rename: the name selects the manifest. The refusal over a
// live container says what does work.
func TestRestoreContainer_AlreadyExistsNamesWhatWorks(t *testing.T) {
	s, _, repo, ts, _, _ := setupProofRestore(t)
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "self", Name: "ct1", State: "stopped",
	}); err != nil {
		t.Fatal(err)
	}
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	err := s.RestoreContainer(&pb.RestoreContainerRequest{Name: "ct1", RepoPath: repo, Timestamp: ts}, rs)
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "different name") || !strings.Contains(err.Error(), "--host") {
		t.Fatalf("message %q offers a rename restore does not have, or omits --host", err)
	}
}
