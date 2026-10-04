package ui

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A refused write must reach the browser as the daemon's refusal, not as a
// server fault. These drive two pages that have nothing to do with the
// notification and resource-mapping ones TestUINotifyTargetWrites_ViewerRefused
// covers, through the real daemon and its auth interceptor, so the source guard
// TestNoUIHandlerAnswersRPCErrorWith500 is not the only proof.

func TestUIDeleteStoragePool_ViewerRefusedWith403(t *testing.T) {
	s, db := newUIOverRealDaemon(t, "vic", "viewer")
	ctx := context.Background()
	if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{
		HostName: "test-host", Name: "fast", Driver: "dir", Target: "/srv/fast", State: "active",
	}); err != nil {
		t.Fatalf("UpsertStoragePool: %v", err)
	}

	w := serveRequest(s, uiSessionReq(t, "DELETE", "/ui/storage/fast?host=test-host", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if _, ok, err := corrosion.GetStoragePool(ctx, db, "test-host", "fast"); err != nil || !ok {
		t.Errorf("a viewer deleted storage pool fast (present=%v, err %v)", ok, err)
	}
}

func TestUIRevokeRole_ViewerRefusedWith403(t *testing.T) {
	s, db := newUIBoundTo(t, "vic", "Viewer")
	ctx := context.Background()
	if err := corrosion.InsertRoleBinding(ctx, db, corrosion.RoleBindingRecord{
		ID: "keep-me", Path: "/", Role: "Operator", Principal: "user:olga@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}

	w := serveRequest(s, uiSessionReq(t, "DELETE", "/ui/rbac/bindings/keep-me", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	bindings, err := corrosion.ListRoleBindings(ctx, db)
	if err != nil {
		t.Fatalf("ListRoleBindings: %v", err)
	}
	for _, b := range bindings {
		if b.ID == "keep-me" {
			return
		}
	}
	t.Errorf("a viewer revoked binding keep-me: %+v", bindings)
}

// A streaming RPC's refusal arrives on the first Recv, not from the call that
// opens the stream. The deploy and push handlers drained their streams with
// `if err != nil { break }`, and the pull handler ignored its one Recv, so a
// refused deploy, push or pull was toasted as a success and answered 200.

type refusingStreamsMock struct {
	*mockGRPC
	err error
}

func (m *refusingStreamsMock) DeployStack(context.Context, *pb.DeployStackRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DeployProgress], error) {
	return &scriptedStream[pb.DeployProgress]{err: m.err}, nil
}

func (m *refusingStreamsMock) PushImage(context.Context, *pb.PushImageRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.PushImageProgress], error) {
	return &scriptedStream[pb.PushImageProgress]{err: m.err}, nil
}

func (m *refusingStreamsMock) PullImage(context.Context, *pb.PullImageRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.PullProgress], error) {
	return &scriptedStream[pb.PullProgress]{err: m.err}, nil
}

func TestUIStreamingWrites_RefusalOnFirstRecvIsReported(t *testing.T) {
	mock := &refusingStreamsMock{mockGRPC: newDefaultMock(), err: status.Error(codes.PermissionDenied, "operator role required")}
	s, err := NewServer(mock, "test-cluster")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	reqs := map[string]*http.Request{
		"deploy stack": authReq(t, "POST", "/ui/stacks", url.Values{"compose_yaml": {"name: hb\nservices: {}\n"}}),
		"pull image":   authReq(t, "POST", "/ui/images/pull", url.Values{"name": {"debian"}, "source_url": {"https://example.invalid/d.qcow2"}}),
		"push image":   authReq(t, "POST", "/ui/images/push", url.Values{"image_name": {"debian"}, "target_host": {"h2"}}),
	}
	for what, r := range reqs {
		w := serveRequest(s, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want %d", what, w.Code, http.StatusForbidden)
		}
		trig := w.Header().Get("HX-Trigger")
		if strings.Contains(trig, `"success"`) || !strings.Contains(trig, "operator role required") {
			t.Errorf("%s: a refused write was not reported as refused: %s", what, trig)
		}
	}
}
