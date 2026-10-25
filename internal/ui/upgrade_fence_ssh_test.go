package ui

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// fakeUpgradeStream records what an upgrade streamed.
type fakeUpgradeStream struct {
	grpc.ClientStream
	sent int
}

func (f *fakeUpgradeStream) Send(*pb.UpgradeHostRequest) error { f.sent++; return nil }
func (f *fakeUpgradeStream) CloseAndRecv() (*pb.UpgradeHostResponse, error) {
	return &pb.UpgradeHostResponse{HostName: "host1", OldVersion: "v1", NewVersion: "v2"}, nil
}

// upgradeMock answers the fanned-out fence ssh status with each member's
// mode and counts the upgrades opened.
type upgradeMock struct {
	*mockGRPC
	modes   map[string]string
	opened  int
	stream  *fakeUpgradeStream
	members []string
}

func (m *upgradeMock) GetFenceSSHStatus(context.Context, *pb.FenceSSHStatusRequest, ...grpc.CallOption) (*pb.FenceSSHStatus, error) {
	st := &pb.FenceSSHStatus{}
	for _, h := range m.members {
		mode := m.modes[h]
		if mode == "" {
			mode = "auto"
		}
		st.Nodes = append(st.Nodes, &pb.FenceSSHNode{Host: h, Reachable: true, Mode: mode})
	}
	return st, nil
}

func (m *upgradeMock) UpgradeHost(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.UpgradeHostRequest, pb.UpgradeHostResponse], error) {
	m.opened++
	return m.stream, nil
}

func upgradeReq(t *testing.T, host string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("binary", "litevirt")
	_, _ = fw.Write([]byte("BINARY"))
	_ = mw.Close()
	r, _ := http.NewRequest("POST", "/ui/hosts/"+host+"/upgrade", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return withAuth(r)
}

// The UI's upgrade runs `lv host upgrade`'s enforcement.fence_ssh preflight
// before it opens the upgrade stream: a target on legacy (it would not start
// on the new binary) and another member on legacy (an upgraded host refuses
// to fence it once release_2026_12_v1 latches) are each refused with the fix
// in the toast, and nothing is streamed. With every member on auto it
// upgrades.
//
// Mutation: drop the preflight from handleUpgradeHost — both refusals go
// through and stream the binary, red.
func TestUIUpgradeHost_RunsTheFenceSSHPreflight(t *testing.T) {
	for _, tc := range []struct {
		name    string
		modes   map[string]string
		refused string
	}{
		{"target on legacy", map[string]string{"host1": "legacy"}, "host1"},
		{"other member on legacy", map[string]string{"host2": "legacy"}, "host2"},
		{"every member on auto", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &upgradeMock{mockGRPC: newDefaultMock(), modes: tc.modes, stream: &fakeUpgradeStream{},
				members: []string{"host1", "host2"}}
			s, err := NewServer(mock, "test-cluster")
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			w := serveRequest(s, upgradeReq(t, "host1"))
			if tc.refused == "" {
				if w.Code != http.StatusOK || mock.opened != 1 || mock.stream.sent == 0 {
					t.Fatalf("upgrade = %d, %d stream(s) opened, %d chunk(s) sent; want it upgraded", w.Code, mock.opened, mock.stream.sent)
				}
				return
			}
			if w.Code != http.StatusConflict || mock.opened != 0 || mock.stream.sent != 0 {
				t.Fatalf("upgrade = %d, %d stream(s) opened, %d chunk(s) sent; want refused before streaming", w.Code, mock.opened, mock.stream.sent)
			}
			msg, typ := renderedToast(t, w)
			if typ != "error" || !strings.Contains(msg, tc.refused+": enforcement.fence_ssh is legacy") ||
				!strings.Contains(msg, "set enforcement.fence_ssh to auto or managed") {
				t.Fatalf("toast = %q (%s), want the refusal naming %s and the fix", msg, typ, tc.refused)
			}
		})
	}
}

// A member that does not report its mode is no refusal, and the upgrade goes
// on, but the operator sees the preflight's warning in the result's toast,
// not only in the daemon's log (R5).
//
// Mutation: leave the warnings out of the toast — red.
func TestUIUpgradeHost_ShowsThePreflightWarnings(t *testing.T) {
	mock := &upgradeMock{mockGRPC: newDefaultMock(), stream: &fakeUpgradeStream{},
		members: []string{"host1", "host2"}, modes: map[string]string{"host2": "-"}}
	s, err := NewServer(&silentMemberMock{mock}, "test-cluster")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	w := serveRequest(s, upgradeReq(t, "host1"))
	if w.Code != http.StatusOK || mock.opened != 1 {
		t.Fatalf("upgrade = %d (%d streams), want it upgraded", w.Code, mock.opened)
	}
	msg, typ := renderedToast(t, w)
	if typ != "warning" || !strings.Contains(msg, "preflight warning: host2 did not report its enforcement.fence_ssh") {
		t.Fatalf("toast = %q (%s), want the preflight warning naming host2", msg, typ)
	}
}

// silentMemberMock reports host2 unreachable, with no mode.
type silentMemberMock struct{ *upgradeMock }

func (m *silentMemberMock) GetFenceSSHStatus(ctx context.Context, req *pb.FenceSSHStatusRequest, opts ...grpc.CallOption) (*pb.FenceSSHStatus, error) {
	return &pb.FenceSSHStatus{Nodes: []*pb.FenceSSHNode{
		{Host: "host1", Reachable: true, Mode: "auto"},
		{Host: "host2", Reachable: false},
	}}, nil
}
