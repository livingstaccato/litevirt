package ui

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The destroy handler reads the whole DeleteStack stream before it answers,
// because only the whole stream says whether the teardown was complete. It did
// that on the request context and under the UI's 30s WriteTimeout, so a
// teardown longer than 30s lost its toast — the "not fully destroyed" warning
// included — to a connection net/http had given up on, and a browser that
// navigated away cancelled the teardown half-way.

// slowDeleteStream models a gRPC stream: frames arrive after delay (the second
// only once gate is closed, if set), and a cancelled context ends it.
type slowDeleteStream struct {
	grpc.ClientStream
	ctx   context.Context
	msgs  []*pb.DeleteProgress
	delay time.Duration
	gate  chan struct{}

	mu    sync.Mutex
	reads int
}

func (s *slowDeleteStream) Recv() (*pb.DeleteProgress, error) {
	s.mu.Lock()
	i := s.reads
	s.reads++
	s.mu.Unlock()
	if s.gate != nil && i == 1 {
		select {
		case <-s.gate:
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		}
	}
	select {
	case <-time.After(s.delay):
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
	if i < len(s.msgs) {
		return s.msgs[i], nil
	}
	return nil, io.EOF
}

func (s *slowDeleteStream) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

type slowDeleteGRPC struct {
	*mockGRPC
	msgs  []*pb.DeleteProgress
	delay time.Duration
	gate  chan struct{}

	smu    sync.Mutex
	stream *slowDeleteStream
}

func (m *slowDeleteGRPC) DeleteStack(ctx context.Context, _ *pb.DeleteStackRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DeleteProgress], error) {
	m.smu.Lock()
	defer m.smu.Unlock()
	m.stream = &slowDeleteStream{ctx: ctx, msgs: m.msgs, delay: m.delay, gate: m.gate}
	return m.stream, nil
}

func (m *slowDeleteGRPC) opened() *slowDeleteStream {
	m.smu.Lock()
	defer m.smu.Unlock()
	return m.stream
}

func serveUIWithWriteTimeout(t *testing.T, m *slowDeleteGRPC, wt time.Duration) *httptest.Server {
	t.Helper()
	s, err := NewServer(m, "test-cluster")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	s.SetAuthorizer(mockAuthorizer{m.mockGRPC})
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.Config.WriteTimeout = wt
	ts.Start()
	t.Cleanup(ts.Close)
	return ts
}

func TestHandler_DestroyStack_ToastSurvivesTheWriteTimeout(t *testing.T) {
	m := &slowDeleteGRPC{mockGRPC: newDefaultMock(), delay: 300 * time.Millisecond, msgs: []*pb.DeleteProgress{
		{VmName: "ha1", Status: "deleting"},
		{VmName: "ha1", Status: "deleted"},
		{VmName: "ha2", Status: "deleting"},
		{VmName: "ha2", Status: "error", Error: "an operation is in progress"},
	}}
	ts := serveUIWithWriteTimeout(t, m, time.Second)

	req := withAuth(mustReq(t, "DELETE", ts.URL+"/ui/stacks/hb"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("a teardown longer than the WriteTimeout got no answer: %v", err)
	}
	defer resp.Body.Close()
	trig := resp.Header.Get("HX-Trigger")
	if !strings.Contains(trig, "not fully destroyed") || !strings.Contains(trig, "ha2") {
		t.Errorf("toast = %q, want the incomplete-teardown warning naming ha2", trig)
	}
	if resp.StatusCode == http.StatusOK {
		t.Errorf("status = %d for an incomplete teardown", resp.StatusCode)
	}
}

func TestHandler_DestroyStack_BrowserLeavingDoesNotCancelTheTeardown(t *testing.T) {
	gate := make(chan struct{})
	m := &slowDeleteGRPC{mockGRPC: newDefaultMock(), gate: gate, msgs: []*pb.DeleteProgress{
		{VmName: "ha1", Status: "deleting"},
		{VmName: "ha1", Status: "deleted"},
	}}
	ts := serveUIWithWriteTimeout(t, m, 10*time.Second)

	reqCtx, cancel := context.WithCancel(context.Background())
	req := withAuth(mustReq(t, "DELETE", ts.URL+"/ui/stacks/hb")).WithContext(reqCtx)
	errc := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		errc <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for m.opened() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	st := m.opened()
	if st == nil {
		t.Fatal("DeleteStack was never opened")
	}
	cancel()
	<-errc
	time.Sleep(200 * time.Millisecond) // net/http notices the closed connection asynchronously

	if err := st.ctx.Err(); err != nil {
		t.Fatalf("the browser leaving cancelled the teardown (%v); the stack is left half-deleted", err)
	}
	close(gate)
	deadline = time.Now().Add(5 * time.Second)
	for st.readCount() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := st.readCount(); got < 3 {
		t.Errorf("the teardown stream was read %d time(s) after the browser left, want it read to the end", got)
	}
}
