package restapi

import (
	"context"
	"encoding/json"
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

// A non-SSE stack deploy or delete reads the whole stream before it answers, so
// it answers only when the operation is over — which for a real stack is well
// past the gateway's 120s WriteTimeout. Under that deadline the verdict was
// written to a connection net/http had already given up on: the client read
// EOF, with no status and no failures list, and a caller that cannot tell
// "failed" from "finished" retries. And the stream ran on the request context,
// so a client that gave up early cancelled the deploy or teardown half-way.

// ctxStream models a gRPC client stream: each frame arrives after delay (or
// after release is closed, when gate is set), and a cancelled context ends the
// stream the way a real one does.
type ctxStream[T any] struct {
	grpc.ClientStream
	ctx   context.Context
	msgs  []*T
	delay time.Duration
	gate  chan struct{}

	mu    sync.Mutex
	reads int
}

func (s *ctxStream[T]) Recv() (*T, error) {
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

func (s *ctxStream[T]) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

type stackStreamGRPC struct {
	pb.LiteVirtClient
	deploy []*pb.DeployProgress
	del    []*pb.DeleteProgress
	delay  time.Duration
	gate   chan struct{}

	mu        sync.Mutex
	deploySt  *ctxStream[pb.DeployProgress]
	deleteSt  *ctxStream[pb.DeleteProgress]
	streamCtx context.Context
}

func (m *stackStreamGRPC) DeployStack(ctx context.Context, _ *pb.DeployStackRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DeployProgress], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streamCtx = ctx
	m.deploySt = &ctxStream[pb.DeployProgress]{ctx: ctx, msgs: m.deploy, delay: m.delay, gate: m.gate}
	return m.deploySt, nil
}

func (m *stackStreamGRPC) DeleteStack(ctx context.Context, _ *pb.DeleteStackRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.DeleteProgress], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streamCtx = ctx
	m.deleteSt = &ctxStream[pb.DeleteProgress]{ctx: ctx, msgs: m.del, delay: m.delay, gate: m.gate}
	return m.deleteSt, nil
}

func (m *stackStreamGRPC) ctx() context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streamCtx
}

// serveWithWriteTimeout runs the gateway on a real listener whose WriteTimeout
// is far shorter than the stream it will serve.
func serveWithWriteTimeout(t *testing.T, s *Server, wt time.Duration) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(s.mux)
	ts.Config.WriteTimeout = wt
	ts.Start()
	t.Cleanup(ts.Close)
	return ts
}

func postJSON(t *testing.T, url, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("the client got no answer from a deploy/delete that outlived the WriteTimeout: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("the verdict was cut off: %v (read %q)", err, b)
	}
	return resp.StatusCode, string(b)
}

func TestStackDeploy_VerdictSurvivesTheWriteTimeout(t *testing.T) {
	mock := &stackStreamGRPC{delay: 300 * time.Millisecond, deploy: []*pb.DeployProgress{
		{Phase: "applying", VmName: "hb-1"},
		{Phase: "done", VmName: "hb-1"},
		{Phase: "applying", VmName: "hb-2"},
		{Phase: "error", VmName: "hb-2", Error: "no host fits"},
	}}
	ts := serveWithWriteTimeout(t, NewServer(mock, "test-token"), time.Second)

	code, raw := postJSON(t, ts.URL+"/api/v1/stacks/deploy", `{"compose_yaml":"name: hb\nvms: {}\n"}`)
	if code != http.StatusInternalServerError {
		t.Fatalf("a deploy with a failed action answered %d, want 500: %s", code, raw)
	}
	var body stackDeployBody
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("verdict is not JSON: %v: %s", err, raw)
	}
	if len(body.Failures) != 1 || body.Failures[0].Name != "hb-2" || strings.Join(body.Done, ",") != "hb-1" {
		t.Errorf("verdict = %s, want hb-1 done and hb-2 failed", raw)
	}
}

func TestStackDelete_VerdictSurvivesTheWriteTimeout(t *testing.T) {
	mock := &stackStreamGRPC{delay: 300 * time.Millisecond, del: []*pb.DeleteProgress{
		{VmName: "hb-1", Status: "deleting"},
		{VmName: "hb-1", Status: "deleted"},
		{VmName: "hb-2", Status: "deleting"},
		{VmName: "hb-2", Status: "error", Error: "undefine refused"},
	}}
	ts := serveWithWriteTimeout(t, NewServer(mock, "test-token"), time.Second)

	code, raw := postJSON(t, ts.URL+"/api/v1/stacks/delete", `{"name":"hb"}`)
	if code != http.StatusConflict {
		t.Fatalf("an incomplete teardown answered %d, want 409: %s", code, raw)
	}
	var body stackDeleteBody
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("verdict is not JSON: %v: %s", err, raw)
	}
	if len(body.Failures) != 1 || body.Failures[0].Name != "hb-2" || strings.Join(body.Deleted, ",") != "hb-1" {
		t.Errorf("verdict = %s, want hb-1 deleted and hb-2 failed", raw)
	}
}

// A client that stops waiting must not take the operation down with it.
func TestStackDeployDelete_ClientDisconnectDoesNotCancel(t *testing.T) {
	for _, tc := range []struct {
		name, path, body string
		reads            func(*stackStreamGRPC) int
		want             int
	}{
		{"deploy", "/api/v1/stacks/deploy", `{"compose_yaml":"name: hb\nvms: {}\n"}`,
			func(m *stackStreamGRPC) int { m.mu.Lock(); defer m.mu.Unlock(); return m.deploySt.readCount() }, 3},
		{"delete", "/api/v1/stacks/delete", `{"name":"hb"}`,
			func(m *stackStreamGRPC) int { m.mu.Lock(); defer m.mu.Unlock(); return m.deleteSt.readCount() }, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gate := make(chan struct{})
			mock := &stackStreamGRPC{gate: gate,
				deploy: []*pb.DeployProgress{{Phase: "applying", VmName: "hb-1"}, {Phase: "done", VmName: "hb-1"}},
				del:    []*pb.DeleteProgress{{VmName: "hb-1", Status: "deleting"}, {VmName: "hb-1", Status: "deleted"}},
			}
			ts := serveWithWriteTimeout(t, NewServer(mock, "test-token"), 10*time.Second)

			reqCtx, cancel := context.WithCancel(context.Background())
			req, _ := http.NewRequestWithContext(reqCtx, http.MethodPost, ts.URL+tc.path, strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer test-token")
			errc := make(chan error, 1)
			go func() {
				resp, err := http.DefaultClient.Do(req)
				if err == nil {
					resp.Body.Close()
				}
				errc <- err
			}()

			// Wait until the handler holds the stream, then walk away.
			deadline := time.Now().Add(5 * time.Second)
			for mock.ctx() == nil && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if mock.ctx() == nil {
				t.Fatal("the handler never opened the stream")
			}
			cancel()
			<-errc
			// net/http notices the closed connection asynchronously.
			time.Sleep(200 * time.Millisecond)

			if err := mock.ctx().Err(); err != nil {
				t.Fatalf("the client disconnecting cancelled the %s stream (%v): the operation is abandoned half-way", tc.name, err)
			}
			close(gate)
			deadline = time.Now().Add(5 * time.Second)
			for tc.reads(mock) < tc.want && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if got := tc.reads(mock); got < tc.want {
				t.Errorf("the %s stream was read %d time(s) after the client left, want it read to the end (%d)", tc.name, got, tc.want)
			}
		})
	}
}
