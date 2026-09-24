package restapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The non-SSE deploy route returned the first progress frame and closed the
// stream. Closing a DeployStack stream cancels the deploy on the server (its
// next Send fails — pinned by TestFleet_ComposeAbandonedDeployStreamCancels
// TheRestOfTheDeploy), so a REST deploy without SSE created at most its first
// VM, abandoned the rest, never wrote the stack record, and answered 200.

type stackDeployBody struct {
	Name     string   `json:"name"`
	Done     []string `json:"done"`
	Failures []struct {
		Name  string `json:"name"`
		Error string `json:"error"`
	} `json:"failures"`
	Error string `json:"error"`
}

func postStackDeploy(t *testing.T, msgs []*pb.DeployProgress) (int, stackDeployBody, string, *mockServerStreamingClient[pb.DeployProgress]) {
	t.Helper()
	s, mock := newMockServer("test-token")
	stream := &mockServerStreamingClient[pb.DeployProgress]{msgs: msgs}
	mock.deployStackStream = stream
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/deploy",
		strings.NewReader(`{"compose_yaml":"name: hb\nvms: {}\n"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	var body stackDeployBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %v: %s", err, rec.Body.String())
	}
	return rec.Code, body, rec.Body.String(), stream
}

func TestStackDeploy_ReadsTheWholeDeploy(t *testing.T) {
	msgs := []*pb.DeployProgress{
		{Phase: "plan", Detail: "2 to create"},
		{Phase: "applying", VmName: "hb-1"},
		{Phase: "done", VmName: "hb-1"},
		{Phase: "applying", VmName: "hb-2"},
		{Phase: "done", VmName: "hb-2"},
	}
	code, body, raw, stream := postStackDeploy(t, msgs)
	if stream.idx != len(msgs) {
		t.Fatalf("the handler read %d of %d frames: it abandoned the stream, which cancels the deploy", stream.idx, len(msgs))
	}
	if code != http.StatusOK {
		t.Fatalf("a clean deploy answered %d: %s", code, raw)
	}
	if body.Name != "hb" || strings.Join(body.Done, ",") != "hb-1,hb-2" || len(body.Failures) != 0 {
		t.Fatalf("body = %s, want name hb, done [hb-1 hb-2], no failures", raw)
	}
}

func TestStackDeploy_AFailedActionIsNotOK(t *testing.T) {
	code, body, raw, _ := postStackDeploy(t, []*pb.DeployProgress{
		{Phase: "applying", VmName: "hb-1"},
		{Phase: "error", VmName: "hb-1", Error: "define refused"},
		{Phase: "applying", VmName: "hb-2"},
		{Phase: "done", VmName: "hb-2"},
	})
	if code == http.StatusOK {
		t.Fatalf("a deploy with a failed action answered 200: %s", raw)
	}
	if len(body.Failures) != 1 || body.Failures[0].Name != "hb-1" || body.Failures[0].Error != "define refused" {
		t.Fatalf("failures = %s, want hb-1: define refused", raw)
	}
	if !strings.Contains(body.Error, "1 of 2") || !strings.Contains(body.Error, "degraded") {
		t.Fatalf("error summary %q should say 1 of 2 actions failed and the stack is degraded", body.Error)
	}
}
