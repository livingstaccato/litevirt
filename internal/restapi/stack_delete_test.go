package restapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// DeleteStack streams a status per resource and ends OK even when some could
// not be removed; the non-SSE REST route used to return only the first frame
// ("deleting <first VM>") with 200, so a caller could not tell a complete
// teardown from one that left VMs, containers or networks behind.

type stackDeleteBody struct {
	Name     string   `json:"name"`
	Deleted  []string `json:"deleted"`
	Failures []struct {
		Name  string `json:"name"`
		Error string `json:"error"`
	} `json:"failures"`
	Error string `json:"error"`
}

func postStackDelete(t *testing.T, msgs []*pb.DeleteProgress, streamErr error) (int, stackDeleteBody, string) {
	t.Helper()
	s, mock := newMockServer("test-token")
	mock.deleteStackStream = &mockServerStreamingClient[pb.DeleteProgress]{msgs: msgs, err: streamErr}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/delete", strings.NewReader(`{"name":"hb"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	var body stackDeleteBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %v: %s", err, rec.Body.String())
	}
	return rec.Code, body, rec.Body.String()
}

func TestStackDelete_CompleteTeardownIsOK(t *testing.T) {
	code, body, raw := postStackDelete(t, []*pb.DeleteProgress{
		{VmName: "hb-1", Status: "deleting"},
		{VmName: "hb-1", Status: "deleted"},
		{VmName: "hb-2", Status: "deleting"},
		{VmName: "hb-2", Status: "deleted"},
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("complete teardown → %d, want 200: %s", code, raw)
	}
	if body.Name != "hb" || strings.Join(body.Deleted, ",") != "hb-1,hb-2" {
		t.Errorf("body = %s, want name hb and deleted [hb-1 hb-2]", raw)
	}
	if len(body.Failures) != 0 || body.Error != "" {
		t.Errorf("complete teardown reported failures: %s", raw)
	}
}

func TestStackDelete_IncompleteTeardownIsNotOK(t *testing.T) {
	code, body, raw := postStackDelete(t, []*pb.DeleteProgress{
		{VmName: "hb-1", Status: "deleting"},
		{VmName: "hb-1", Status: "deleted"},
		{VmName: "hb-2", Status: "deleting"},
		{VmName: "hb-2", Status: "error", Error: "undefine refused"},
		{VmName: "network hb_net", Status: "error", Error: "deprovision network: busy"},
		{Status: "error", Error: "unnamed failure"},
	}, nil)
	if code >= 200 && code < 300 {
		t.Fatalf("teardown that left resources behind → %d, want non-2xx: %s", code, raw)
	}
	got := map[string]string{}
	for _, f := range body.Failures {
		got[f.Name] = f.Error
	}
	want := map[string]string{
		"hb-2":           "undefine refused",
		"network hb_net": "deprovision network: busy",
		"stack resource": "unnamed failure",
	}
	for name, errText := range want {
		if got[name] != errText {
			t.Errorf("failure for %q = %q, want %q (body %s)", name, got[name], errText, raw)
		}
	}
	if len(body.Failures) != len(want) {
		t.Errorf("got %d failures, want %d: %s", len(body.Failures), len(want), raw)
	}
	if strings.Join(body.Deleted, ",") != "hb-1" {
		t.Errorf("deleted = %v, want [hb-1]", body.Deleted)
	}
	if !strings.Contains(body.Error, "hb-2") || !strings.Contains(body.Error, "deleting") {
		t.Errorf("error summary %q does not name the failure and the retained deleting state", body.Error)
	}
}

// A stream that ends in an error after some progress is not a success either,
// and what was already reported must not be lost.
func TestStackDelete_StreamErrorIsNotOK(t *testing.T) {
	code, body, raw := postStackDelete(t, []*pb.DeleteProgress{
		{VmName: "hb-1", Status: "deleting"},
		{VmName: "hb-1", Status: "deleted"},
	}, grpcstatus.Error(codes.Internal, "set stack state: boom"))
	if code >= 200 && code < 300 {
		t.Fatalf("stream error → %d, want non-2xx: %s", code, raw)
	}
	if !strings.Contains(body.Error, "boom") {
		t.Errorf("error %q does not carry the stream error", body.Error)
	}
	if strings.Join(body.Deleted, ",") != "hb-1" {
		t.Errorf("deleted = %v, want [hb-1]", body.Deleted)
	}
}

// A stream refused before any progress keeps the usual gRPC→HTTP mapping.
func TestStackDelete_StreamRefusedMapsStatus(t *testing.T) {
	code, body, raw := postStackDelete(t, nil, grpcstatus.Error(codes.PermissionDenied, "operator role required"))
	if code != http.StatusForbidden {
		t.Fatalf("PermissionDenied → %d, want 403: %s", code, raw)
	}
	if !strings.Contains(body.Error, "operator role required") {
		t.Errorf("error = %q", body.Error)
	}
}
