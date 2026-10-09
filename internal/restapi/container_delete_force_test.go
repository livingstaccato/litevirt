package restapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func deleteContainerREST(t *testing.T, body string) (*httptest.ResponseRecorder, *mockGRPC) {
	t.Helper()
	s, mock := newMockServer("test-token")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/containers/delete", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec, mock
}

// A REST delete body without a "force" key deletes the container even when it
// is running, as on main: the REST surface never had the field, so a client
// written against main sends {"name": ...} and expects the container gone.
// Only an explicit "force": false asks for the running-container refusal.
func TestContainerDeleteREST_ForceDefaultsWhenKeyAbsent(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{`{"name":"web"}`, true},
		{`{"name":"web","host_name":"n1"}`, true},
		{`{"name":"web","force":true}`, true},
		{`{"name":"web","force":false}`, false},
	}
	for _, tc := range cases {
		rec, mock := deleteContainerREST(t, tc.body)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("%s: status %d body=%q", tc.body, rec.Code, rec.Body.String())
		}
		got := mock.lastDeleteContainerReq
		if got == nil {
			t.Fatalf("%s: DeleteContainer not called", tc.body)
		}
		if got.GetName() != "web" {
			t.Errorf("%s: forwarded name %q, want web", tc.body, got.GetName())
		}
		if got.GetForce() != tc.want {
			t.Errorf("%s: forwarded force=%v, want %v", tc.body, got.GetForce(), tc.want)
		}
	}
}

// A body that does not parse is still refused, and nothing is deleted.
func TestContainerDeleteREST_MalformedBodyRefused(t *testing.T) {
	for _, body := range []string{`{"name":"web","force":"yes"}`, `{"name":`} {
		rec, mock := deleteContainerREST(t, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", body, rec.Code)
		}
		if mock.lastDeleteContainerReq != nil {
			t.Errorf("%s: DeleteContainer called with %+v", body, mock.lastDeleteContainerReq)
		}
	}
}
