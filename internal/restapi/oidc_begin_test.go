package restapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
)

type oidcBeginMock struct {
	*mockGRPC
	last *pb.BeginOIDCLoginRequest
}

func (m *oidcBeginMock) BeginOIDCLogin(_ context.Context, in *pb.BeginOIDCLoginRequest, _ ...grpc.CallOption) (*pb.BeginOIDCLoginResponse, error) {
	m.last = in
	return &pb.BeginOIDCLoginResponse{AuthUrl: "https://idp.example/a", State: "s", Binding: "b"}, nil
}

// TestOIDCBegin_ClientAddressIsThePeers (re-review N5): the daemon trusts this
// loopback gateway's client_address, so the gateway must never pass the
// body's: it names the HTTP peer, or, from a listed trusted proxy, the
// forwarded client.
func TestOIDCBegin_ClientAddressIsThePeers(t *testing.T) {
	_, base := newMockServer("")
	m := &oidcBeginMock{mockGRPC: base}
	s := NewServer(m, "")
	post := func(peer, xff string) string {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oidc/begin",
			strings.NewReader(`{"realm":"oidc:corp","client":"cli","client_address":"6.6.6.6"}`))
		req.RemoteAddr = peer
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || m.last == nil {
			t.Fatalf("begin: %d %s", rec.Code, rec.Body.String())
		}
		return m.last.ClientAddress
	}
	if got := post("127.0.0.1:40000", "198.51.100.7"); got != "127.0.0.1" {
		t.Fatalf("no trusted proxies: client_address %q, want the peer 127.0.0.1", got)
	}
	p, _ := auth.ParseTrustedProxies([]string{"127.0.0.1"})
	s.SetTrustedProxies(p)
	if got := post("127.0.0.1:40000", "6.6.6.6, 198.51.100.7"); got != "198.51.100.7" {
		t.Fatalf("from a trusted proxy: client_address %q, want the forwarded client", got)
	}
}
