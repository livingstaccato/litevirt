package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// oidcCLIStub is the node side of a CLI OIDC login.
type oidcCLIStub struct {
	pb.LiteVirtClient
	redirect string
	logins   []*pb.LoginRequest
	answers  []*pb.LoginResponse
}

func (s *oidcCLIStub) BeginOIDCLogin(_ context.Context, in *pb.BeginOIDCLoginRequest, _ ...grpc.CallOption) (*pb.BeginOIDCLoginResponse, error) {
	if in.Client != "cli" {
		return nil, fmt.Errorf("client %q, want cli", in.Client)
	}
	return &pb.BeginOIDCLoginResponse{AuthUrl: "https://idp.example/authorize?x=1", State: "the-state", RedirectUri: s.redirect, Binding: "b-1"}, nil
}

func (s *oidcCLIStub) Login(_ context.Context, in *pb.LoginRequest, _ ...grpc.CallOption) (*pb.LoginResponse, error) {
	s.logins = append(s.logins, in)
	r := s.answers[0]
	s.answers = s.answers[1:]
	return r, nil
}

func loopbackRedirect(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return fmt.Sprintf("http://127.0.0.1:%d/oidc/callback", port)
}

// TestOIDCLogin_CLIAcceptsOnlyItsOwnFlowsAnswer: a request to the loopback
// listener with another state, or on another path, does not end the login;
// the real answer's code is the one sent to the node, with the flow's state.
func TestOIDCLogin_CLIAcceptsOnlyItsOwnFlowsAnswer(t *testing.T) {
	stub := &oidcCLIStub{redirect: loopbackRedirect(t), answers: []*pb.LoginResponse{{Token: "lvs_t", Username: "alice"}}}
	statuses := make(chan string, 3)
	resp, err := OIDCLogin(context.Background(), stub, OIDCLoginOptions{
		Realm:   "oidc:corp",
		Timeout: 10 * time.Second,
		OpenBrowser: func(string) error {
			go func() {
				for _, u := range []string{
					stub.redirect + "?code=forged&state=not-the-state",
					strings.Replace(stub.redirect, "/oidc/callback", "/other", 1) + "?code=forged&state=the-state",
					stub.redirect + "?code=real&state=the-state",
				} {
					r, err := http.Get(u)
					if err != nil {
						statuses <- err.Error()
						continue
					}
					r.Body.Close()
					statuses <- r.Status
				}
			}()
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Token != "lvs_t" || len(stub.logins) != 1 {
		t.Fatalf("resp %+v, %d logins", resp, len(stub.logins))
	}
	if l := stub.logins[0]; l.OidcCode != "real" || l.OidcState != "the-state" || l.Realm != "oidc:corp" || l.OidcBinding != "b-1" {
		t.Fatalf("login request %+v: want the real code with the flow's state and its binding", l)
	}
	if s := <-statuses; !strings.HasPrefix(s, "400") {
		t.Fatalf("a forged state answered %s, want 400", s)
	}
	if s := <-statuses; !strings.HasPrefix(s, "404") {
		t.Fatalf("another path answered %s, want 404", s)
	}
}

// TestOIDCLogin_CLISecondFactorUsesTheHandle: a challenge is answered with the
// node's handle and the factor, never by resending the spent code.
func TestOIDCLogin_CLISecondFactorUsesTheHandle(t *testing.T) {
	stub := &oidcCLIStub{redirect: loopbackRedirect(t), answers: []*pb.LoginResponse{
		{Requires_2Fa: true, OidcPending: "handle-1"},
		{Token: "lvs_t", Username: "alice"},
	}}
	resp, err := OIDCLogin(context.Background(), stub, OIDCLoginOptions{
		Realm:        "oidc:corp",
		Timeout:      10 * time.Second,
		SecondFactor: func() (string, error) { return "123456", nil },
		OpenBrowser: func(string) error {
			go func() {
				if r, err := http.Get(stub.redirect + "?code=real&state=the-state"); err == nil {
					r.Body.Close()
				}
			}()
			return nil
		},
	})
	if err != nil || resp.Token != "lvs_t" {
		t.Fatalf("%+v %v", resp, err)
	}
	if l := stub.logins[1]; l.OidcPending != "handle-1" || l.TotpCode != "123456" || l.OidcCode != "" || l.OidcState != "" {
		t.Fatalf("second-factor request %+v", l)
	}
}

// TestOIDCLogin_CLIRefusesANonLoopbackRedirect: whatever the node says, the
// CLI listens only on the IPv4 loopback.
func TestOIDCLogin_CLIRefusesANonLoopbackRedirect(t *testing.T) {
	for _, r := range []string{"https://127.0.0.1:18765/cb", "http://0.0.0.0:18765/cb", "http://10.0.0.1:18765/cb"} {
		stub := &oidcCLIStub{redirect: r}
		opened := false
		_, err := OIDCLogin(context.Background(), stub, OIDCLoginOptions{Realm: "oidc:corp", Timeout: time.Second,
			OpenBrowser: func(string) error { opened = true; return nil }})
		if err == nil || opened || !strings.Contains(err.Error(), "not a loopback http URL") {
			t.Errorf("redirect %s: err %v, browser opened %v; want a refusal before listening", r, err, opened)
		}
	}
}
