package cli

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// OIDCLoginOptions drive OIDCLogin.
type OIDCLoginOptions struct {
	// Realm is "oidc:<name>".
	Realm string
	// Out receives the instructions (the URL to open). Never a token.
	Out io.Writer
	// OpenBrowser opens the IdP URL; nil prints it only. OpenBrowserDefault
	// runs the platform's opener.
	OpenBrowser func(url string) error
	// SecondFactor prompts for litevirt's second factor when the login
	// policy requires one.
	SecondFactor func() (string, error)
	// Timeout bounds the wait for the IdP's answer (default 5 minutes).
	Timeout time.Duration
	// UserAgent is recorded on the session.
	UserAgent string
}

// OIDCLogin runs an OIDC login from the CLI with a loopback redirect (RFC 8252
// §7.3):
//
//  1. BeginOIDCLogin(client=cli) on the node c is connected to. The node holds
//     the flow (state, PKCE verifier, nonce) and returns the realm's configured
//     cli_redirect_url, http://127.0.0.1:<port>/<path>.
//  2. Listen on exactly that address, open the IdP URL in a browser on THIS
//     machine, and wait for the IdP to send it back with ?code&state. Only the
//     configured path with this flow's state is accepted.
//  3. Login on the same node with the code and state; the node exchanges the
//     code (PKCE + client secret, which the CLI never holds), verifies the ID
//     token and mints the session. If litevirt's own second factor is required,
//     ask for it and send it with the node's oidc_pending handle.
//
// The code reaches only this machine's loopback and the node; no token is put
// in a URL or printed.
func OIDCLogin(ctx context.Context, c pb.LiteVirtClient, o OIDCLoginOptions) (*pb.LoginResponse, error) {
	if o.Out == nil {
		o.Out = io.Discard
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Minute
	}
	begin, err := c.BeginOIDCLogin(ctx, &pb.BeginOIDCLoginRequest{Realm: o.Realm, Client: "cli"})
	if err != nil {
		return nil, fmt.Errorf("begin OIDC login: %w", err)
	}
	redirect, err := url.Parse(begin.RedirectUri)
	if err != nil || redirect.Scheme != "http" || redirect.Hostname() != "127.0.0.1" || redirect.Port() == "" {
		// The daemon validates cli_redirect_url at load; refuse anything else
		// rather than listen somewhere a code should never go.
		return nil, fmt.Errorf("the node answered with redirect %q, which is not a loopback http URL", begin.RedirectUri)
	}
	ln, err := net.Listen("tcp", redirect.Host)
	if err != nil {
		return nil, fmt.Errorf("listen on %s for the identity provider's answer (cli_redirect_url): %w", redirect.Host, err)
	}
	type result struct {
		code string
		err  error
	}
	got := make(chan result, 1)
	path := redirect.Path
	if path == "" {
		path = "/"
	}
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Referrer-Policy", "no-referrer")
			if r.URL.Path != path {
				http.NotFound(w, r)
				return
			}
			q := r.URL.Query()
			// Another flow's (or a forged) answer does not end this one: the
			// real one may still arrive.
			if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(begin.State)) != 1 {
				http.Error(w, "this answer is not for the login in progress", http.StatusBadRequest)
				return
			}
			if e := q.Get("error"); e != "" {
				fmt.Fprintln(w, "The identity provider did not sign you in. You can close this window.")
				select {
				case got <- result{err: fmt.Errorf("the identity provider refused the login (%s)", sanitizeOAuthErrorCode(e))}:
				default:
				}
				return
			}
			code := q.Get("code")
			if code == "" {
				http.Error(w, "no code in the answer", http.StatusBadRequest)
				return
			}
			fmt.Fprintln(w, "Signed in to the identity provider. You can close this window and return to the terminal.")
			select {
			case got <- result{code: code}:
			default:
			}
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	fmt.Fprintf(o.Out, "Open this URL in a browser on this machine to sign in through %s:\n\n  %s\n\n", o.Realm, begin.AuthUrl)
	if o.OpenBrowser != nil {
		if err := o.OpenBrowser(begin.AuthUrl); err != nil {
			fmt.Fprintf(o.Out, "(could not open a browser: %v)\n", err)
		}
	}
	fmt.Fprintf(o.Out, "Waiting for the identity provider on %s ...\n", redirect.Host)

	wait, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	var r result
	select {
	case r = <-got:
	case <-wait.Done():
		return nil, fmt.Errorf("no answer from the identity provider within %s", o.Timeout)
	}
	if r.err != nil {
		return nil, r.err
	}

	resp, err := c.Login(ctx, &pb.LoginRequest{
		Realm:       o.Realm,
		OidcCode:    r.code,
		OidcState:   begin.State,
		OidcBinding: begin.Binding,
		UserAgent:   o.UserAgent,
	})
	if err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}
	for resp.GetRequires_2Fa() {
		if resp.GetOidcPending() == "" {
			return nil, errors.New("the node asked for a second factor but sent no handle to send it with")
		}
		if o.SecondFactor == nil {
			return nil, errors.New("the login policy requires a second factor")
		}
		code, err := o.SecondFactor()
		if err != nil {
			return nil, err
		}
		pending := resp.GetOidcPending()
		resp, err = c.Login(ctx, &pb.LoginRequest{
			Realm:       o.Realm,
			OidcPending: pending,
			TotpCode:    code,
			UserAgent:   o.UserAgent,
		})
		if err != nil {
			return nil, fmt.Errorf("2fa stage failed: %w", err)
		}
	}
	return resp, nil
}

// OpenBrowserDefault opens u with the platform's URL opener. The URL is one
// argument to the opener, never parsed by a shell.
func OpenBrowserDefault(u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	return cmd.Start()
}

func sanitizeOAuthErrorCode(e string) string {
	out := make([]rune, 0, len(e))
	for _, c := range e {
		if c == '_' || c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			out = append(out, c)
		}
		if len(out) >= 64 {
			break
		}
	}
	if len(out) == 0 {
		return "error"
	}
	return string(out)
}
