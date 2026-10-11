package fence

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// The redfish strategy powers a host off through its BMC's Redfish service
// (DMTF DSP0266): a ComputerSystem.Reset with ResetType ForceOff, then a
// PowerState read that says Off. It is the ipmi strategy over HTTPS, and it
// carries the same weight: a fence is a success, and assurance "verified",
// ONLY once the system is observed Off after the request. A BMC that accepted
// the reset proves nothing on its own.
//
// Its time budget is the ipmi strategy's, so the failover coordinator's lease
// floor (fence.WorstCasePowerOff) covers both: everything up to and including
// the reset request — the session login, the ComputerSystem discovery and the
// reset — runs inside redfishSendTimeout, the verification inside
// PowerOffVerifyTimeout, and the session logout inside redfishLogoutTimeout.
// redfishSendTimeout + redfishLogoutTimeout is ipmitoolPerCallTimeout
// (TestRedfish_BudgetFitsTheIPMIBudget).
//
// TLS is always verified: against the configured CA bundle when there is one,
// otherwise against the system roots. There is no insecure mode; the ipmi
// strategy has no TLS to turn off, so there is no equivalent to mirror. An
// http:// endpoint is refused, because the session login and basic auth both
// carry the BMC password.

// Redfish auth modes.
const (
	// RedfishAuthSession logs in through the SessionService and sends the
	// X-Auth-Token it returns; the session is deleted afterwards. The default.
	RedfishAuthSession = "session"
	// RedfishAuthBasic sends HTTP basic auth on every request.
	RedfishAuthBasic = "basic"
)

// RedfishConfig is a host's Redfish BMC configuration. Only used when the
// host's FenceStrategy is "redfish".
type RedfishConfig struct {
	// Endpoint is the BMC's base URL, https://host[:port]. The service root is
	// <Endpoint>/redfish/v1.
	Endpoint string
	User     string
	Pass     string
	// SystemID picks the ComputerSystem to power off by its Id (the last
	// segment of its @odata.id). Empty: the service must expose exactly one.
	SystemID string
	// Auth is RedfishAuthSession ("" means session) or RedfishAuthBasic.
	Auth string
	// CACert is a PEM bundle the BMC's certificate must chain to. Empty: the
	// system roots.
	CACert string
}

// Configured reports whether c names a BMC at all.
func (c RedfishConfig) Configured() bool { return c.Endpoint != "" }

const (
	// redfishSendTimeout bounds everything before verification: service root,
	// session login, system discovery, the power-state read and the reset.
	redfishSendTimeout = 6 * time.Second
	// redfishLogoutTimeout bounds the session delete after the fence.
	redfishLogoutTimeout = 2 * time.Second
	// redfishRequestTimeout bounds one HTTP request, so a BMC that accepts the
	// connection and then stops answering costs one request, not the budget.
	redfishRequestTimeout = 4 * time.Second
	// redfishMaxBody caps a response body read. A ComputerSystem is a few KiB.
	redfishMaxBody = 1 << 20
)

// ValidateRedfishConfig checks c the way a fence will use it, so a broken
// configuration is refused when it is set rather than discovered during an
// outage. An empty Endpoint is valid (nothing configured).
func ValidateRedfishConfig(c RedfishConfig) error {
	if c.Endpoint == "" {
		return nil
	}
	if _, err := redfishBaseURL(c.Endpoint); err != nil {
		return err
	}
	switch c.Auth {
	case "", RedfishAuthSession, RedfishAuthBasic:
	default:
		return fmt.Errorf("invalid redfish auth %q (valid: session, basic)", c.Auth)
	}
	if strings.ContainsAny(c.SystemID, "/?#") {
		return fmt.Errorf("invalid redfish system id %q: an Id, not a path", c.SystemID)
	}
	if c.CACert != "" {
		if _, err := redfishCAPool(c.CACert); err != nil {
			return err
		}
	}
	return nil
}

// redfishBaseURL parses an endpoint into its scheme and host. Only https, a
// host, and an empty or "/" path; no credentials, query or fragment.
func redfishBaseURL(endpoint string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return nil, fmt.Errorf("invalid redfish endpoint %q: %v", endpoint, err)
	}
	switch {
	case u.Scheme != "https":
		return nil, fmt.Errorf("invalid redfish endpoint %q: must be https:// (the BMC password crosses it)", endpoint)
	case u.Host == "" || u.Hostname() == "":
		return nil, fmt.Errorf("invalid redfish endpoint %q: no host", endpoint)
	case u.User != nil:
		return nil, fmt.Errorf("invalid redfish endpoint %q: credentials belong in the redfish user and password, not the URL", endpoint)
	case u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/"):
		return nil, fmt.Errorf("invalid redfish endpoint %q: give the base URL only, https://host[:port]", endpoint)
	}
	return &url.URL{Scheme: "https", Host: u.Host}, nil
}

func redfishCAPool(pemData string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemData)) {
		return nil, errors.New("invalid redfish CA bundle: no PEM certificate in it")
	}
	return pool, nil
}

// redfishClient is one conversation with one BMC.
type redfishClient struct {
	base    *url.URL
	http    *http.Client
	cfg     RedfishConfig
	token   string // session auth: X-Auth-Token
	session string // session auth: the session's path, for the logout
}

func newRedfishClient(cfg RedfishConfig) (*redfishClient, error) {
	if err := ValidateRedfishConfig(cfg); err != nil {
		return nil, err
	}
	if !cfg.Configured() {
		return nil, errors.New("redfish endpoint not configured on host")
	}
	base, _ := redfishBaseURL(cfg.Endpoint)
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CACert != "" {
		pool, _ := redfishCAPool(cfg.CACert)
		tlsCfg.RootCAs = pool
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	tr := &http.Transport{
		// No proxy from the environment: the fence talks to the BMC directly,
		// whatever HTTPS_PROXY the daemon inherited.
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: redfishRequestTimeout,
		MaxIdleConns:          2,
		IdleConnTimeout:       10 * time.Second,
	}
	return &redfishClient{
		base: base,
		cfg:  cfg,
		http: &http.Client{
			Transport: tr,
			Timeout:   redfishRequestTimeout,
			// Never follow a redirect: it would carry the credentials (basic
			// auth, or the session token) to wherever the BMC pointed.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (c *redfishClient) close() { c.http.CloseIdleConnections() }

// resolve turns a reference the BMC returned (@odata.id, an action target, a
// session Location) into a path on the configured endpoint. A reference to
// any other host is refused: following it would hand that host the BMC
// credentials.
func (c *redfishClient) resolve(ref string) (string, error) {
	u, err := url.Parse(ref)
	if err != nil {
		return "", fmt.Errorf("BMC returned an unparseable reference %q: %v", ref, err)
	}
	if u.IsAbs() || u.Host != "" {
		if u.Scheme != "https" || !strings.EqualFold(u.Host, c.base.Host) {
			return "", fmt.Errorf("BMC returned a reference to another host, %q; not following it", ref)
		}
	}
	p := u.EscapedPath()
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return "", fmt.Errorf("BMC returned a relative reference %q", ref)
	}
	return p, nil
}

// redact removes the password from text taken from a BMC's response.
func (c *redfishClient) redact(s string) string {
	if c.cfg.Pass != "" {
		s = strings.ReplaceAll(s, c.cfg.Pass, "***")
	}
	return s
}

// do runs one request against path and decodes a JSON reply into out.
func (c *redfishClient) do(ctx context.Context, method, p string, body, out any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	u := *c.base
	u.RawPath = p
	if dp, err := url.PathUnescape(p); err == nil {
		u.Path = dp
	} else {
		return nil, fmt.Errorf("bad path %q: %v", p, err)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("OData-Version", "4.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	switch {
	case c.cfg.Auth == RedfishAuthBasic:
		req.SetBasicAuth(c.cfg.User, c.cfg.Pass)
	case c.token != "":
		req.Header.Set("X-Auth-Token", c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %s", method, p, c.redact(err.Error()))
	}
	defer resp.Body.Close()
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, redfishMaxBody))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 300 {
			msg = msg[:300] + "..."
		}
		return resp, fmt.Errorf("%s %s: HTTP %d: %s", method, p, resp.StatusCode, c.redact(msg))
	}
	if rerr != nil {
		return resp, fmt.Errorf("%s %s: read reply: %v", method, p, rerr)
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp, fmt.Errorf("%s %s: decode reply: %v", method, p, err)
		}
	}
	return resp, nil
}

type odataRef struct {
	ID string `json:"@odata.id"`
}

type redfishServiceRoot struct {
	Systems odataRef `json:"Systems"`
	Links   struct {
		Sessions odataRef `json:"Sessions"`
	} `json:"Links"`
}

type redfishCollection struct {
	Members []odataRef `json:"Members"`
}

type redfishSystem struct {
	ID         string `json:"Id"`
	PowerState string `json:"PowerState"`
	Actions    struct {
		Reset struct {
			Target     string   `json:"target"`
			Allowable  []string `json:"ResetType@Redfish.AllowableValues"`
			ActionInfo string   `json:"@Redfish.ActionInfo"`
		} `json:"#ComputerSystem.Reset"`
	} `json:"Actions"`
}

// open reads the service root and, for session auth, logs in. It returns the
// Systems collection's path.
func (c *redfishClient) open(ctx context.Context) (string, error) {
	var root redfishServiceRoot
	if _, err := c.do(ctx, http.MethodGet, "/redfish/v1/", nil, &root); err != nil {
		return "", fmt.Errorf("service root: %w", err)
	}
	systems := "/redfish/v1/Systems"
	if root.Systems.ID != "" {
		p, err := c.resolve(root.Systems.ID)
		if err != nil {
			return "", err
		}
		systems = p
	}
	if c.cfg.Auth == RedfishAuthBasic {
		return systems, nil
	}
	sessions := "/redfish/v1/SessionService/Sessions"
	if root.Links.Sessions.ID != "" {
		p, err := c.resolve(root.Links.Sessions.ID)
		if err != nil {
			return "", err
		}
		sessions = p
	}
	resp, err := c.do(ctx, http.MethodPost, sessions,
		map[string]string{"UserName": c.cfg.User, "Password": c.cfg.Pass}, nil)
	if err != nil {
		return "", fmt.Errorf("session login: %w", err)
	}
	c.token = resp.Header.Get("X-Auth-Token")
	if c.token == "" {
		return "", errors.New("session login: the BMC returned no X-Auth-Token")
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		if p, err := c.resolve(loc); err == nil {
			c.session = p
		}
	}
	return systems, nil
}

// logout deletes the session, if there is one. Best effort: a session the
// BMC keeps expires on its own.
func (c *redfishClient) logout(ctx context.Context) {
	if c.session == "" || c.token == "" || ctx.Err() != nil {
		return
	}
	lctx, cancel := context.WithTimeout(ctx, redfishLogoutTimeout)
	defer cancel()
	if _, err := c.do(lctx, http.MethodDelete, c.session, nil, nil); err != nil {
		slog.Debug("redfish: session logout failed", "endpoint", c.base.Host, "error", err)
	}
	c.token, c.session = "", ""
}

// findSystem picks the ComputerSystem: the member whose Id is cfg.SystemID,
// or the only member when none is configured.
func (c *redfishClient) findSystem(ctx context.Context, systems string) (string, error) {
	var coll redfishCollection
	if _, err := c.do(ctx, http.MethodGet, systems, nil, &coll); err != nil {
		return "", fmt.Errorf("systems collection: %w", err)
	}
	var ids []string
	var paths []string
	for _, m := range coll.Members {
		p, err := c.resolve(m.ID)
		if err != nil {
			return "", err
		}
		id := path.Base(strings.TrimSuffix(p, "/"))
		if uid, err := url.PathUnescape(id); err == nil {
			id = uid
		}
		ids = append(ids, id)
		paths = append(paths, p)
	}
	if c.cfg.SystemID != "" {
		for i, id := range ids {
			if id == c.cfg.SystemID {
				return paths[i], nil
			}
		}
		return "", fmt.Errorf("no ComputerSystem %q on the BMC (it has %s)", c.cfg.SystemID, describeIDs(ids))
	}
	switch len(paths) {
	case 1:
		return paths[0], nil
	case 0:
		return "", errors.New("the BMC lists no ComputerSystem")
	default:
		return "", fmt.Errorf("the BMC lists %d ComputerSystems (%s); set the redfish system id to pick one",
			len(paths), describeIDs(ids))
	}
}

func describeIDs(ids []string) string {
	if len(ids) == 0 {
		return "none"
	}
	return strings.Join(ids, ", ")
}

func (c *redfishClient) system(ctx context.Context, p string) (redfishSystem, error) {
	var s redfishSystem
	_, err := c.do(ctx, http.MethodGet, p, nil, &s)
	return s, err
}

// reset posts a ComputerSystem.Reset of resetType to the system at p.
func (c *redfishClient) reset(ctx context.Context, p string, s redfishSystem, resetType string) error {
	target := p + "/Actions/ComputerSystem.Reset"
	if s.Actions.Reset.Target != "" {
		t, err := c.resolve(s.Actions.Reset.Target)
		if err != nil {
			return err
		}
		target = t
	}
	if allowed := s.Actions.Reset.Allowable; len(allowed) > 0 {
		ok := false
		for _, a := range allowed {
			if a == resetType {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("the BMC does not offer ResetType %s for this system (it offers %s)",
				resetType, strings.Join(allowed, ", "))
		}
	}
	if _, err := c.do(ctx, http.MethodPost, target, map[string]string{"ResetType": resetType}, nil); err != nil {
		return fmt.Errorf("reset %s: %w", resetType, err)
	}
	return nil
}

// redfishPowerStateOff is the one PowerState value that proves the system is
// off. "PoweringOff", null, an absent field, or anything else is not off.
const redfishPowerStateOff = "Off"

// fenceRedfish powers h off through its BMC's Redfish service and confirms it
// is off.
func fenceRedfish(ctx context.Context, h HostConfig) Result {
	cfg := h.Redfish
	if !cfg.Configured() {
		return Result{Method: "redfish", Detail: "redfish endpoint not configured on host", Success: false}
	}
	c, err := newRedfishClient(cfg)
	if err != nil {
		return Result{Method: "redfish", Detail: err.Error(), Success: false}
	}
	defer c.close()
	defer c.logout(ctx)

	slog.Info("fencing host via Redfish", "host", h.Name, "bmc", c.base.Host, "system", cfg.SystemID)

	sctx, cancel := context.WithTimeout(ctx, redfishSendTimeout)
	sysPath, sent, err := c.sendPowerOff(sctx)
	cancel()
	detail := fmt.Sprintf("redfish ForceOff %s system %s", c.base.Host, orUnknown(sysPath))
	if err != nil {
		return Result{Method: "redfish", Detail: fmt.Sprintf("%s: %v", detail, err), Success: false}
	}
	if !sent {
		detail += " (already off; not reset)"
	}

	// The reset being accepted means the BMC took the request, not that the
	// system is down. Only an observed Off proves it cannot still be writing
	// to shared storage, so an unconfirmed fence is a failure.
	verified, verifyErr := verifyRedfishPowerOff(ctx, c, sysPath)
	if !verified {
		slog.Warn("Redfish fence sent but power-off not confirmed",
			"host", h.Name, "within", PowerOffVerifyTimeout, "error", verifyErr)
		return Result{
			Method: "redfish",
			Detail: fmt.Sprintf("%s (power-off not confirmed within %s: %v)",
				detail, PowerOffVerifyTimeout, verifyErr),
			Success: false,
		}
	}
	return Result{Method: "redfish", Detail: detail + ": PowerState Off observed", Success: true}
}

func orUnknown(s string) string {
	if s == "" {
		return "(not found)"
	}
	return s
}

// sendPowerOff opens the conversation, finds the system and, unless it already
// reads Off, resets it with ForceOff. sent is false for a system that already
// read Off: a power-off of an off system is a no-op on every BMC that accepts
// it and an error on some that do not, and either way verification decides.
func (c *redfishClient) sendPowerOff(ctx context.Context) (sysPath string, sent bool, err error) {
	systems, err := c.open(ctx)
	if err != nil {
		return "", false, err
	}
	sysPath, err = c.findSystem(ctx, systems)
	if err != nil {
		return "", false, err
	}
	s, err := c.system(ctx, sysPath)
	if err != nil {
		return sysPath, false, fmt.Errorf("read system: %w", err)
	}
	if s.PowerState == redfishPowerStateOff {
		return sysPath, false, nil
	}
	if err := c.reset(ctx, sysPath, s, "ForceOff"); err != nil {
		return sysPath, false, err
	}
	return sysPath, true, nil
}

// verifyRedfishPowerOff polls the system's PowerState until it reads Off, the
// budget expires, or ctx is done. It returns (true, nil) ONLY on an Off
// reading; otherwise false and the last substantive reading, by the rule
// verifyIPMIPowerOff states: a request this function's own budget cut short is
// not a reading and does not overwrite one.
func verifyRedfishPowerOff(ctx context.Context, c *redfishClient, sysPath string) (bool, error) {
	vctx, cancel := context.WithTimeout(ctx, PowerOffVerifyTimeout)
	defer cancel()

	lastErr := errors.New("no power-state reading was taken")
	for {
		if vctx.Err() != nil {
			return false, lastErr
		}
		started := time.Now()
		s, err := c.system(vctx, sysPath)
		switch {
		case err != nil:
			if vctx.Err() != nil {
				return false, lastErr
			}
			lastErr = err
		case s.PowerState == redfishPowerStateOff:
			return true, nil
		default:
			lastErr = fmt.Errorf("system not off: PowerState %q", s.PowerState)
		}
		if wait := powerOffPollInterval - time.Since(started); wait > 0 {
			select {
			case <-vctx.Done():
				return false, lastErr
			case <-time.After(wait):
			}
		}
	}
}

// RedfishPowerState reads the PowerState of cfg's ComputerSystem.
func RedfishPowerState(ctx context.Context, cfg RedfishConfig) (string, error) {
	c, err := newRedfishClient(cfg)
	if err != nil {
		return "", err
	}
	defer c.close()
	defer c.logout(ctx)
	sctx, cancel := context.WithTimeout(ctx, redfishSendTimeout)
	defer cancel()
	systems, err := c.open(sctx)
	if err != nil {
		return "", err
	}
	p, err := c.findSystem(sctx, systems)
	if err != nil {
		return "", err
	}
	s, err := c.system(sctx, p)
	if err != nil {
		return "", err
	}
	return s.PowerState, nil
}

// RedfishPowerOn resets cfg's ComputerSystem with ResetType On. It is not part
// of any fence: nothing in the cluster powers a fenced host back on. It is the
// operator's and the lab's way back after one.
func RedfishPowerOn(ctx context.Context, cfg RedfishConfig) error {
	c, err := newRedfishClient(cfg)
	if err != nil {
		return err
	}
	defer c.close()
	defer c.logout(ctx)
	sctx, cancel := context.WithTimeout(ctx, redfishSendTimeout)
	defer cancel()
	systems, err := c.open(sctx)
	if err != nil {
		return err
	}
	p, err := c.findSystem(sctx, systems)
	if err != nil {
		return err
	}
	s, err := c.system(sctx, p)
	if err != nil {
		return err
	}
	return c.reset(sctx, p, s, "On")
}
