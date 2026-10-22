package fencessh

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// Gate is the release-feature gate a row is written through: the daemon's
// grpcapi.Server.
type Gate interface {
	ReleaseFeatureAvailable(feature capabilities.Feature) bool
	WithReleaseFeature(ctx context.Context, feature capabilities.Feature,
		write func(context.Context, capabilities.FeatureGrant) error) error
}

// AcceptingFunc reports whether this host's sshd reads Dir/authorized_keys
// for root, with public-key authentication on and root login not refused, for
// a connection from every one of peers. The reason says why not.
type AcceptingFunc func(ctx context.Context, peers []string) (bool, string)

// Config is an Agent's wiring.
type Config struct {
	Self   string
	PKIDir string
	DB     *corrosion.Client
	Gate   Gate
	// Dir holds the rendered files (DefaultDir); HostKeyGlob names this host's
	// sshd public keys (DefaultHostKeyGlob).
	Dir         string
	HostKeyGlob string
	// Accepting is SSHDAccepting in production.
	Accepting AcceptingFunc
	// Mode is enforcement.fence_ssh: managed, auto (default) or legacy.
	Mode func() string
	// SSHUser is the account a managed fence logs in as: root, except in a
	// test's unprivileged sshd.
	SSHUser string
	// ProbeInterval is how often every peer's managed path is checked; zero
	// or less disables the probe.
	ProbeInterval time.Duration
	// SyncInterval is how often Run syncs (RenderInterval when zero).
	SyncInterval time.Duration
}

// Agent publishes this host's row, renders its peers' verified rows, resolves
// how a fence reaches a target, and probes every peer's managed path.
type Agent struct {
	cfg Config

	mu sync.Mutex
	// accepting is the last sshd evaluation, for acceptPeers, until
	// acceptUntil.
	accepting   bool
	acceptWhy   string
	acceptPeers string
	acceptUntil time.Time
	// lastErr is the last publish or render failure, for the status read.
	lastErr string
	probes  map[string]ProbeResult
	// syncMu serialises Sync.
	syncMu sync.Mutex
}

// ProbeResult is one peer's last managed-path check.
type ProbeResult struct {
	OK     bool
	Detail string
	At     time.Time
}

// New returns an Agent; unset paths take their defaults.
func New(cfg Config) *Agent {
	if cfg.Dir == "" {
		cfg.Dir = DefaultDir
	}
	if cfg.HostKeyGlob == "" {
		cfg.HostKeyGlob = DefaultHostKeyGlob
	}
	if cfg.SSHUser == "" {
		cfg.SSHUser = "root"
	}
	if cfg.Mode == nil {
		cfg.Mode = func() string { return ModeAuto }
	}
	return &Agent{cfg: cfg, probes: map[string]ProbeResult{}}
}

// Modes of enforcement.fence_ssh.
const (
	ModeManaged = "managed"
	ModeAuto    = "auto"
	ModeLegacy  = "legacy"
)

// NormalizeMode is mode as the agent reads it: "" is auto; anything else
// unknown is refused at config load (ValidMode).
func NormalizeMode(mode string) string {
	switch m := strings.ToLower(strings.TrimSpace(mode)); m {
	case ModeManaged, ModeLegacy:
		return m
	default:
		return ModeAuto
	}
}

// ValidMode reports whether mode is a value enforcement.fence_ssh takes.
func ValidMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", ModeManaged, ModeAuto, ModeLegacy:
		return true
	}
	return false
}

// Dir is where the agent's files live.
func (a *Agent) Dir() string { return a.cfg.Dir }

// Mode is the agent's current mode.
func (a *Agent) Mode() string { return NormalizeMode(a.cfg.Mode()) }

// RenderInterval is how often Run re-renders (and republishes when anything
// it publishes changed). A replicated change of a peer's row, of a host or of
// the CRL is picked up on the next tick.
const RenderInterval = 30 * time.Second

// acceptTTL is how long an sshd evaluation stands for an unchanged peer set:
// `lv host install-fence-ssh` waits for the next one.
const acceptTTL = time.Minute

// Run syncs at once, then every RenderInterval, and probes every
// ProbeInterval, until ctx ends.
func (a *Agent) Run(ctx context.Context) {
	a.syncLogged(ctx)
	every := a.cfg.SyncInterval
	if every <= 0 {
		every = RenderInterval
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	var probe <-chan time.Time
	if a.cfg.ProbeInterval > 0 {
		pt := time.NewTicker(a.cfg.ProbeInterval)
		defer pt.Stop()
		probe = pt.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			a.syncLogged(ctx)
		case <-probe:
			a.ProbeAll(ctx)
		}
	}
}

func (a *Agent) syncLogged(ctx context.Context) {
	if err := a.Sync(ctx); err != nil && ctx.Err() == nil {
		slog.Warn("fence ssh: sync failed", "error", err)
	}
}

// Sync publishes this host's row when anything it publishes changed (once
// the release feature is available) and renders every verified peer into
// authorized_keys and known_hosts. A host whose own certificate is revoked,
// or whose row is removed, renders no peer at all: a machine taken out of the
// cluster stops trusting it.
func (a *Agent) Sync(ctx context.Context) error {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()
	err := a.sync(ctx)
	a.mu.Lock()
	a.lastErr = ""
	if err != nil {
		a.lastErr = err.Error()
	}
	a.mu.Unlock()
	return err
}

func (a *Agent) sync(ctx context.Context) error {
	if err := os.MkdirAll(a.cfg.Dir, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(a.cfg.Dir, 0o755); err != nil {
		return err
	}
	if _, err := writeIfChanged(filepath.Join(a.cfg.Dir, CommandName), ForcedCommand(a.cfg.Self), 0o755); err != nil {
		return fmt.Errorf("write the forced command: %w", err)
	}
	tr, err := TrustFromPKIDir(a.cfg.PKIDir)
	if err != nil {
		return err
	}
	self, selfSigner, err := a.ownIdentity()
	if err != nil {
		return err
	}
	if out, why := a.outOfCluster(ctx, self, tr); out {
		slog.Warn("fence ssh: this host is out of the cluster; trusting no peer's fence key", "why", why)
		return a.render(nil)
	}

	peers, rejected, err := a.verifiedPeers(ctx, tr)
	if err != nil {
		return err
	}
	for host, why := range rejected {
		slog.Warn("fence ssh: a peer's row did not verify; it is not rendered", "peer", host, "why", why)
	}
	var pubErr error
	if a.cfg.Gate != nil && a.cfg.Gate.ReleaseFeatureAvailable(capabilities.FeatureFenceSSH) {
		pubErr = a.publish(ctx, self, selfSigner, peers, tr)
	}
	return errors.Join(pubErr, a.render(peers))
}

// ownIdentity is the certificate and key this host serves, which follows a
// renewal (pki.ServedHostKeyPair).
func (a *Agent) ownIdentity() (*x509.Certificate, crypto.Signer, error) {
	pair, err := pki.ServedHostKeyPair(a.cfg.PKIDir)
	if err != nil {
		return nil, nil, fmt.Errorf("read this host's identity: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, nil, errors.New("this host's identity has no certificate")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("this host's key is %T, not a signer", pair.PrivateKey)
	}
	return cert, signer, nil
}

// outOfCluster reports whether this host's certificate is revoked or its
// host row removed.
func (a *Agent) outOfCluster(ctx context.Context, self *x509.Certificate, tr Trust) (bool, string) {
	if tr.Revoked != nil && tr.Revoked(self.SerialNumber) {
		return true, "its certificate " + self.SerialNumber.Text(16) + " is revoked"
	}
	rows, err := a.cfg.DB.Query(ctx, `SELECT deleted_at FROM hosts WHERE name = ?`, a.cfg.Self)
	if err == nil && len(rows) == 1 && rows[0].String("deleted_at") != "" {
		return true, "its host row is removed"
	}
	return false, ""
}

// verifiedPeers is every live peer's verified row, and why each other row
// was refused.
func (a *Agent) verifiedPeers(ctx context.Context, tr Trust) ([]*Verified, map[string]string, error) {
	hosts, err := corrosion.ListHosts(ctx, a.cfg.DB)
	if err != nil {
		return nil, nil, err
	}
	live := map[string]bool{}
	for _, h := range hosts {
		live[h.Name] = true
	}
	rows, err := corrosion.ListHostFenceSSH(ctx, a.cfg.DB)
	if err != nil {
		return nil, nil, err
	}
	var out []*Verified
	rejected := map[string]string{}
	for _, r := range rows {
		if r.HostName == a.cfg.Self || !live[r.HostName] || r.Deleted {
			continue
		}
		v, err := Verify(r, tr)
		if err != nil {
			rejected[r.HostName] = err.Error()
			continue
		}
		out = append(out, v)
	}
	return out, rejected, nil
}

// render writes peers' keys and pins.
func (a *Agent) render(peers []*Verified) error {
	if _, err := writeIfChanged(filepath.Join(a.cfg.Dir, AuthorizedKeysName), AuthorizedKeys(a.cfg.Dir, peers), 0o644); err != nil {
		return fmt.Errorf("write authorized_keys: %w", err)
	}
	if _, err := writeIfChanged(filepath.Join(a.cfg.Dir, KnownHostsName), KnownHosts(peers), 0o644); err != nil {
		return fmt.Errorf("write known_hosts: %w", err)
	}
	return nil
}

// ownFenceKey is this host's fence key, generated on first use. The private
// half never leaves the host.
func (a *Agent) ownFenceKey() (ssh.PublicKey, error) {
	path := filepath.Join(a.cfg.Dir, KeyName)
	if raw, err := os.ReadFile(path); err == nil {
		s, err := ssh.ParsePrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		return s.PublicKey(), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	priv, pub, err := NewFenceKey()
	if err != nil {
		return nil, err
	}
	if _, err := writeIfChanged(path, priv, 0o600); err != nil {
		return nil, err
	}
	if _, err := writeIfChanged(path+".pub", []byte(KeyLine(pub)+" litevirt-fence:"+a.cfg.Self+"\n"), 0o644); err != nil {
		return nil, err
	}
	slog.Info("fence ssh: generated this host's fence key", "path", path)
	return pub, nil
}

// peerAddresses are the addresses sshd must accept a fence from: every
// verified peer's certificate address, and every other live host's recorded
// IPv4 address (a peer that has not published yet). With no peer, this
// host's own address stands in.
func (a *Agent) peerAddresses(ctx context.Context, peers []*Verified, self net.IP) []string {
	set := map[string]bool{}
	for _, v := range peers {
		set[v.Addr.String()] = true
	}
	if hosts, err := corrosion.ListHosts(ctx, a.cfg.DB); err == nil {
		for _, h := range hosts {
			if h.Name == a.cfg.Self {
				continue
			}
			if ip := net.ParseIP(h.Address).To4(); ip != nil && !ip.IsLoopback() {
				set[ip.String()] = true
			}
		}
	}
	if len(set) == 0 && self != nil {
		set[self.String()] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// sshdAccepting evaluates (or reuses) whether sshd accepts the fence key
// from addrs.
func (a *Agent) sshdAccepting(ctx context.Context, addrs []string) (bool, string) {
	key := strings.Join(addrs, ",")
	a.mu.Lock()
	if key == a.acceptPeers && time.Now().Before(a.acceptUntil) {
		ok, why := a.accepting, a.acceptWhy
		a.mu.Unlock()
		return ok, why
	}
	a.mu.Unlock()
	ok, why := false, "no sshd evaluation is wired"
	if a.cfg.Accepting != nil {
		ok, why = a.cfg.Accepting(ctx, addrs)
	}
	a.mu.Lock()
	a.accepting, a.acceptWhy, a.acceptPeers, a.acceptUntil = ok, why, key, time.Now().Add(acceptTTL)
	a.mu.Unlock()
	return ok, why
}

// publish writes this host's row when anything in it changed.
func (a *Agent) publish(ctx context.Context, self *x509.Certificate, signer crypto.Signer, peers []*Verified, tr Trust) error {
	fk, err := a.ownFenceKey()
	if err != nil {
		return fmt.Errorf("fence key: %w", err)
	}
	hostKeys, err := readHostKeys(a.cfg.HostKeyGlob)
	if err != nil {
		return err
	}
	selfAddr, addrErr := FenceAddress(self)
	accepting, why := false, ""
	if addrErr != nil {
		why = addrErr.Error()
	} else {
		accepting, why = a.sshdAccepting(ctx, a.peerAddresses(ctx, peers, selfAddr))
	}
	if accepting {
		why = ""
	}
	certPEM := string(pemCert(self))

	prev, havePrev, err := corrosion.GetHostFenceSSH(ctx, a.cfg.DB, a.cfg.Self)
	if err != nil {
		return err
	}
	p := Publication{
		HostName: a.cfg.Self, Generation: 1, FencePubkeys: KeyLine(fk), SSHDHostkeys: hostKeys,
		Accepting: accepting, Detail: why, CertPEM: certPEM,
	}
	if havePrev && !prev.Deleted {
		p.Generation = prev.Generation
		if prev.FencePubkeys != p.FencePubkeys || prev.SSHDHostkeys != p.SSHDHostkeys {
			p.Generation++
		}
		// The never-downgrade bit comes from the replicated row, and only
		// from one this host signed: a row another node wrote under this
		// host's name cannot clear it, nor a renewal (the predecessor
		// certificate may be revoked by now, so revocation is not checked
		// here).
		if _, err := Verify(prev, Trust{Roots: tr.Roots}); err == nil {
			p.EverAccepting = prev.EverAccepting
		}
	}
	p.EverAccepting = p.EverAccepting || accepting
	if havePrev && !prev.Deleted && PublicationOf(prev) == p {
		if _, err := Verify(prev, tr); err == nil {
			return nil
		}
	}
	row, err := Sign(p, signer)
	if err != nil {
		return err
	}
	err = a.cfg.Gate.WithReleaseFeature(ctx, capabilities.FeatureFenceSSH,
		func(ctx context.Context, g capabilities.FeatureGrant) error {
			return corrosion.PutHostFenceSSH(ctx, a.cfg.DB, g, row)
		})
	if err != nil {
		return fmt.Errorf("publish this host's fence ssh row: %w", err)
	}
	slog.Info("fence ssh: published this host's row", "generation", p.Generation, "accepting", accepting,
		"detail", why, "serial", strings.ToLower(self.SerialNumber.Text(16)))
	return nil
}
