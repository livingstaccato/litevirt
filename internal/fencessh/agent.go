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
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
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
// a connection from every one of peers. The reason says why not. err is an
// evaluation that could not be made (sshd -T did not run), which is no answer.
type AcceptingFunc func(ctx context.Context, peers []string) (ok bool, why string, err error)

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
	// ReevaluateTimeout bounds one Reevaluate (ReevaluateTimeout when zero).
	ReevaluateTimeout time.Duration
	// SelfCheck: before publishing that it accepts the managed key, the host
	// logs in to its own sshd over it (its own key, rendered for its own
	// address, and a check request), so the claim is about the RUNNING sshd,
	// not about its configuration files. The daemon sets it; a fleet node,
	// which has no sshd, does not.
	SelfCheck bool
	// OnAccepting is told, after every publish, what the host published:
	// the daemon raises the fence_ssh_not_accepting health condition from it.
	OnAccepting func(ctx context.Context, accepting, everAccepting bool, detail string)
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
	acceptErr   error
	acceptPeers string
	acceptUntil time.Time
	// lastErr is the last publish or render failure, for the status read.
	lastErr string
	probes  map[string]ProbeResult
	// syncMu serialises Sync.
	syncMu sync.Mutex
	// reeval coalesces Reevaluate's fresh syncs (reevaluate.go).
	reeval reevalQueue
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

// RowFreshAfter is how long after a change to a host's sshd its own row is
// expected to reflect an sshd evaluation that began after the change, while
// its agent syncs on schedule: an evaluation in flight at the change (its
// self-check bounded by probeTimeout) stands for acceptTTL, the next sync
// starts within RenderInterval, and its own evaluation and publish take about
// probeTimeout. It is an estimate, not a bound: the sshd -T calls, the
// replicated write and a sync that overruns its tick are not bounded. `lv
// host install-fence-ssh` counts no row it read sooner, and no row from an
// agent whose last sync failed.
const RowFreshAfter = probeTimeout + acceptTTL + RenderInterval + probeTimeout

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
	// The probe runs on its own: a peer that blackholes its checks must not
	// hold this host's rendering and publishing back.
	if a.cfg.ProbeInterval > 0 {
		go func() {
			pt := time.NewTicker(a.cfg.ProbeInterval)
			defer pt.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-pt.C:
					a.ProbeAll(ctx)
				}
			}
		}()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			a.syncLogged(ctx)
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
		return a.render(nil, nil)
	}

	peers, rejected, err := a.verifiedPeers(ctx, tr)
	if err != nil {
		return err
	}
	for host, why := range rejected {
		slog.Warn("fence ssh: a peer's row did not verify; it is not rendered", "peer", host, "why", why)
	}
	// Rendered first: the self-check before a publish logs in over the file.
	if err := a.render(peers, a.selfEntry(self)); err != nil {
		return err
	}
	if a.cfg.Gate == nil || !a.cfg.Gate.ReleaseFeatureAvailable(capabilities.FeatureFenceSSH) {
		return nil
	}
	// enforcement.fence_ssh: legacy never makes the FIRST publication, so the
	// release feature stays unused and a rollback below release_2026_12_v1
	// stays possible. A row this host already published is still maintained
	// (the feature is used anyway): left frozen, a renewal's revocation would
	// stay owed, a revoked or expired certificate would leave the host
	// unfenceable, and a new sshd host key would fail every fence of it.
	if a.Mode() == ModeLegacy && !a.hasOwnRow(ctx, self, tr) {
		return nil
	}
	return a.publish(ctx, self, selfSigner, peers, tr)
}

// selfEntry is this host's own key, accepted from its own certificate
// address, for the self-check (Config.SelfCheck); nil without one.
func (a *Agent) selfEntry(self *x509.Certificate) *Verified {
	if !a.cfg.SelfCheck {
		return nil
	}
	addr, err := FenceAddress(self)
	if err != nil {
		return nil
	}
	fk, err := a.ownFenceKey()
	if err != nil {
		return nil
	}
	return &Verified{Host: a.cfg.Self, FenceKeys: []ssh.PublicKey{fk}, Addr: addr}
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
		// An expired certificate still pins its host's sshd keys for a fence
		// of it (Verify), but grants no inbound authority: its fence key is
		// not accepted here until the host is renewed.
		if v.Expired {
			rejected[r.HostName] = "its certificate expired " + v.NotAfter.UTC().Format(time.RFC3339) +
				"; its fence key is not accepted until it is renewed"
			continue
		}
		out = append(out, v)
	}
	return out, rejected, nil
}

// render writes peers' keys and pins, and self's own key (for the
// self-check) when self is not nil.
func (a *Agent) render(peers []*Verified, self *Verified) error {
	keys := peers
	if self != nil {
		keys = append(append([]*Verified(nil), peers...), self)
	}
	if _, err := writeIfChanged(filepath.Join(a.cfg.Dir, AuthorizedKeysName), AuthorizedKeys(a.cfg.Dir, keys), 0o644); err != nil {
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
// from addrs: its configuration (Accepting) and, with SelfCheck, the running
// sshd itself. err is an evaluation that could not be made.
func (a *Agent) sshdAccepting(ctx context.Context, addrs []string, self *x509.Certificate) (bool, string, error) {
	key := strings.Join(addrs, ",")
	fresh := freshSyncOf(ctx)
	a.mu.Lock()
	if fresh == nil && key == a.acceptPeers && time.Now().Before(a.acceptUntil) {
		ok, why, err := a.accepting, a.acceptWhy, a.acceptErr
		a.mu.Unlock()
		return ok, why, err
	}
	a.mu.Unlock()
	ok, why, err := false, "no sshd evaluation is wired", error(nil)
	if a.cfg.Accepting != nil {
		ok, why, err = a.cfg.Accepting(ctx, addrs)
	}
	if ok && err == nil && a.cfg.SelfCheck {
		if serr := a.selfCheck(ctx, self); serr != nil {
			ok, why = false, "sshd's configuration reads the managed key, but the running sshd does not accept it "+
				"(reload or restart sshd): "+serr.Error()
		}
	}
	a.mu.Lock()
	a.accepting, a.acceptWhy, a.acceptErr, a.acceptPeers, a.acceptUntil = ok, why, err, key, time.Now().Add(acceptTTL)
	a.mu.Unlock()
	fresh.evaluated(err)
	return ok, why, err
}

// selfCheck logs in to this host's own sshd over the managed key: its own
// key (rendered for its own address), its own sshd keys pinned, from its own
// certificate address, with a check request its forced command answers
// without arming.
func (a *Agent) selfCheck(ctx context.Context, self *x509.Certificate) error {
	addr, err := FenceAddress(self)
	if err != nil {
		return err
	}
	hostKeys, err := readHostKeys(a.cfg.HostKeyGlob)
	if err != nil {
		return err
	}
	keys, err := parseKeys(hostKeys, "sshd host key")
	if err != nil {
		return err
	}
	port := 22
	if h, herr := corrosion.GetHost(ctx, a.cfg.DB, a.cfg.Self); herr == nil && h != nil && h.SSHPort != 0 {
		port = h.SSHPort
	}
	cctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	return fence.ProbeSSH(cctx, fence.HostConfig{Name: a.cfg.Self, Address: addr.String(), SSHPort: port,
		SSH: fence.SSHFence{Path: fence.SSHPathManaged, KnownHosts: KnownHostsLines(&Verified{Host: a.cfg.Self, HostKeys: keys}),
			HostKeyAlias: Alias(a.cfg.Self), IdentityFile: filepath.Join(a.cfg.Dir, KeyName), BindAddress: addr.String(),
			User: a.cfg.SSHUser, Request: CheckRequest(a.cfg.Self)}}, CheckOK)
}

// publish writes this host's row when anything in it changed.
//
// A host whose certificate names no single fence address, or is not valid
// now, publishes nothing: its peers keep fencing it the legacy way, unpinned
// (`lv doctor fence` warns), rather than refuse a row that could never verify.
func (a *Agent) publish(ctx context.Context, self *x509.Certificate, signer crypto.Signer, peers []*Verified, tr Trust) error {
	selfAddr, addrErr := FenceAddress(self)
	if addrErr != nil {
		slog.Warn("fence ssh: publishing no row: this host's certificate gives it no fence address", "why", addrErr)
		return nil
	}
	if now := time.Now(); now.Before(self.NotBefore) || now.After(self.NotAfter) {
		slog.Warn("fence ssh: publishing no row: this host's certificate is not valid now",
			"not_before", self.NotBefore, "not_after", self.NotAfter)
		return nil
	}
	fk, err := a.ownFenceKey()
	if err != nil {
		return fmt.Errorf("fence key: %w", err)
	}
	hostKeys, err := readHostKeys(a.cfg.HostKeyGlob)
	if err != nil {
		return err
	}
	accepting, why, evalErr := a.sshdAccepting(ctx, a.peerAddresses(ctx, peers, selfAddr), self)
	if accepting {
		why = ""
	}
	certPEM := string(pemCert(self))

	prev, havePrev, err := corrosion.GetHostFenceSSH(ctx, a.cfg.DB, a.cfg.Self)
	if err != nil {
		return err
	}
	// The previous row counts only when this host signed it under its
	// current certificate or the one that certificate renewed: a row another
	// node wrote under its name, or a removed machine's under the same name,
	// carries nothing over.
	ours := havePrev && !prev.Deleted && a.ownLineage(prev, self, tr)
	// evalReport is what this sync returns once the row is published (or
	// already current): nil, or why sshd could not be evaluated.
	var evalReport error
	if evalErr != nil {
		// No answer is not "no": keep what was published, and say why.
		accepting = ours && prev.Accepting
		why = "sshd could not be evaluated: " + evalErr.Error()
		if accepting {
			why = ""
		}
		// The sync still fails, so the agent's last_error shows it: a row
		// carried over is not a fresh answer (`lv doctor fence` warns, and
		// `lv host install-fence-ssh` does not confirm it).
		evalReport = fmt.Errorf("sshd could not be evaluated, so this host's row keeps accepting=%v from before: %w",
			accepting, evalErr)
	}
	p := Publication{
		HostName: a.cfg.Self, Generation: 1, FencePubkeys: KeyLine(fk), SSHDHostkeys: hostKeys,
		Accepting: accepting, Detail: why, CertPEM: certPEM,
	}
	high := a.generationHighWater()
	if ours {
		p.Generation = prev.Generation
		if prev.FencePubkeys != p.FencePubkeys || prev.SSHDHostkeys != p.SSHDHostkeys {
			p.Generation++
		}
		p.EverAccepting = prev.EverAccepting
	}
	// Never below a generation this host published before: a replay of an
	// older row of its own does not set the count back.
	if p.Generation < high || (!ours && p.Generation <= high) {
		p.Generation = high + 1
	}
	p.EverAccepting = p.EverAccepting || accepting
	if a.cfg.OnAccepting != nil {
		a.cfg.OnAccepting(ctx, p.Accepting, p.EverAccepting, p.Detail)
	}
	if ours && PublicationOf(prev) == p {
		if _, err := Verify(prev, tr); err == nil {
			freshSyncOf(ctx).published()
			return evalReport
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
	a.setGenerationHighWater(p.Generation)
	freshSyncOf(ctx).published()
	slog.Info("fence ssh: published this host's row", "generation", p.Generation, "accepting", accepting,
		"detail", why, "serial", strings.ToLower(self.SerialNumber.Text(16)))
	return evalReport
}

// hasOwnRow reports whether this host holds a live row it published itself
// (ownLineage).
func (a *Agent) hasOwnRow(ctx context.Context, self *x509.Certificate, tr Trust) bool {
	prev, ok, err := corrosion.GetHostFenceSSH(ctx, a.cfg.DB, a.cfg.Self)
	return err == nil && ok && !prev.Deleted && a.ownLineage(prev, self, tr)
}

// ownLineage reports whether prev was signed by this host under its current
// certificate or under the one its current certificate renewed.
func (a *Agent) ownLineage(prev corrosion.HostFenceSSHRow, self *x509.Certificate, tr Trust) bool {
	if _, err := Verify(prev, Trust{Roots: tr.Roots}); err != nil {
		return false
	}
	cert, err := pki.ParseCertPEM([]byte(prev.CertPEM))
	if err != nil {
		return false
	}
	got := strings.ToLower(cert.SerialNumber.Text(16))
	if got == strings.ToLower(self.SerialNumber.Text(16)) {
		return true
	}
	from, ok := pki.RenewedFromSerial(self)
	return ok && strings.EqualFold(from, got)
}

// generationFile records the highest generation this host has published.
const generationFile = "generation"

func (a *Agent) generationHighWater() int64 {
	raw, err := os.ReadFile(filepath.Join(a.cfg.Dir, generationFile))
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func (a *Agent) setGenerationHighWater(n int64) {
	if n <= a.generationHighWater() {
		return
	}
	if _, err := writeIfChanged(filepath.Join(a.cfg.Dir, generationFile), []byte(strconv.FormatInt(n, 10)+"\n"), 0o644); err != nil {
		slog.Warn("fence ssh: could not record the published generation", "error", err)
	}
}
