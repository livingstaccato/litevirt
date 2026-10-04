package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/ssh"
)

// The cluster gossip key travels the way ca.crt does: this machine (the one
// that ran `lv host init`, and so holds the CA) keeps the canonical copy in its
// PKI directory and pushes it to each host's /etc/litevirt/pki over SSH. See
// internal/corrosion/gossip_keyring.go for what the daemon does with it.

const (
	remoteGossipKeyPath   = "/etc/litevirt/pki/" + pki.GossipKeyName
	remoteGossipStatePath = "/etc/litevirt/pki/" + pki.GossipKeyringStateName
)

// GossipKeyHost is one cluster host as the gossip-key commands see it. The
// production implementation is SSH; tests substitute hosts that model the
// daemon's reload.
type GossipKeyHost interface {
	Name() string
	// ReadKeyFile returns the host's gossip.key; present is false when it has none.
	ReadKeyFile(ctx context.Context) (data []byte, present bool, err error)
	// WriteKeyFile atomically replaces the host's gossip.key, 0600.
	WriteKeyFile(ctx context.Context, data []byte) error
	// LiveKeyring returns what the host's daemon reports it is USING; present
	// is false when there is no state file (a build without gossip keyrings,
	// or a daemon that has never started).
	LiveKeyring(ctx context.Context) (state pki.GossipKeyringState, present bool, err error)
}

// GossipKeyOptions tunes the rotation's pacing.
type GossipKeyOptions struct {
	Out io.Writer
	// Grace is how long the old key stays accepted after every host has
	// stopped encrypting with it, before it is removed.
	Grace time.Duration
	// Timeout bounds each barrier: how long every host gets to load a phase.
	Timeout time.Duration
	// Poll is how often a barrier re-reads each host's state.
	Poll time.Duration
}

func (o GossipKeyOptions) withDefaults() GossipKeyOptions {
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Minute
	}
	if o.Poll <= 0 {
		o.Poll = 2 * time.Second
	}
	return o
}

// isLive reports whether a host's daemon is running a keyring the rotation
// must wait on. Off hosts and hosts with no state file load whatever file is
// current when they next start, so there is nothing to confirm.
func isLive(s pki.GossipKeyringState, present bool) bool {
	return present && s.Mode != "off" && s.Mode != ""
}

// describeLive says what a host's gossip is doing on the wire, from its stage.
// The state file's primary is the keyring's first key at every stage but off —
// install included, where the host holds it but still SENDS PLAINTEXT — so the
// sending half comes from the stage, never from the presence of a primary
// (colonelpanik/litevirt#259). The stage table is corrosion/gossip_keyring.go's.
func describeLive(s pki.GossipKeyringState, present bool) string {
	keys := strings.Join(s.Keys, ",")
	switch {
	case !present:
		return "no state file (daemon not running this build, or not started)"
	case s.Mode == "off":
		return "off (gossip plaintext; key file ignored)"
	case s.Mode == "install":
		return fmt.Sprintf("install, sending plaintext, accepting plaintext and %s, %d rejected", keys, s.Rejected)
	case s.Mode == "staged":
		return fmt.Sprintf("staged, encrypting with %s, accepting plaintext and %s, %d rejected", s.Primary, keys, s.Rejected)
	case s.Mode == "enforced":
		return fmt.Sprintf("enforced, encrypting with %s, accepting only %s, %d rejected", s.Primary, keys, s.Rejected)
	default:
		// A stage this CLI does not know (a newer daemon): report the file,
		// claim nothing about the wire.
		return fmt.Sprintf("%s (stage unknown to this lv), primary key %s, keys %s, %d rejected",
			s.Mode, s.Primary, keys, s.Rejected)
	}
}

type surveyed struct {
	host    GossipKeyHost
	file    [][]byte // parsed key file; nil when absent
	present bool
	live    pki.GossipKeyringState
	hasLive bool
}

// survey reads every host's key file and live state, failing on the first host
// it cannot read. Both commands survey before writing anything, so an
// unreachable host refuses the whole operation rather than leaving the cluster
// with some hosts changed.
func survey(ctx context.Context, hosts []GossipKeyHost) ([]surveyed, error) {
	out := make([]surveyed, 0, len(hosts))
	for _, h := range hosts {
		data, present, err := h.ReadKeyFile(ctx)
		if err != nil {
			return nil, fmt.Errorf("read %s on %s: %w (nothing has been changed on any host)", remoteGossipKeyPath, h.Name(), err)
		}
		s := surveyed{host: h, present: present}
		if present {
			if s.file, err = pki.ParseGossipKeyring(data); err != nil {
				return nil, fmt.Errorf("%s on %s: %w (nothing has been changed on any host)", remoteGossipKeyPath, h.Name(), err)
			}
		}
		if s.live, s.hasLive, err = h.LiveKeyring(ctx); err != nil {
			return nil, fmt.Errorf("read %s on %s: %w (nothing has been changed on any host)", remoteGossipStatePath, h.Name(), err)
		}
		out = append(out, s)
	}
	return out, nil
}

func sameRing(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// InstallGossipKey gives every host the cluster gossip key, minting it into
// localPath first if this machine has none. It never replaces a key a host
// already holds: daemons reload gossip.key live, so overwriting the key of a
// host that is using one is a partition. Changing keys is RotateGossipKey.
//
// It changes nothing on the wire. A host starts using the key only when its
// enforcement.gossip_encryption moves off false and it restarts.
func InstallGossipKey(ctx context.Context, localPath string, hosts []GossipKeyHost, opt GossipKeyOptions) error {
	opt = opt.withDefaults()
	st, err := survey(ctx, hosts)
	if err != nil {
		return err
	}

	ring, err := pki.LoadGossipKeyring(localPath)
	switch {
	case os.IsNotExist(err):
		for _, s := range st {
			if s.present {
				return fmt.Errorf("%s has no gossip key, but %s already holds %s: the cluster has one. "+
					"Run this from the machine that installed it, or copy that machine's %s here (mode 0600)",
					localPath, s.host.Name(), strings.Join(pki.GossipKeyIDs(s.file), ","), pki.GossipKeyName)
			}
		}
		k, err := pki.NewGossipKey()
		if err != nil {
			return err
		}
		ring = [][]byte{k}
		if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
			return fmt.Errorf("create PKI dir: %w", err)
		}
		if err := pki.WriteGossipKeyring(localPath, ring); err != nil {
			return fmt.Errorf("write %s: %w", localPath, err)
		}
		fmt.Fprintf(opt.Out, "Minted cluster gossip key %s into %s\n", pki.GossipKeyID(k), localPath)
	case err != nil:
		return err
	}

	var conflicts []string
	for _, s := range st {
		if s.present && !sameRing(s.file, ring) {
			conflicts = append(conflicts, fmt.Sprintf("%s holds %s", s.host.Name(), strings.Join(pki.GossipKeyIDs(s.file), ",")))
		}
	}
	if len(conflicts) > 0 {
		return fmt.Errorf("refusing to replace a gossip key a host already holds (this machine has %s): %s. "+
			"A daemon reloads gossip.key live, so replacing a key in use cuts that host off; "+
			"nothing has been changed on any host",
			strings.Join(pki.GossipKeyIDs(ring), ","), strings.Join(conflicts, "; "))
	}

	data := pki.FormatGossipKeyring(ring)
	for _, s := range st {
		if s.present {
			fmt.Fprintf(opt.Out, "  %-20s already holds %s — %s\n", s.host.Name(),
				strings.Join(pki.GossipKeyIDs(ring), ","), describeLive(s.live, s.hasLive))
			continue
		}
		if err := s.host.WriteKeyFile(ctx, data); err != nil {
			return fmt.Errorf("push %s to %s: %w", pki.GossipKeyName, s.host.Name(), err)
		}
		fmt.Fprintf(opt.Out, "  %-20s installed %s — %s\n", s.host.Name(),
			strings.Join(pki.GossipKeyIDs(ring), ","), describeLive(s.live, s.hasLive))
	}
	fmt.Fprintln(opt.Out, "Every host holds the gossip key. Nothing changes on the wire until each host's")
	fmt.Fprintln(opt.Out, "enforcement.gossip_encryption moves off false, one rolling restart per stage:")
	fmt.Fprintln(opt.Out, "install, then staged, then true — each finished on EVERY host before the next")
	fmt.Fprintln(opt.Out, "(docs/auth.md, \"Gossip encryption\"). Re-run this command to see each host's stage.")
	return nil
}

// RotateGossipKey replaces the cluster gossip key on every host, live, without
// a partition at any instant.
//
// memberlist encrypts with the keyring's primary and decrypts with any key in
// it. So a new key must be held by EVERY host before ANY host encrypts with
// it, and every host must have stopped encrypting with the old key before any
// host drops it. That is three fleet-wide phases, each confirmed on every live
// host (by the state file its daemon writes after it has loaded the keyring,
// not merely after the file landed) before the next begins:
//
//  1. [old, new]  the new key is accepted everywhere; old still encrypts
//  2. [new, old]  the new key encrypts; the old one is still accepted
//     ...grace...
//  3. [new]       the old key is gone
//
// Doing it in two — "add the new key as primary, then remove the old" — cuts
// off every host that has not yet loaded the new key for as long as it takes to
// get there, which is a partition the failure detector acts on.
//
// localPath is updated at the start of each phase, so it is always the target
// of the phase in flight. That makes a re-run after any interruption safe: it
// first puts every host on localPath's keyring (every host already holds that
// keyring's primary, which is checked), then settles on the primary alone —
// finishing an interrupted phase 2 or 3, or rolling back an interrupted phase
// 1 — and stops, asking for another run to rotate afresh.
func RotateGossipKey(ctx context.Context, localPath string, hosts []GossipKeyHost, opt GossipKeyOptions) error {
	opt = opt.withDefaults()
	local, err := pki.LoadGossipKeyring(localPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("%s does not exist: rotation runs from the machine holding the cluster's gossip key; "+
			"a cluster without one needs `lv host install-gossip-key` first", localPath)
	}
	if err != nil {
		return err
	}
	st, err := survey(ctx, hosts)
	if err != nil {
		return err
	}
	primary := pki.GossipKeyID(local[0])
	for _, s := range st {
		if isLive(s.live, s.hasLive) && !containsID(s.live.Keys, primary) {
			return fmt.Errorf("%s is live on %s but does not hold this machine's primary gossip key %s, so "+
				"any keyring pushed from here would cut it off; nothing has been changed on any host. "+
				"Put this machine's %s back on the host that differs, or run from the machine that holds the "+
				"key the cluster is using", s.host.Name(), strings.Join(s.live.Keys, ","), primary, localPath)
		}
	}

	// Resync: every host to the local keyring. A clean cluster is already
	// there; a run that finds any host elsewhere is finishing an interrupted
	// rotation. Safe because every live host holds local[0].
	interrupted := len(local) > 1
	for _, s := range st {
		if !s.present || !sameRing(s.file, local) || (isLive(s.live, s.hasLive) && !pki.SameGossipKeyring(s.live.Keys, pki.GossipKeyIDs(local))) {
			interrupted = true
		}
	}
	if err := pushPhase(ctx, st, local, "resync to "+idList(local), opt); err != nil {
		return err
	}
	if interrupted {
		if len(local) > 1 {
			settled := local[:1]
			if err := pki.WriteGossipKeyring(localPath, settled); err != nil {
				return err
			}
			if err := pushPhase(ctx, st, settled, "settle on "+primary, opt); err != nil {
				return err
			}
		}
		fmt.Fprintf(opt.Out, "Hosts were not all on %s's keyring, which is what an interrupted rotation (or an\n", localPath)
		fmt.Fprintf(opt.Out, "install that missed a host) leaves. That is settled: every host now uses only %s.\n", primary)
		fmt.Fprintln(opt.Out, "It may be the new key or the old one, depending on where a rotation stopped; run it again")
		fmt.Fprintln(opt.Out, "to rotate to a fresh key.")
		return nil
	}

	old := local[0]
	next, err := pki.NewGossipKey()
	if err != nil {
		return err
	}
	fmt.Fprintf(opt.Out, "Rotating the cluster gossip key %s -> %s on %d hosts\n",
		pki.GossipKeyID(old), pki.GossipKeyID(next), len(st))
	phases := []struct {
		ring [][]byte
		what string
	}{
		{[][]byte{old, next}, "phase 1/3: accept the new key everywhere"},
		{[][]byte{next, old}, "phase 2/3: encrypt with the new key"},
		{[][]byte{next}, "phase 3/3: drop the old key"},
	}
	for i, ph := range phases {
		if i == 2 && opt.Grace > 0 {
			fmt.Fprintf(opt.Out, "every host encrypts with %s; keeping %s accepted for %s\n",
				pki.GossipKeyID(next), pki.GossipKeyID(old), opt.Grace)
			select {
			case <-ctx.Done():
				return fmt.Errorf("interrupted during the grace period; the cluster is safe on %s — re-run "+
					"`lv host rotate-gossip-key` to finish: %w", idList(ph.ring), ctx.Err())
			case <-time.After(opt.Grace):
			}
		}
		if err := pki.WriteGossipKeyring(localPath, ph.ring); err != nil {
			return fmt.Errorf("record %s in %s: %w", ph.what, localPath, err)
		}
		if err := pushPhase(ctx, st, ph.ring, ph.what, opt); err != nil {
			return err
		}
	}
	fmt.Fprintf(opt.Out, "Rotated: every host now uses only %s; %s is retired. %s holds the new key.\n",
		pki.GossipKeyID(next), pki.GossipKeyID(old), localPath)
	return nil
}

// pushPhase writes ring to every host whose file differs and then waits until
// every live host reports it as its live keyring.
func pushPhase(ctx context.Context, st []surveyed, ring [][]byte, what string, opt GossipKeyOptions) error {
	data := pki.FormatGossipKeyring(ring)
	wrote := 0
	for i := range st {
		if st[i].present && sameRing(st[i].file, ring) {
			continue
		}
		if err := st[i].host.WriteKeyFile(ctx, data); err != nil {
			return fmt.Errorf("%s: push to %s: %w — the cluster is safe as it stands; fix the host and "+
				"re-run `lv host rotate-gossip-key`", what, st[i].host.Name(), err)
		}
		st[i].file, st[i].present = ring, true
		wrote++
	}
	if wrote == 0 {
		// Nothing moved, but a live host may still be on an older keyring than
		// its file (a reload in flight): the barrier below covers that too.
		fmt.Fprintf(opt.Out, "%s: every host already has %s\n", what, idList(ring))
	} else {
		fmt.Fprintf(opt.Out, "%s: wrote %s to %d host(s)\n", what, idList(ring), wrote)
	}
	return waitLive(ctx, st, ring, what, opt)
}

// waitLive is the barrier: every live host must report ring as the keyring it
// is USING — the same primary and the same keys. Secondary order is the
// daemon's (memberlist's), not the file's, so it is not compared.
func waitLive(ctx context.Context, st []surveyed, ring [][]byte, what string, opt GossipKeyOptions) error {
	want := pki.GossipKeyIDs(ring)
	deadline := time.Now().Add(opt.Timeout)
	for i := range st {
		for {
			s, present, err := st[i].host.LiveKeyring(ctx)
			if err == nil {
				st[i].live, st[i].hasLive = s, present
				if !isLive(s, present) || pki.SameGossipKeyring(s.Keys, want) {
					break
				}
			}
			if time.Now().After(deadline) {
				last := describeLive(st[i].live, st[i].hasLive)
				if err != nil {
					last = err.Error()
				}
				return fmt.Errorf("%s: %s did not load %s within %s (last seen: %s). The cluster is safe "+
					"as it stands — no later phase has started. Check the daemon on %s "+
					"(journalctl -u litevirt), then re-run `lv host rotate-gossip-key` to finish",
					what, st[i].host.Name(), strings.Join(want, ","), opt.Timeout, last, st[i].host.Name())
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("%s: interrupted waiting for %s; re-run `lv host rotate-gossip-key` to "+
					"finish: %w", what, st[i].host.Name(), ctx.Err())
			case <-time.After(opt.Poll):
			}
		}
	}
	return nil
}

func containsID(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func idList(ring [][]byte) string { return "[" + strings.Join(pki.GossipKeyIDs(ring), ",") + "]" }

// ─── SSH ────────────────────────────────────────────────────────────────────

const noGossipFileSentinel = "__LV_NO_GOSSIP_FILE__"

type sshGossipKeyHost struct {
	name string
	sc   *ssh.Client
}

func (h *sshGossipKeyHost) Name() string { return h.name }

func (h *sshGossipKeyHost) readOptional(path string) ([]byte, bool, error) {
	// Same shape as remoteConfigProbe: absent is a positive answer, and an
	// unreadable file is an error rather than an empty one.
	out, err := h.sc.RunOutput(fmt.Sprintf("if [ -e %s ]; then cat -- %s; else printf '%%s' '%s'; fi",
		ssh.ShellQuote(path), ssh.ShellQuote(path), noGossipFileSentinel))
	if err != nil {
		return nil, false, err
	}
	if string(out) == noGossipFileSentinel {
		return nil, false, nil
	}
	return out, true, nil
}

func (h *sshGossipKeyHost) ReadKeyFile(context.Context) ([]byte, bool, error) {
	return h.readOptional(remoteGossipKeyPath)
}

func (h *sshGossipKeyHost) WriteKeyFile(_ context.Context, data []byte) error {
	if err := h.sc.Run("mkdir -p /etc/litevirt/pki"); err != nil {
		return err
	}
	// On stdin, to a temp file renamed into place: the key never appears on a
	// command line, and the daemon's reload never reads a half-written file.
	return h.sc.WriteFile(remoteGossipKeyPath, data, 0o600)
}

func (h *sshGossipKeyHost) LiveKeyring(context.Context) (pki.GossipKeyringState, bool, error) {
	data, present, err := h.readOptional(remoteGossipStatePath)
	if err != nil || !present {
		return pki.GossipKeyringState{}, false, err
	}
	s, err := pki.ParseGossipKeyringState(data)
	return s, err == nil, err
}

// SSHGossipKeyHosts connects to every cluster host as sshUser@address. The
// returned close func closes every connection.
func SSHGossipKeyHosts(ctx context.Context, c pb.LiteVirtClient, sshUser string) ([]GossipKeyHost, func(), error) {
	resp, err := c.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		return nil, nil, fmt.Errorf("list hosts: %w", err)
	}
	if sshUser == "" {
		sshUser = "root"
	}
	var hosts []GossipKeyHost
	var conns []*ssh.Client
	closeAll := func() {
		for _, sc := range conns {
			sc.Close()
		}
	}
	for _, h := range resp.Hosts {
		if h.Address == "" {
			closeAll()
			return nil, nil, fmt.Errorf("host %s has no recorded address to reach it on", h.Name)
		}
		sc, err := ssh.NewClient(sshUser + "@" + h.Address)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("SSH to %s (%s@%s): %w — every host must be reachable, or the "+
				"cluster would be left with some hosts on a different keyring", h.Name, sshUser, h.Address, err)
		}
		conns = append(conns, sc)
		hosts = append(hosts, &sshGossipKeyHost{name: h.Name, sc: sc})
	}
	if len(hosts) == 0 {
		return nil, nil, fmt.Errorf("the cluster lists no hosts")
	}
	return hosts, closeAll, nil
}
