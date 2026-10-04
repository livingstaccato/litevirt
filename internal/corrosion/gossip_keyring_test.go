package corrosion

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"

	"github.com/litevirt/litevirt/internal/hlc"
	"github.com/litevirt/litevirt/internal/pki"
)

var allGossipModes = []GossipEncryption{
	GossipEncryptionOff, GossipEncryptionInstall, GossipEncryptionStaged, GossipEncryptionEnforced,
}

func newTestGossipKey(t *testing.T) []byte {
	t.Helper()
	k, err := pki.NewGossipKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// ─── the flag ──────────────────────────────────────────────────────────────

// enforcement.gossip_encryption is documented as a bool defaulting to false,
// with two named transition stages between. `true` must mean the END state:
// an operator who writes the obvious value gets the full guarantee, not a
// half-way house that still accepts plaintext.
func TestGossipEncryption_ParsesTheFlagValues(t *testing.T) {
	for in, want := range map[string]GossipEncryption{
		"":         GossipEncryptionOff,
		"false":    GossipEncryptionOff,
		"off":      GossipEncryptionOff,
		"install":  GossipEncryptionInstall,
		"staged":   GossipEncryptionStaged,
		"true":     GossipEncryptionEnforced,
		"enforced": GossipEncryptionEnforced,
	} {
		var got GossipEncryption
		if err := got.UnmarshalText([]byte(in)); err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != want {
			t.Errorf("%q parsed as %v, want %v", in, got, want)
		}
	}
	// A typo must stop the daemon, not quietly select some stage.
	for _, bad := range []string{"yes", "on", "enforce", "True", "1"} {
		var got GossipEncryption
		if err := got.UnmarshalText([]byte(bad)); err == nil {
			t.Errorf("%q parsed as %v; want an error", bad, got)
		}
	}
	for _, m := range allGossipModes {
		txt, err := m.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		var back GossipEncryption
		if err := back.UnmarshalText(txt); err != nil || back != m {
			t.Errorf("%v does not round-trip (%q → %v, %v)", m, txt, back, err)
		}
	}
}

// ─── the stage → memberlist mapping ─────────────────────────────────────────

func TestConfigureGossipEncryption_StageMapping(t *testing.T) {
	k := newTestGossipKey(t)
	for _, tc := range []struct {
		mode                GossipEncryption
		keyring             bool
		verifyIn, verifyOut bool
	}{
		{GossipEncryptionOff, false, false, false},
		{GossipEncryptionInstall, true, false, false},
		{GossipEncryptionStaged, true, false, true},
		{GossipEncryptionEnforced, true, true, true},
	} {
		cfg := memberlist.DefaultLANConfig()
		ring, err := configureGossipEncryption(cfg, tc.mode, GossipKeys{k})
		if err != nil {
			t.Fatalf("%v: %v", tc.mode, err)
		}
		if got := cfg.EncryptionEnabled(); got != tc.keyring {
			t.Errorf("%v: encryption enabled = %v, want %v", tc.mode, got, tc.keyring)
		}
		if tc.keyring && ring == nil {
			t.Errorf("%v: no live keyring handle returned", tc.mode)
		}
		if tc.keyring && (cfg.GossipVerifyIncoming != tc.verifyIn || cfg.GossipVerifyOutgoing != tc.verifyOut) {
			t.Errorf("%v: verify incoming/outgoing = %v/%v, want %v/%v", tc.mode,
				cfg.GossipVerifyIncoming, cfg.GossipVerifyOutgoing, tc.verifyIn, tc.verifyOut)
		}
	}
}

// A stage that needs a key and has none must refuse to start, not come up
// plaintext: "enforced, but nothing to enforce with" is the silent downgrade.
func TestConfigureGossipEncryption_RefusesAStageWithoutAKey(t *testing.T) {
	for _, m := range allGossipModes[1:] {
		if _, err := configureGossipEncryption(memberlist.DefaultLANConfig(), m, nil); err == nil {
			t.Errorf("%v with no key: accepted", m)
		}
		if _, err := configureGossipEncryption(memberlist.DefaultLANConfig(), m, GossipKeys{[]byte("short")}); err == nil {
			t.Errorf("%v with a 5-byte key: accepted", m)
		}
	}
}

// The compatibility model the operator sequence is built on. Each rolling step
// moves a node exactly one stage, so ADJACENT stages must always interoperate;
// anything two stages apart must not be assumed to.
func TestGossipStagesCompatible_AdjacentStagesOnly(t *testing.T) {
	for i, a := range allGossipModes {
		for j, b := range allGossipModes {
			want := i-j <= 1 && j-i <= 1
			if got := gossipStagesCompatible(a, b); got != want {
				t.Errorf("compatible(%v, %v) = %v, want %v", a, b, got, want)
			}
		}
	}
}

// ─── real memberlist ────────────────────────────────────────────────────────

// keyedGossipNode starts a real gossip client that binds 0.0.0.0 and advertises
// 127.0.0.1 (so auto-detection cannot quietly produce the same answer), with the
// given stage and keys, and a hosts table admitting every name in rows. A node
// that already exists has its rows before anyone joins it, so admission never
// masks what encryption does; a joiner learns its seed through bootstrap trust.
func keyedGossipNode(t *testing.T, name string, mode GossipEncryption, keys GossipKeys,
	join []string, rows ...string) *Client {
	t.Helper()
	var c *Client
	var err error
	// A port free for TCP can still be taken for UDP -- by this test's other
	// parallel nodes or by anything else on the machine -- so retry the bind.
	for attempt := 0; attempt < 8; attempt++ {
		c, err = NewClient(Config{
			HostName: name, DataDir: t.TempDir(), BindAddr: "0.0.0.0", AdvertiseAddr: "127.0.0.1",
			BindPort: freePort(t), JoinPeers: join, GossipEncryption: mode, GossipKeys: keys,
			pushPullInterval: 300 * time.Millisecond,
		}, hlc.NewClock(name))
		if err == nil || !strings.Contains(err.Error(), "address already in use") {
			break
		}
	}
	if err != nil {
		t.Fatalf("NewClient %s: %v", name, err)
	}
	once := &sync.Once{}
	gossipNodeStops.Store(c, once)
	t.Cleanup(func() { stopGossipNode(c) })
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		admitRow(t, c, r, "127.0.0.1")
	}
	return c
}

// gossipNodeStops lets a test stop a node early without its cleanup closing it
// a second time (memberlist panics on a Leave after Shutdown).
var gossipNodeStops sync.Map

func stopGossipNode(c *Client) {
	if o, ok := gossipNodeStops.Load(c); ok {
		o.(*sync.Once).Do(func() { c.Close() })
	}
}

func gossipPort(c *Client) int { return int(c.list.LocalNode().Port) }

func seedAddr(port int) string { return net.JoinHostPort("127.0.0.1", itoa(port)) }

// seesAlive reports whether c holds name as an ADMITTED member in memberlist's
// ALIVE state. Suspect does not count: a link that is failing but not yet
// declared dead is exactly what these tests must not mistake for healthy.
func seesAlive(c *Client, name string) bool {
	admitted := false
	for _, p := range c.Members() {
		if p.Name == name {
			admitted = true
		}
	}
	if !admitted {
		return false
	}
	for _, n := range c.list.Members() {
		if n.Name == name {
			return n.State == memberlist.StateAlive
		}
	}
	return false
}

// TestGossipEncryption_PairwiseMatrixOnRealMemberlist checks the compatibility
// model against memberlist itself, every ordered pair of stages: an existing
// node in stage a, a joiner in stage b, one shared key. Compatible pairs must
// converge and STAY converged past memberlist's suspicion timeout; incompatible
// pairs must never see each other at the same moment. The model is what the
// documented rollout sequence relies on, so it is not allowed to be a guess.
func TestGossipEncryption_PairwiseMatrixOnRealMemberlist(t *testing.T) {
	if testing.Short() {
		t.Skip("real gossip; ~10s")
	}
	key := newTestGossipKey(t)
	for _, a := range allGossipModes {
		for _, b := range allGossipModes {
			a, b := a, b
			t.Run(fmt.Sprintf("%v-%v", a, b), func(t *testing.T) {
				t.Parallel()
				na := keyedGossipNode(t, "node-a", a, keysFor(a, key), nil, "node-a", "node-b")
				nb := keyedGossipNode(t, "node-b", b, keysFor(b, key), []string{seedAddr(gossipPort(na))}, "node-a", "node-b")
				mutual := func() bool { return seesAlive(na, "node-b") && seesAlive(nb, "node-a") }

				if gossipStagesCompatible(a, b) {
					waitFor(t, 5*time.Second, "the pair to converge", mutual)
					// Past memberlist's LAN suspicion timeout: a pair whose probes
					// fail in one direction converges on the join and then decays.
					deadline := time.Now().Add(6 * time.Second)
					for time.Now().Before(deadline) {
						if !mutual() {
							t.Fatalf("%v and %v converged and then lost each other", a, b)
						}
						time.Sleep(100 * time.Millisecond)
					}
					return
				}
				deadline := time.Now().Add(4 * time.Second)
				for time.Now().Before(deadline) {
					if mutual() {
						t.Fatalf("%v and %v see each other; the model says they cannot", a, b)
					}
					time.Sleep(50 * time.Millisecond)
				}
			})
		}
	}
}

// encrypting reports whether memberlist is encrypting: it holds the very
// keyring pointer configureGossipEncryption handed it.
func encrypting(c *Client) bool {
	return c.gossipKeyring != nil && len(c.gossipKeyring.GetKeys()) > 0
}

func keysFor(m GossipEncryption, key []byte) GossipKeys {
	if m == GossipEncryptionOff {
		return nil
	}
	return GossipKeys{key}
}

// TestGossip_EnforcedClusterRefusesANodeWithoutTheKey is the property step 2
// exists for. The intruder is given a hosts row on every member, so ADMISSION
// would let it in — only the keyring stands between it and membership. The
// keyed control, same name and row, does join: without it, a refusal could be
// admission's doing and the test would pass for the wrong reason.
func TestGossip_EnforcedClusterRefusesANodeWithoutTheKey(t *testing.T) {
	key := newTestGossipKey(t)
	names := []string{"node-a", "node-b", "node-c", "intruder"}
	var members []*Client
	for i := range names[:3] {
		var join []string
		if i > 0 {
			join = []string{seedAddr(gossipPort(members[0]))}
		}
		members = append(members, keyedGossipNode(t, names[i], GossipEncryptionEnforced, GossipKeys{key}, join, names...))
	}
	waitFor(t, 5*time.Second, "the enforced cluster to form", func() bool {
		for _, m := range members {
			if len(m.Members()) != 2 {
				return false
			}
		}
		return true
	})

	everSeen := func(d time.Duration) bool {
		deadline := time.Now().Add(d)
		for time.Now().Before(deadline) {
			for _, m := range members {
				for _, p := range m.Members() {
					if p.Name == "intruder" {
						return true
					}
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		return false
	}

	for _, intr := range []struct {
		what string
		mode GossipEncryption
		keys GossipKeys
	}{
		{"no key at all", GossipEncryptionOff, nil},
		{"a different key", GossipEncryptionEnforced, GossipKeys{newTestGossipKey(t)}},
		{"a different key, sending plaintext", GossipEncryptionInstall, GossipKeys{newTestGossipKey(t)}},
	} {
		in := keyedGossipNode(t, "intruder", intr.mode, intr.keys,
			[]string{seedAddr(gossipPort(members[0])), seedAddr(gossipPort(members[1]))}, names...)
		if everSeen(4 * time.Second) {
			t.Fatalf("an intruder with %s became a member of an enforced cluster", intr.what)
		}
		stopGossipNode(in)
	}
	for _, m := range members[:2] { // the seeds: the intruders never learn node-c
		if m.GossipAuthRejections() == 0 {
			t.Errorf("%s dropped intruder traffic but counted no rejections", m.hostName)
		}
	}

	// Control: the same name with the cluster key is admitted.
	keyed := keyedGossipNode(t, "intruder", GossipEncryptionEnforced, GossipKeys{key},
		[]string{seedAddr(gossipPort(members[0]))}, names...)
	if !everSeen(5 * time.Second) {
		t.Fatal("control failed: a node holding the cluster key and a hosts row never joined, " +
			"so the refusals above prove nothing about the keyring")
	}
	stopGossipNode(keyed)
}

// TestGossip_EnforcedNodeAnswersAKeyedStrangerOnly pins what the live-cluster
// check (tests/e2e/gossip_keyring_test.go) relies on to tell the keyring from
// admission. An enforced node ANSWERS a join from a stranger holding the key and
// sending encrypted — memberlist sends its state before the merge delegate
// refuses the name — so a refusal of anything else is the keyring's doing. The
// sharpest of those is a stranger that HOLDS the key but sends plaintext (the
// install stage): only GossipVerifyIncoming refuses it, since it could read an
// encrypted answer. A staged node answers it.
func TestGossip_EnforcedNodeAnswersAKeyedStrangerOnly(t *testing.T) {
	key, other := newTestGossipKey(t), newTestGossipKey(t)
	type probe struct {
		ring      GossipKeys
		plaintext bool
	}
	probes := map[string]probe{
		"keyed": {GossipKeys{key}, false}, "keyed-plaintext": {GossipKeys{key}, true},
		"unkeyed": {nil, false}, "other key": {GossipKeys{other}, false},
	}
	for _, tc := range []struct {
		stage    GossipEncryption
		answered map[string]bool
	}{
		{GossipEncryptionEnforced, map[string]bool{"keyed": true, "keyed-plaintext": false, "unkeyed": false, "other key": false}},
		{GossipEncryptionStaged, map[string]bool{"keyed": true, "keyed-plaintext": true, "unkeyed": false, "other key": false}},
	} {
		name := "node-" + tc.stage.String()
		n := keyedGossipNode(t, name, tc.stage, GossipKeys{key}, nil, name)
		for what, want := range tc.answered {
			p := probes[what]
			err := probeGossipJoin(t, seedAddr(gossipPort(n)), p.ring, p.plaintext)
			if got := err == nil; got != want {
				t.Errorf("%v node: %s join answered=%v, want %v (%v)", tc.stage, what, got, want, err)
			}
		}
		if sees := memberNames(n.Members()); len(sees) != 0 {
			t.Fatalf("admission let a stranger in: %v", sees)
		}
	}
}

// probeGossipJoin is a bare memberlist stranger (no hosts row anywhere) joining
// peer. plaintext keeps the keyring but sends unencrypted, as the install stage
// does. It returns the join error: nil means the peer answered.
func probeGossipJoin(t *testing.T, peer string, ring GossipKeys, plaintext bool) error {
	t.Helper()
	cfg := memberlist.DefaultLANConfig()
	cfg.Name, cfg.BindAddr, cfg.BindPort = "stranger", "127.0.0.1", 0
	cfg.LogOutput = io.Discard
	if ring != nil {
		kr, err := memberlist.NewKeyring(nil, ring[0])
		if err != nil {
			t.Fatal(err)
		}
		cfg.Keyring = kr
		if plaintext {
			cfg.GossipVerifyIncoming, cfg.GossipVerifyOutgoing = false, false
		}
	}
	ml, err := memberlist.Create(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ml.Shutdown()
	_, err = ml.Join([]string{peer})
	return err
}

// TestSetGossipKeys_LiveRotationKeepsMembership walks the three rotation phases
// on a live enforced cluster — no restart — and requires every pair to stay
// alive throughout. It then shows why the phases exist: promoting a key on ONE
// node before the others hold it cuts that node off.
func TestSetGossipKeys_LiveRotationKeepsMembership(t *testing.T) {
	old, next := newTestGossipKey(t), newTestGossipKey(t)
	names := []string{"node-a", "node-b", "node-c"}
	var ns []*Client
	for i := range names {
		var join []string
		if i > 0 {
			join = []string{seedAddr(gossipPort(ns[0]))}
		}
		ns = append(ns, keyedGossipNode(t, names[i], GossipEncryptionEnforced, GossipKeys{old}, join, names...))
	}
	allAlive := func() bool {
		for i, a := range ns {
			for j := range ns {
				if i != j && !seesAlive(a, names[j]) {
					return false
				}
			}
		}
		return true
	}
	waitFor(t, 5*time.Second, "the cluster to form", allAlive)

	var mu sync.Mutex
	lost := ""
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
			if !allAlive() {
				mu.Lock()
				lost = "membership lost mid-rotation"
				mu.Unlock()
			}
		}
	}()
	for _, phase := range []GossipKeys{{old, next}, {next, old}, {next}} {
		for _, n := range ns {
			if err := n.SetGossipKeys(phase); err != nil {
				t.Fatal(err)
			}
			time.Sleep(700 * time.Millisecond) // nodes adopt a phase at different moments
		}
		time.Sleep(2 * time.Second)
	}
	close(stop)
	<-done
	if lost != "" {
		t.Fatal(lost)
	}
	for _, n := range ns {
		if s := n.GossipKeyring(); s.Primary != pki.GossipKeyID(next) || len(s.Keys) != 1 {
			t.Fatalf("%s ended on %+v, want only the new key", n.hostName, s)
		}
	}

	// The hazard: node-c jumps to a key nobody else holds.
	other := newTestGossipKey(t)
	if err := ns[2].SetGossipKeys(GossipKeys{other}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 15*time.Second, "node-c to be cut off by a key its peers do not hold", func() bool {
		return !seesAlive(ns[0], "node-c") && !seesAlive(ns[1], "node-c")
	})
}

func TestSetGossipKeys_Refusals(t *testing.T) {
	k := newTestGossipKey(t)
	on := keyedGossipNode(t, "node-a", GossipEncryptionEnforced, GossipKeys{k}, nil)
	for what, keys := range map[string]GossipKeys{
		"empty":     nil,
		"short key": {[]byte("0123456789abcdef")},
		"duplicate": {k, k},
	} {
		if err := on.SetGossipKeys(keys); err == nil {
			t.Errorf("%s keyring accepted", what)
		}
		if s := on.GossipKeyring(); s.Primary != pki.GossipKeyID(k) || len(s.Keys) != 1 {
			t.Fatalf("a refused %s keyring still changed the live one: %+v", what, s)
		}
	}
	// Off has no keyring to change, and must not grow one mid-run: encryption
	// switching on under a running node is a stage change, which is a restart.
	off := keyedGossipNode(t, "node-b", GossipEncryptionOff, nil, nil)
	if err := off.SetGossipKeys(GossipKeys{k}); err == nil {
		t.Fatal("an off node accepted a live keyring")
	}
	if encrypting(off) {
		t.Fatal("an off node is encrypting")
	}
}

// ─── the key never leaves the process ───────────────────────────────────────

func TestGossipKeys_NeverFormatted(t *testing.T) {
	k := newTestGossipKey(t)
	keys := GossipKeys{k}
	cfg := Config{HostName: "n", GossipEncryption: GossipEncryptionEnforced, GossipKeys: keys}
	var logBuf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&logBuf, nil))
	lg.Info("cfg", "keys", keys, "cfg", cfg)
	j, _ := json.Marshal(cfg)
	out := strings.Join([]string{
		fmt.Sprintf("%v", keys), fmt.Sprintf("%+v", keys), fmt.Sprintf("%#v", keys),
		fmt.Sprintf("%s", keys), fmt.Sprintf("%x", keys), fmt.Sprintf("%q", keys),
		fmt.Sprintf("%v", cfg), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg),
		logBuf.String(), string(j),
	}, "\n")
	for _, enc := range []string{
		base64.StdEncoding.EncodeToString(k), hex.EncodeToString(k), string(k),
		fmt.Sprint([]byte(k)), fmt.Sprintf("%#v", []byte(k)),
	} {
		if strings.Contains(out, enc) || strings.Contains(out, enc[:len(enc)/2]) {
			t.Fatalf("key material formatted:\n%s", out)
		}
	}
	if !strings.Contains(fmt.Sprint(keys), pki.GossipKeyID(k)) {
		t.Errorf("formatted keyring should name its key IDs, got %v", keys)
	}
}

// ─── the file watcher ───────────────────────────────────────────────────────

func readState(t *testing.T, path string) pki.GossipKeyringState {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := pki.ParseGossipKeyringState(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func waitState(t *testing.T, path string, what string, ok func(pki.GossipKeyringState) bool) {
	t.Helper()
	waitFor(t, 5*time.Second, what, func() bool {
		b, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		s, err := pki.ParseGossipKeyringState(b)
		return err == nil && ok(s)
	})
}

// The watcher is how a rotation reaches a running daemon without a restart. It
// adopts a changed file, reports what it is USING (not what the file says), and
// never lets a bad or missing file take a key away: dropping to an empty
// keyring would switch memberlist to plaintext on the spot.
func TestWatchGossipKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath, statePath := filepath.Join(dir, pki.GossipKeyName), filepath.Join(dir, pki.GossipKeyringStateName)
	k1, k2 := newTestGossipKey(t), newTestGossipKey(t)
	if err := pki.WriteGossipKeyring(keyPath, [][]byte{k1}); err != nil {
		t.Fatal(err)
	}
	c := keyedGossipNode(t, "node-a", GossipEncryptionStaged, GossipKeys{k1}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.WatchGossipKeyFile(ctx, keyPath, statePath, 20*time.Millisecond)

	waitState(t, statePath, "the initial state", func(s pki.GossipKeyringState) bool {
		return s.Mode == "staged" && s.Primary == pki.GossipKeyID(k1)
	})

	if err := pki.WriteGossipKeyring(keyPath, [][]byte{k1, k2}); err != nil {
		t.Fatal(err)
	}
	waitState(t, statePath, "the second key", func(s pki.GossipKeyringState) bool {
		return s.Primary == pki.GossipKeyID(k1) && len(s.Keys) == 2 && s.Keys[1] == pki.GossipKeyID(k2)
	})
	if got := c.GossipKeyring(); len(got.Keys) != 2 {
		t.Fatalf("state says two keys but the live keyring has %v", got.Keys)
	}

	for what, bad := range map[string]func() error{
		"corrupt": func() error { return os.WriteFile(keyPath, []byte("garbage\n"), 0o600) },
		"loose":   func() error { return os.Chmod(keyPath, 0o644) },
		"missing": func() error { return os.Remove(keyPath) },
	} {
		if err := pki.WriteGossipKeyring(keyPath, [][]byte{k1, k2}); err != nil {
			t.Fatal(err)
		}
		if err := bad(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
		if got := c.GossipKeyring(); len(got.Keys) != 2 || got.Primary != pki.GossipKeyID(k1) {
			t.Fatalf("a %s key file changed the live keyring to %+v", what, got)
		}
		if !encrypting(c) {
			t.Fatalf("a %s key file switched gossip to plaintext", what)
		}
	}
}

func TestWatchGossipKeyFile_OffReportsOffAndLoadsNothing(t *testing.T) {
	dir := t.TempDir()
	keyPath, statePath := filepath.Join(dir, pki.GossipKeyName), filepath.Join(dir, pki.GossipKeyringStateName)
	if err := pki.WriteGossipKeyring(keyPath, [][]byte{newTestGossipKey(t)}); err != nil {
		t.Fatal(err)
	}
	c := keyedGossipNode(t, "node-a", GossipEncryptionOff, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.WatchGossipKeyFile(ctx, keyPath, statePath, 20*time.Millisecond)
	waitState(t, statePath, "an off state", func(s pki.GossipKeyringState) bool { return s.Mode == "off" })
	time.Sleep(100 * time.Millisecond)
	if s := readState(t, statePath); s.Primary != "" || len(s.Keys) != 0 {
		t.Fatalf("off node reports keys: %+v", s)
	}
	if encrypting(c) {
		t.Fatal("an off node loaded the key file")
	}
}

// TestWatchGossipKeyFile_ReorderedSecondariesSettle: memberlist keeps its own
// secondary order — AddKey appends — so a node live on [A,B] that loads a file
// reading [A,C,B] ends up on [A,B,C]. Secondary order is not semantics (every
// installed key is tried on receipt; only the primary encrypts), so the watcher
// must treat that as loaded. Comparing in order re-applied the file and logged
// "gossip keyring reloaded" on every tick, forever.
//
// Mutation: compare the ID lists in order (the old sameKeyIDs) — the reload
// count climbs with every tick and this goes red.
func TestWatchGossipKeyFile_ReorderedSecondariesSettle(t *testing.T) {
	buf := &syncBuf{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	dir := t.TempDir()
	keyPath, statePath := filepath.Join(dir, pki.GossipKeyName), filepath.Join(dir, pki.GossipKeyringStateName)
	a, b, c3 := newTestGossipKey(t), newTestGossipKey(t), newTestGossipKey(t)
	if err := pki.WriteGossipKeyring(keyPath, [][]byte{a, b}); err != nil {
		t.Fatal(err)
	}
	c := keyedGossipNode(t, "node-a", GossipEncryptionStaged, GossipKeys{a, b}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.WatchGossipKeyFile(ctx, keyPath, statePath, 10*time.Millisecond)
	waitState(t, statePath, "the initial state", func(s pki.GossipKeyringState) bool { return len(s.Keys) == 2 })

	if err := pki.WriteGossipKeyring(keyPath, [][]byte{a, c3, b}); err != nil {
		t.Fatal(err)
	}
	waitState(t, statePath, "the third key", func(s pki.GossipKeyringState) bool { return len(s.Keys) == 3 })
	time.Sleep(300 * time.Millisecond) // ~30 ticks
	if n := buf.count("gossip keyring reloaded"); n != 1 {
		t.Fatalf("the watcher reloaded %d times for one file change; live %v never matches the file's order",
			n, c.GossipKeyring().Keys)
	}
	if got := c.GossipKeyring(); got.Primary != pki.GossipKeyID(a) || len(got.Keys) != 3 {
		t.Fatalf("live keyring %+v, want primary %s and three keys", got, pki.GossipKeyID(a))
	}
}
