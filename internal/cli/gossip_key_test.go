package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

// fakeKeyWorld is a cluster of fake hosts that checks, every time any host's
// LIVE keyring changes, the one invariant a rotation must never break: every
// live host can decrypt what every other live host encrypts with. That is the
// pairwise "your primary is in my keyring" condition — memberlist tries every
// installed key on receipt and encrypts with the primary only.
type fakeKeyWorld struct {
	mu         sync.Mutex
	hosts      []*fakeKeyHost
	violations []string
}

func (w *fakeKeyWorld) checkLocked() {
	for _, a := range w.hosts {
		for _, b := range w.hosts {
			if a == b || !a.liveMode() || !b.liveMode() {
				continue
			}
			if !containsKey(b.live, a.live[0]) {
				w.violations = append(w.violations, fmt.Sprintf("%s encrypts with %s, which %s does not hold (%v)",
					a.name, pki.GossipKeyID(a.live[0]), b.name, pki.GossipKeyIDs(b.live)))
			}
		}
	}
}

func containsKey(ring [][]byte, k []byte) bool {
	for _, r := range ring {
		if bytes.Equal(r, k) {
			return true
		}
	}
	return false
}

type fakeKeyHost struct {
	world *fakeKeyWorld
	name  string
	mode  string // "" = no state file (daemon never wrote one)
	file  []byte // nil = no key file
	live  [][]byte
	// lag is how many LiveKeyring polls a newly written file waits before the
	// "daemon" loads it — hosts reload at different moments, as they do in
	// production. -1 never loads (a daemon that is down).
	lag, pending int
	fileDirty    bool
	unreachable  bool
	writes       [][]string // key IDs of every file written, in order
	// memberlistOrder loads a file the way the daemon's memberlist keyring
	// does — keys it lacks are appended, the primary moved to the front,
	// keys the file dropped removed — so the live secondary order can differ
	// from the file's. Off, the fake loads the file's order verbatim.
	memberlistOrder bool
}

func (h *fakeKeyHost) liveMode() bool { return h.mode != "" && h.mode != "off" && len(h.live) > 0 }

func (h *fakeKeyHost) Name() string { return h.name }

func (h *fakeKeyHost) ReadKeyFile(context.Context) ([]byte, bool, error) {
	h.world.mu.Lock()
	defer h.world.mu.Unlock()
	if h.unreachable {
		return nil, false, errors.New("ssh: connect: no route to host")
	}
	if h.file == nil {
		return nil, false, nil
	}
	return append([]byte(nil), h.file...), true, nil
}

func (h *fakeKeyHost) WriteKeyFile(_ context.Context, data []byte) error {
	h.world.mu.Lock()
	defer h.world.mu.Unlock()
	if h.unreachable {
		return errors.New("ssh: connect: no route to host")
	}
	h.file = append([]byte(nil), data...)
	keys, _ := pki.ParseGossipKeyring(data)
	h.writes = append(h.writes, pki.GossipKeyIDs(keys))
	h.fileDirty, h.pending = true, h.lag
	h.maybeLoadLocked()
	return nil
}

func (h *fakeKeyHost) maybeLoadLocked() {
	if !h.fileDirty || h.mode == "" || h.mode == "off" || h.pending != 0 {
		return
	}
	keys, err := pki.ParseGossipKeyring(h.file)
	if err != nil {
		return
	}
	if h.memberlistOrder && len(h.live) > 0 && len(keys) > 0 {
		next := append([][]byte(nil), h.live...)
		for _, k := range keys {
			if !containsKey(next, k) {
				next = append(next, k)
			}
		}
		ordered := [][]byte{keys[0]}
		for _, k := range next {
			if !bytes.Equal(k, keys[0]) && containsKey(keys, k) {
				ordered = append(ordered, k)
			}
		}
		keys = ordered
	}
	h.live, h.fileDirty = keys, false
	h.world.checkLocked()
}

func (h *fakeKeyHost) LiveKeyring(context.Context) (pki.GossipKeyringState, bool, error) {
	h.world.mu.Lock()
	defer h.world.mu.Unlock()
	if h.unreachable {
		return pki.GossipKeyringState{}, false, errors.New("ssh: connect: no route to host")
	}
	if h.pending > 0 {
		h.pending--
	}
	h.maybeLoadLocked()
	if h.mode == "" {
		return pki.GossipKeyringState{}, false, nil
	}
	return pki.NewGossipKeyringState(h.mode, h.live, 0), true, nil
}

// newKeyWorld builds hosts that all run mode with the file and live keyring
// set to ring. lags gives each host's reload lag.
func newKeyWorld(t *testing.T, mode string, ring [][]byte, lags ...int) (*fakeKeyWorld, []GossipKeyHost) {
	t.Helper()
	w := &fakeKeyWorld{}
	var hs []GossipKeyHost
	for i, lag := range lags {
		h := &fakeKeyHost{world: w, name: fmt.Sprintf("node-%d", i+1), mode: mode, lag: lag}
		if ring != nil {
			h.file = pki.FormatGossipKeyring(ring)
			if mode != "off" {
				h.live = ring
			}
		}
		w.hosts = append(w.hosts, h)
		hs = append(hs, h)
	}
	return w, hs
}

func testKey(t *testing.T) []byte {
	t.Helper()
	k, err := pki.NewGossipKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func fastOpts() GossipKeyOptions {
	return GossipKeyOptions{Out: io.Discard, Grace: time.Millisecond, Timeout: 2 * time.Second, Poll: time.Millisecond}
}

func writeLocal(t *testing.T, ring [][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), pki.GossipKeyName)
	if err := pki.WriteGossipKeyring(path, ring); err != nil {
		t.Fatal(err)
	}
	return path
}

// ─── rotate ─────────────────────────────────────────────────────────────────

// TestRotateGossipKey_NeverSplitsTheCluster is the rotation's whole contract:
// at no instant does any live host encrypt under a key another live host does
// not hold, even with hosts reloading at very different moments. It ends with
// every host, and the local copy, on one fresh key.
func TestRotateGossipKey_NeverSplitsTheCluster(t *testing.T) {
	old := testKey(t)
	local := writeLocal(t, [][]byte{old})
	w, hosts := newKeyWorld(t, "enforced", [][]byte{old}, 0, 3, 0, 7)

	if err := RotateGossipKey(context.Background(), local, hosts, fastOpts()); err != nil {
		t.Fatal(err)
	}
	if len(w.violations) > 0 {
		t.Fatalf("the rotation split the cluster:\n  %s", strings.Join(w.violations, "\n  "))
	}
	got, err := pki.LoadGossipKeyring(local)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || bytes.Equal(got[0], old) {
		t.Fatalf("local keyring after rotation is %v, want one new key", pki.GossipKeyIDs(got))
	}
	for _, h := range w.hosts {
		if len(h.live) != 1 || !bytes.Equal(h.live[0], got[0]) {
			t.Fatalf("%s is live on %v, want only %s", h.name, pki.GossipKeyIDs(h.live), pki.GossipKeyID(got[0]))
		}
	}
	// Three phases, in order: new key accepted, then used, then the old one dropped.
	oldID, newID := pki.GossipKeyID(old), pki.GossipKeyID(got[0])
	want := [][]string{{oldID, newID}, {newID, oldID}, {newID}}
	for _, h := range w.hosts {
		if fmt.Sprint(h.writes) != fmt.Sprint(want) {
			t.Fatalf("%s saw writes %v, want %v", h.name, h.writes, want)
		}
	}
}

// A host whose daemon is down still holds a stale state file. The rotation
// must stop at that phase's barrier — never run ahead into a phase that would
// cut the host off when it comes back — and say which host and what to do.
func TestRotateGossipKey_StopsAtTheBarrierForAHostThatNeverLoads(t *testing.T) {
	old := testKey(t)
	local := writeLocal(t, [][]byte{old})
	w, hosts := newKeyWorld(t, "enforced", [][]byte{old}, 0, -1, 0)

	err := RotateGossipKey(context.Background(), local, hosts, fastOpts())
	if err == nil || !strings.Contains(err.Error(), "node-2") || !strings.Contains(err.Error(), "rotate-gossip-key") {
		t.Fatalf("got %v, want a barrier timeout naming node-2 and how to resume", err)
	}
	for _, h := range w.hosts {
		if len(h.writes) != 1 {
			t.Fatalf("%s got %d writes; the rotation ran past its first barrier", h.name, len(h.writes))
		}
	}
	if len(w.violations) > 0 {
		t.Fatalf("split: %v", w.violations)
	}
}

// Re-running after an interruption settles on the local primary, safely, from
// any mix of half-applied phases, and says so — it does not go on to rotate
// again unasked.
func TestRotateGossipKey_SettlesAnInterruptedRotation(t *testing.T) {
	p, n := testKey(t), testKey(t)
	for name, tc := range map[string]struct {
		local [][]byte
		live  [][][]byte
		want  []byte
	}{
		// Interrupted in phase 2: local says "n is primary", hosts are mixed.
		"mid-promote": {[][]byte{n, p}, [][][]byte{{n, p}, {p, n}, {n, p}}, n},
		// Interrupted in phase 1: some hosts never got the new key.
		"mid-install": {[][]byte{p, n}, [][][]byte{{p, n}, {p}, {p}}, p},
		// Interrupted in phase 3: some hosts already dropped the old key.
		"mid-remove": {[][]byte{n}, [][][]byte{{n}, {n, p}, {n, p}}, n},
	} {
		t.Run(name, func(t *testing.T) {
			local := writeLocal(t, tc.local)
			w := &fakeKeyWorld{}
			var hosts []GossipKeyHost
			for i, live := range tc.live {
				h := &fakeKeyHost{world: w, name: fmt.Sprintf("node-%d", i+1), mode: "enforced",
					file: pki.FormatGossipKeyring(live), live: live, lag: i}
				w.hosts = append(w.hosts, h)
				hosts = append(hosts, h)
			}
			var out bytes.Buffer
			opt := fastOpts()
			opt.Out = &out
			if err := RotateGossipKey(context.Background(), local, hosts, opt); err != nil {
				t.Fatal(err)
			}
			if len(w.violations) > 0 {
				t.Fatalf("settling split the cluster: %v", w.violations)
			}
			for _, h := range w.hosts {
				if len(h.live) != 1 || !bytes.Equal(h.live[0], tc.want) {
					t.Fatalf("%s live on %v, want only %s", h.name, pki.GossipKeyIDs(h.live), pki.GossipKeyID(tc.want))
				}
			}
			if !strings.Contains(out.String(), "run it again") {
				t.Fatalf("output does not tell the operator the rotation itself still needs a run:\n%s", out.String())
			}
		})
	}
}

// TestRotateGossipKey_BarrierAcceptsReorderedSecondaries: a daemon live on
// [A,B] that loads a file reading [A,C,B] reports [A,B,C] — memberlist appends
// a key it adds. That is the file's keyring (same primary, same keys), so the
// barrier must pass; comparing in order waited out the timeout on a host that
// had loaded everything.
//
// Mutation: compare the barrier's IDs in order — RotateGossipKey times out at
// the resync barrier and this goes red.
func TestRotateGossipKey_BarrierAcceptsReorderedSecondaries(t *testing.T) {
	a, b, c := testKey(t), testKey(t), testKey(t)
	local := writeLocal(t, [][]byte{a, c, b})
	w, hosts := newKeyWorld(t, "enforced", [][]byte{a, b}, 0, 1)
	for _, h := range w.hosts {
		h.memberlistOrder = true
	}
	opt := fastOpts()
	opt.Timeout = 300 * time.Millisecond
	if err := RotateGossipKey(context.Background(), local, hosts, opt); err != nil {
		t.Fatalf("a host on the file's keyring, secondaries in memberlist's order, failed the barrier: %v", err)
	}
	if len(w.violations) > 0 {
		t.Fatalf("rotation split the cluster: %v", w.violations)
	}
}

// Refusals happen before anything is written.
func TestRotateGossipKey_Refusals(t *testing.T) {
	p := testKey(t)
	t.Run("host unreachable", func(t *testing.T) {
		w, hosts := newKeyWorld(t, "enforced", [][]byte{p}, 0, 0, 0)
		w.hosts[2].unreachable = true
		err := RotateGossipKey(context.Background(), writeLocal(t, [][]byte{p}), hosts, fastOpts())
		if err == nil || !strings.Contains(err.Error(), "node-3") {
			t.Fatalf("got %v", err)
		}
		for _, h := range w.hosts {
			if len(h.writes) != 0 {
				t.Fatalf("%s was written to before the refusal", h.name)
			}
		}
	})
	t.Run("a live host does not hold the local primary", func(t *testing.T) {
		stranger := testKey(t)
		w, hosts := newKeyWorld(t, "enforced", [][]byte{p}, 0, 0)
		w.hosts[1].live, w.hosts[1].file = [][]byte{stranger}, pki.FormatGossipKeyring([][]byte{stranger})
		err := RotateGossipKey(context.Background(), writeLocal(t, [][]byte{p}), hosts, fastOpts())
		if err == nil || !strings.Contains(err.Error(), "node-2") {
			t.Fatalf("got %v", err)
		}
		for _, h := range w.hosts {
			if len(h.writes) != 0 {
				t.Fatalf("%s was written to before the refusal", h.name)
			}
		}
	})
	t.Run("no local key", func(t *testing.T) {
		_, hosts := newKeyWorld(t, "enforced", [][]byte{p}, 0)
		err := RotateGossipKey(context.Background(), filepath.Join(t.TempDir(), pki.GossipKeyName), hosts, fastOpts())
		if err == nil || !strings.Contains(err.Error(), "install-gossip-key") {
			t.Fatalf("got %v", err)
		}
	})
}

// Hosts that are off (or run a build that writes no state) take the file but
// are not waited on: they have no live keyring to confirm, and they load the
// file current when they next start.
func TestRotateGossipKey_OffHostsTakeTheFileWithoutABarrier(t *testing.T) {
	p := testKey(t)
	local := writeLocal(t, [][]byte{p})
	w, hosts := newKeyWorld(t, "off", [][]byte{p}, -1, -1)
	w.hosts[1].mode = ""
	if err := RotateGossipKey(context.Background(), local, hosts, fastOpts()); err != nil {
		t.Fatal(err)
	}
	final, _ := pki.LoadGossipKeyring(local)
	for _, h := range w.hosts {
		got, _ := pki.ParseGossipKeyring(h.file)
		if len(got) != 1 || !bytes.Equal(got[0], final[0]) {
			t.Fatalf("%s file is %v, want %v", h.name, pki.GossipKeyIDs(got), pki.GossipKeyIDs(final))
		}
	}
}

// ─── install ────────────────────────────────────────────────────────────────

func TestInstallGossipKey_MintsAndDistributes(t *testing.T) {
	local := filepath.Join(t.TempDir(), pki.GossipKeyName)
	w, hosts := newKeyWorld(t, "off", nil, 0, 0, 0)
	if err := InstallGossipKey(context.Background(), local, hosts, fastOpts()); err != nil {
		t.Fatal(err)
	}
	ring, err := pki.LoadGossipKeyring(local)
	if err != nil {
		t.Fatalf("no local key after install: %v", err)
	}
	fi, _ := os.Stat(local)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("local key is %o", fi.Mode().Perm())
	}
	for _, h := range w.hosts {
		got, err := pki.ParseGossipKeyring(h.file)
		if err != nil || len(got) != 1 || !bytes.Equal(got[0], ring[0]) {
			t.Fatalf("%s did not receive the key", h.name)
		}
	}

	// Idempotent: a second run writes nothing, and reuses the same key.
	if err := InstallGossipKey(context.Background(), local, hosts, fastOpts()); err != nil {
		t.Fatal(err)
	}
	for _, h := range w.hosts {
		if len(h.writes) != 1 {
			t.Fatalf("%s rewritten on a repeat install", h.name)
		}
	}
	again, _ := pki.LoadGossipKeyring(local)
	if !bytes.Equal(again[0], ring[0]) {
		t.Fatal("a repeat install minted a new key")
	}
}

// Install never replaces a key a host already holds. The daemon reloads the
// file live, so overwriting a staged or enforced host's key IS a partition;
// changing keys is rotate's job.
func TestInstallGossipKey_NeverReplacesAHostsKey(t *testing.T) {
	mine, theirs := testKey(t), testKey(t)
	local := writeLocal(t, [][]byte{mine})
	w, hosts := newKeyWorld(t, "off", nil, 0, 0, 0)
	w.hosts[1].file = pki.FormatGossipKeyring([][]byte{theirs})
	err := InstallGossipKey(context.Background(), local, hosts, fastOpts())
	if err == nil || !strings.Contains(err.Error(), "node-2") {
		t.Fatalf("got %v", err)
	}
	for _, h := range w.hosts {
		if len(h.writes) != 0 {
			t.Fatalf("%s written despite the refusal", h.name)
		}
	}

	// With no local key, a cluster that already has one is not given a second.
	fresh := filepath.Join(t.TempDir(), pki.GossipKeyName)
	if err := InstallGossipKey(context.Background(), fresh, hosts, fastOpts()); err == nil {
		t.Fatal("minted a new key although node-2 already holds one")
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatal("a refused install still wrote a local key")
	}
}

// ─── status wording ─────────────────────────────────────────────────────────

// TestDescribeLive_SaysWhatEachStageSends pins that every stage's status line
// is true about the wire (colonelpanik/litevirt#259). The state file's primary
// is the keyring's first key at every stage but off, including install — where
// the node holds it and does NOT send with it. So the line must be built from
// the stage, not from the presence of a primary: "install, encrypting with"
// told an operator mid-rollout that plaintext gossip was encrypted.
func TestDescribeLive_SaysWhatEachStageSends(t *testing.T) {
	k1, k2 := testKey(t), testKey(t)
	ring := [][]byte{k1, k2}
	id1, id2 := pki.GossipKeyID(k1), pki.GossipKeyID(k2)
	for _, tc := range []struct {
		mode string
		want string
	}{
		{"off", "off (gossip plaintext; key file ignored)"},
		{"install", fmt.Sprintf("install, sending plaintext, accepting plaintext and %s,%s, 3 rejected", id1, id2)},
		{"staged", fmt.Sprintf("staged, encrypting with %s, accepting plaintext and %s,%s, 3 rejected", id1, id1, id2)},
		{"enforced", fmt.Sprintf("enforced, encrypting with %s, accepting only %s,%s, 3 rejected", id1, id1, id2)},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			var keys [][]byte
			if tc.mode != "off" {
				keys = ring
			}
			// Round-trip through the file, as the CLI reads it over SSH.
			s, err := pki.ParseGossipKeyringState(pki.NewGossipKeyringState(tc.mode, keys, 3).Marshal())
			if err != nil {
				t.Fatal(err)
			}
			if got := describeLive(s, true); got != tc.want {
				t.Fatalf("describeLive(%s)\n got: %s\nwant: %s", tc.mode, got, tc.want)
			}
		})
	}

	// A stage this CLI does not know (a newer daemon) makes no claim about
	// what the host sends.
	s := pki.NewGossipKeyringState("future", ring, 0)
	if got := describeLive(s, true); strings.Contains(got, "encrypting") || strings.Contains(got, "plaintext") {
		t.Fatalf("unknown stage described as %q: it claims what the host sends", got)
	}
}

// TestInstallGossipKey_ReportsInstallHostsAsPlaintext is the reported line
// itself: a re-run of install-gossip-key against hosts at stage install.
func TestInstallGossipKey_ReportsInstallHostsAsPlaintext(t *testing.T) {
	k := testKey(t)
	local := writeLocal(t, [][]byte{k})
	_, hosts := newKeyWorld(t, "install", [][]byte{k}, 0, 0)
	var out bytes.Buffer
	opt := fastOpts()
	opt.Out = &out
	if err := InstallGossipKey(context.Background(), local, hosts, opt); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, "already holds") {
			if strings.Contains(line, "encrypting") || !strings.Contains(line, "install, sending plaintext") {
				t.Fatalf("an install-stage host is described as %q", line)
			}
		}
	}
	if !strings.Contains(out.String(), "install, sending plaintext") {
		t.Fatalf("no host line in:\n%s", out.String())
	}
}
