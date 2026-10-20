package libvirtfake

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// A daemon killed while it talks to libvirtd: its connection goes with the
// process, and libvirtd hears nothing more from it.
//
// SeverDaemon models that for the daemon this Fake serves. Every method a
// daemon calls (each exported method but the scenario's own readers,
// severExempt) and every call on a StateReader connection first asks
// daemon(); while the Fake is severed that ends the calling goroutine where
// it stands (runtime.Goexit), before libvirt is asked anything, as a killed
// process makes no further call. Its deferred calls run, as Goexit runs them;
// whatever they ask of libvirt ends them the same way.
//
// A scenario severs the Fake only while the daemon is dead (between its kill
// and its replacement) and calls nothing on it then but the exempt readers;
// libvirtd itself (the Fake's state) is untouched by the sever.

// severState is the Fake's sever: on while severed, and the calls it ended.
type severState struct {
	on    atomic.Bool
	mu    sync.Mutex
	calls []string
}

// severExempt are the exported methods a scenario reads the Fake with while
// its daemon is dead: they are no daemon's calls, so the sever does not end
// them.
var severExempt = map[string]bool{
	"EventLog":    true,
	"RawState":    true,
	"SeverDaemon": true,
	"Severed":     true,
	"Fingerprint": true,
}

// SeverDaemon severs the daemon's connection (see above). restore ends the
// sever and returns the calls it ended, in order, by method name.
func (f *Fake) SeverDaemon() (restore func() []string) {
	f.sever.mu.Lock()
	f.sever.calls = nil
	f.sever.mu.Unlock()
	f.sever.on.Store(true)
	return func() []string {
		f.sever.on.Store(false)
		f.sever.mu.Lock()
		defer f.sever.mu.Unlock()
		return append([]string(nil), f.sever.calls...)
	}
}

// Severed reports whether the daemon's connection is severed.
func (f *Fake) Severed() bool { return f.sever.on.Load() }

// daemon is the first thing every daemon-facing method does: on a severed
// Fake it ends the calling goroutine.
func (f *Fake) daemon() {
	if !f.sever.on.Load() {
		return
	}
	name := "?"
	if pc, _, _, ok := runtime.Caller(1); ok {
		if fn := runtime.FuncForPC(pc); fn != nil {
			name = fn.Name()
			if i := strings.LastIndex(name, "."); i >= 0 {
				name = name[i+1:]
			}
		}
	}
	f.sever.mu.Lock()
	f.sever.calls = append(f.sever.calls, name)
	f.sever.mu.Unlock()
	runtime.Goexit()
}

// outsideLock runs fn with f.mu released and takes it back however fn ends,
// so a callback whose goroutine ends in it (a severed daemon's, or a
// scenario's kill) leaves the lock as the caller's deferred unlock expects.
func (f *Fake) outsideLock(fn func()) {
	f.mu.Unlock()
	defer f.mu.Lock()
	fn()
}

// Fingerprint digests what libvirtd holds: every domain's state, both of its
// definitions and its stop reason, and the operations performed. Two equal
// fingerprints mean libvirt was not changed between them.
func (f *Fake) Fingerprint() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := map[string]bool{}
	for n := range f.domains {
		names[n] = true
	}
	for n := range f.xml {
		names[n] = true
	}
	for n := range f.activeXML {
		names[n] = true
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	h := sha256.New()
	for _, n := range sorted {
		fmt.Fprintf(h, "%q %q %q %q %q\n", n, f.domains[n], f.xml[n], f.activeXML[n], f.offReason[n])
	}
	for _, e := range f.events {
		fmt.Fprintf(h, "%q %q %q\n", e.Op, e.Domain, e.Note)
	}
	return hex.EncodeToString(h.Sum(nil))
}
