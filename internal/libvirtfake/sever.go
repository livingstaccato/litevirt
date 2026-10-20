package libvirtfake

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
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

// severExempt are the exported methods no daemon calls: the scenario's
// readers, and libvirtd's own landing of a migration. The sever does not end
// them.
var severExempt = map[string]bool{
	"EventLog":    true,
	"RawState":    true,
	"SeverDaemon": true,
	"Severed":     true,
	"Fingerprint": true,
	// A migration landing here is libvirtd's own doing (the source
	// libvirtd's), not this daemon's call: a source daemon that lives on
	// lands its migration on a target whose daemon is dead.
	"LandFirmwareLive":  true,
	"LandMigrated":      true,
	"LandMigratedState": true,
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

// Fingerprint digests what libvirtd holds: every field of the Fake's state
// (domains, definitions, snapshots, pools, secrets, bridges, the operations
// performed and the rest), followed through pointers and in a fixed order.
// Its knobs (funcs), channels, locks and the connection model are not
// state. Two equal fingerprints mean libvirt was not changed between them.
func (f *Fake) Fingerprint() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := sha256.New()
	v := reflect.ValueOf(f).Elem()
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		if fingerprintSkip[name] {
			continue
		}
		fmt.Fprintf(h, "%s=", name)
		fingerprintValue(h, v.Field(i), 0)
		fmt.Fprintln(h)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fingerprintSkip are the Fake's fields that are not libvirt's state.
var fingerprintSkip = map[string]bool{"mu": true, "sever": true, "conns": true}

var lockTypes = map[reflect.Type]bool{
	reflect.TypeOf(sync.Mutex{}):     true,
	reflect.TypeOf(sync.RWMutex{}):   true,
	reflect.TypeOf(sync.Once{}):      true,
	reflect.TypeOf(sync.WaitGroup{}): true,
}

// fingerprintValue writes v, followed through pointers, maps in key order.
func fingerprintValue(w io.Writer, v reflect.Value, depth int) {
	if depth > 12 {
		fmt.Fprint(w, "…")
		return
	}
	if lockTypes[v.Type()] {
		return
	}
	switch v.Kind() {
	case reflect.Func, reflect.Chan, reflect.UnsafePointer:
		fmt.Fprint(w, "-")
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			fmt.Fprint(w, "nil")
			return
		}
		fingerprintValue(w, v.Elem(), depth+1)
	case reflect.Map:
		keys := v.MapKeys()
		type kv struct {
			k string
			v reflect.Value
		}
		kvs := make([]kv, 0, len(keys))
		for _, k := range keys {
			var b strings.Builder
			fingerprintValue(&b, k, depth+1)
			kvs = append(kvs, kv{b.String(), v.MapIndex(k)})
		}
		sort.Slice(kvs, func(i, j int) bool { return kvs[i].k < kvs[j].k })
		fmt.Fprint(w, "{")
		for _, e := range kvs {
			fmt.Fprintf(w, "%q:", e.k)
			fingerprintValue(w, e.v, depth+1)
			fmt.Fprint(w, ",")
		}
		fmt.Fprint(w, "}")
	case reflect.Slice, reflect.Array:
		fmt.Fprint(w, "[")
		for i := 0; i < v.Len(); i++ {
			fingerprintValue(w, v.Index(i), depth+1)
			fmt.Fprint(w, ",")
		}
		fmt.Fprint(w, "]")
	case reflect.Struct:
		fmt.Fprint(w, "{")
		for i := 0; i < v.NumField(); i++ {
			fmt.Fprintf(w, "%s:", v.Type().Field(i).Name)
			fingerprintValue(w, v.Field(i), depth+1)
			fmt.Fprint(w, ",")
		}
		fmt.Fprint(w, "}")
	case reflect.String:
		fmt.Fprintf(w, "%q", v.String())
	case reflect.Bool:
		fmt.Fprint(w, v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		fmt.Fprint(w, v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		fmt.Fprint(w, v.Uint())
	case reflect.Float32, reflect.Float64:
		fmt.Fprint(w, v.Float())
	case reflect.Complex64, reflect.Complex128:
		fmt.Fprint(w, v.Complex())
	default:
		fmt.Fprintf(w, "?%s", v.Kind())
	}
}
