package libvirtfake

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// A daemon killed while it talks to libvirtd: its connection goes with the
// process, and libvirtd hears nothing more from it.
//
// The daemon this Fake serves passes a gate on each call: every exported
// method but those no daemon calls (severExempt), and every call on a
// StateReader connection, starts with `defer f.daemon()()`. The gate has
// three states:
//
//   - alive: the call is admitted and counted until it returns;
//   - fenced (FenceDaemon): a new call waits at the gate, asking libvirt
//     nothing and seeing no error, while the calls already admitted run to
//     their end (DaemonInFlight counts them). A scenario fences every channel
//     the daemon has before anything of it can react, so the moment of death
//     comes after all are fenced;
//   - dead (KillDaemon): each waiting call, and every later one, ends its
//     goroutine where it stands (runtime.Goexit), as a killed process makes
//     no further call. Its deferred calls run, as Goexit runs them; whatever
//     they ask of libvirt ends them the same way.
//
// ReviveDaemon opens the gate again, for the daemon that replaces the dead
// one: only once no goroutine of the dead daemon is left to pass it.
// libvirtd itself (the Fake's state) is untouched by the gate.

type gateState int

const (
	gateAlive gateState = iota
	gateFenced
	gateDead
)

// daemonGate is the Fake's gate for its daemon's calls.
type daemonGate struct {
	mu       sync.Mutex
	state    gateState
	changed  chan struct{} // closed, and replaced, on each change of state
	inflight int
	owners   map[uint64]int // goroutine → depth of its admitted call
	calls    []string       // the calls the dead gate ended
	// leaving, when set (a test's seam), is told each goroutine that
	// leaves an admitted call, before it takes the gate's lock.
	leaving func(id uint64)
}

// severExempt are the exported methods no daemon calls: the scenario's
// readers and the gate's own controls, and libvirtd's own landing of a
// migration. The gate does not stop them.
var severExempt = map[string]bool{
	"EventLog":       true,
	"RawState":       true,
	"Fingerprint":    true,
	"FenceDaemon":    true,
	"KillDaemon":     true,
	"ReviveDaemon":   true,
	"DaemonInFlight": true,
	"DaemonGate":     true,
	// A migration landing here is libvirtd's own doing (the source
	// libvirtd's), not this daemon's call: a source daemon that lives on
	// lands its migration on a target whose daemon is dead.
	"LandFirmwareLive":  true,
	"LandMigrated":      true,
	"LandMigratedState": true,
}

func (g *daemonGate) setLocked(st gateState) {
	g.state = st
	if g.changed != nil {
		close(g.changed)
	}
	g.changed = make(chan struct{})
}

// FenceDaemon fences the gate (see above).
func (f *Fake) FenceDaemon() {
	f.gate.mu.Lock()
	defer f.gate.mu.Unlock()
	f.gate.calls = nil
	f.gate.setLocked(gateFenced)
}

// KillDaemon kills the daemon at the gate (see above).
func (f *Fake) KillDaemon() {
	f.gate.mu.Lock()
	defer f.gate.mu.Unlock()
	f.gate.setLocked(gateDead)
}

// ReviveDaemon opens the gate for a new daemon and returns the calls the dead
// gate ended, in order, by method name.
func (f *Fake) ReviveDaemon() []string {
	f.gate.mu.Lock()
	defer f.gate.mu.Unlock()
	f.gate.setLocked(gateAlive)
	return append([]string(nil), f.gate.calls...)
}

// DaemonInFlight is how many of the daemon's calls are admitted and have not
// returned.
func (f *Fake) DaemonInFlight() int {
	f.gate.mu.Lock()
	defer f.gate.mu.Unlock()
	return f.gate.inflight
}

// DaemonGate names the gate's state: "alive", "fenced" or "dead".
func (f *Fake) DaemonGate() string {
	f.gate.mu.Lock()
	defer f.gate.mu.Unlock()
	return [...]string{"alive", "fenced", "dead"}[f.gate.state]
}

// daemon is the gate (see above): the caller defers the func it returns.
//
// Admission is per logical call: a call the Fake makes on itself, or that a
// hook it runs makes, on the goroutine of a call already admitted
// (DomainState asking its connection, a migrate's landing reading the
// source) is part of that call and passes, fenced or not. Only new work
// waits, so the gate never waits on a call it holds.
func (f *Fake) daemon() (exit func()) {
	g := &f.gate
	id := goid()
	g.mu.Lock()
	for {
		if g.state != gateDead && g.owners[id] > 0 {
			g.owners[id]++
			g.mu.Unlock()
			return func() { g.leave(id) }
		}
		switch g.state {
		case gateAlive:
			if g.owners == nil {
				g.owners = map[uint64]int{}
			}
			g.owners[id] = 1
			g.inflight++
			g.mu.Unlock()
			return func() { g.leave(id) }
		case gateFenced:
			if g.changed == nil {
				g.changed = make(chan struct{})
			}
			ch := g.changed
			g.mu.Unlock()
			<-ch
			g.mu.Lock()
		default:
			g.calls = append(g.calls, callerName())
			g.mu.Unlock()
			runtime.Goexit()
		}
	}
}

// leave ends one level of goroutine id's admitted call.
func (g *daemonGate) leave(id uint64) {
	if g.leaving != nil {
		g.leaving(id)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.owners[id]--; g.owners[id] <= 0 {
		delete(g.owners, id)
		g.inflight--
	}
}

// goid is the calling goroutine's id.
func goid() uint64 {
	var b [64]byte
	s := b[:runtime.Stack(b[:], false)]
	s = bytes.TrimPrefix(s, []byte("goroutine "))
	if i := bytes.IndexByte(s, ' '); i > 0 {
		s = s[:i]
	}
	id, err := strconv.ParseUint(string(s), 10, 64)
	if err != nil {
		panic(fmt.Sprintf("libvirtfake: goroutine id of %q", b[:]))
	}
	return id
}

// callerName is the name of the method that asked the gate.
func callerName() string {
	pc, _, _, ok := runtime.Caller(2)
	if !ok {
		return "?"
	}
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return "?"
	}
	name := fn.Name()
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	return name
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
var fingerprintSkip = map[string]bool{"mu": true, "gate": true, "conns": true}

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
