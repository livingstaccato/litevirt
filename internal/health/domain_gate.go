package health

import (
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A pass of this host's background loops — the reconcile walk and its
// sweeps, the VM checker's restart pass — asks libvirt about each local
// domain on the daemon's one connection, and waits for each answer. libvirt
// does not always answer: a domain whose start waits on storage that does
// not answer holds its domain's lock, and every call naming that domain
// waits with it, as does every domain list. One such call held the whole
// pass, every pass after it, and the daemon's connection with it: libvirtd
// serves at most max_client_requests (5) calls of one connection, so a
// handful of loops each waiting on one filled it, and from then on libvirt
// answered nothing on it for any domain (lab 2, 03fe9868 and 339a79f4, B2).
//
// So before a pass makes any call naming a domain, it asks libvirt for the
// domain's state on a connection of its own (the backend's StateReader),
// within virtWaitDefault. A domain libvirt has not answered for is skipped
// this pass: nothing is read of it on the daemon's connection, nothing is
// decided about it and nothing is changed; the next pass asks again. A
// domain list is asked the same way, and a sweep whose list libvirt has not
// answered is skipped whole. The call itself is never cancelled (libvirt has
// no way to); while it has not returned, a later ask of the same domain
// joins it, and once it has been waited out it is latched: later asks answer
// "no answer" at once until it returns. So a domain libvirt does not answer
// for costs one outstanding call per loop, on a reader connection, and one
// wait the first time.
//
// The calls a pass makes after the ask stay on the daemon's connection: the
// ask says libvirt answered for the domain a moment ago. A domain whose
// start begins to hang between the two is not caught; that window is the
// residual.
const virtWaitDefault = 3 * time.Second

// errLibvirtNoAnswer is a bounded read libvirt has not answered.
var errLibvirtNoAnswer = errors.New("libvirt has not answered")

// virtWait bounds a loop's reads of libvirt (see above). The zero value is
// ready to use.
type virtWait struct {
	// wait overrides virtWaitDefault (tests).
	wait time.Duration

	mu    sync.Mutex
	calls map[string]*virtCall
	// skipped holds the domains this loop has said it skips, so the skip is
	// logged once per outage, not every pass.
	skipped map[string]bool
}

type virtCall struct {
	since time.Time
	done  chan struct{}
	val   any
	err   error
}

func (w *virtWait) waitOrDefault() time.Duration {
	if w.wait > 0 {
		return w.wait
	}
	return virtWaitDefault
}

// do makes call under key in its own goroutine and waits for it at most the
// wait, joining a call under key that has not returned, and answering
// errLibvirtNoAnswer at once for one already waited out.
func (w *virtWait) do(key string, call func() (any, error)) (any, error) {
	wait := w.waitOrDefault()
	w.mu.Lock()
	c, joined := w.calls[key]
	if joined {
		wait -= time.Since(c.since)
		if wait <= 0 {
			w.mu.Unlock()
			select {
			case <-c.done:
				return c.val, c.err
			default:
				return nil, errLibvirtNoAnswer
			}
		}
	} else {
		c = &virtCall{since: time.Now(), done: make(chan struct{})}
		if w.calls == nil {
			w.calls = map[string]*virtCall{}
		}
		w.calls[key] = c
		go func() {
			v, err := call()
			w.mu.Lock()
			c.val, c.err = v, err
			if w.calls[key] == c {
				delete(w.calls, key)
			}
			w.mu.Unlock()
			close(c.done)
		}()
	}
	w.mu.Unlock()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-c.done:
		return c.val, c.err
	case <-timer.C:
		return nil, errLibvirtNoAnswer
	}
}

// domainStater is what the ask reads on the daemon's connection when the
// backend has no StateReader (or it cannot dial).
type domainStater interface {
	DomainState(name string) (string, error)
}

// stateReaderOf is the backend's StateReader, or nil.
func stateReaderOf(virt any) *lv.StateReader {
	if b, ok := virt.(interface{ StateReader() *lv.StateReader }); ok {
		return b.StateReader()
	}
	return nil
}

// domainState is virt's DomainState of name, asked on its StateReader (on
// the daemon's connection when it has none, or it cannot dial), within the
// wait: errLibvirtNoAnswer when libvirt has not answered.
func (w *virtWait) domainState(virt domainStater, name string) (string, error) {
	v, err := w.do("state\x00"+name, func() (any, error) {
		if r := stateReaderOf(virt); r != nil {
			st, err := r.DomainState(name)
			if !errors.Is(err, lv.ErrStateConnUnavailable) {
				return st, err
			}
		}
		return virt.DomainState(name)
	})
	st, _ := v.(string)
	return st, err
}

// domainAnswers reports whether libvirt answers for name now (any answer, an
// error of libvirt's own included). A domain it has not answered for is
// logged once per outage, by who, as skipped.
func (w *virtWait) domainAnswers(virt domainStater, who, name string) bool {
	_, err := w.domainState(virt, name)
	answered := !errors.Is(err, errLibvirtNoAnswer)
	switch w.noteSkip(who+"\x00"+name, !answered) {
	case skipStarted:
		slog.Warn(who+": libvirt has not answered for this VM's domain; nothing is decided or changed for it until it does",
			"vm", name, "waited", w.waitOrDefault())
	case skipEnded:
		slog.Info(who+": libvirt answers for this VM's domain again", "vm", name)
	}
	return answered
}

type skipChange int

const (
	skipSame skipChange = iota
	skipStarted
	skipEnded
)

// noteSkip records whether key is skipped now, and says whether that began
// or ended an outage, so it is logged once each way.
func (w *virtWait) noteSkip(key string, skip bool) skipChange {
	w.mu.Lock()
	defer w.mu.Unlock()
	was := w.skipped[key]
	switch {
	case skip && !was:
		if w.skipped == nil {
			w.skipped = map[string]bool{}
		}
		w.skipped[key] = true
		return skipStarted
	case !skip && was:
		delete(w.skipped, key)
		return skipEnded
	}
	return skipSame
}

// prune forgets the skips of the VMs not in live (deleted, or moved away
// while skipped), so a VM re-created under the name logs its own skip.
// Sweeps' list skips are kept.
func (w *virtWait) prune(live map[string]bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for key := range w.skipped {
		i := strings.IndexByte(key, 0)
		if i < 0 {
			continue
		}
		if name := key[i+1:]; name != "list" && !live[name] {
			delete(w.skipped, key)
		}
	}
}

// domainLister is a backend's domain list.
type domainLister interface {
	ListDomains() ([]string, error)
}

// listDomains is virt's ListDomains, asked on its StateReader (on the
// daemon's connection when it has none, or it cannot dial), within the
// wait: errLibvirtNoAnswer when libvirt has not answered. libvirt lists only
// once it can look at every domain, so one it hangs on holds the list.
func (w *virtWait) listDomains(virt domainLister) ([]string, error) {
	v, err := w.do("list", func() (any, error) {
		if r := stateReaderOf(virt); r != nil {
			names, err := r.ListDomains()
			if !errors.Is(err, lv.ErrStateConnUnavailable) {
				return names, err
			}
		}
		return virt.ListDomains()
	})
	names, _ := v.([]string)
	return names, err
}

// domainAnswers is virtWait.domainAnswers for the reconciler.
func (r *Reconciler) domainAnswers(name string) bool {
	return r.virtWait.domainAnswers(r.virt, "reconciler", name)
}

// listDomainsBounded is virtWait.listDomains for the reconciler; who names
// the sweep for the log line when libvirt has not answered.
func (r *Reconciler) listDomainsBounded(who string) ([]string, error) {
	names, err := r.virtWait.listDomains(r.virt)
	switch r.virtWait.noteSkip(who+"\x00list", errors.Is(err, errLibvirtNoAnswer)) {
	case skipStarted:
		slog.Warn(who+": libvirt has not answered the domain list (a domain it hangs on holds it); the sweep is skipped until it does",
			"waited", r.virtWait.waitOrDefault())
	case skipEnded:
		slog.Info(who+": libvirt answers the domain list again", "sweep", who)
	}
	return names, err
}
