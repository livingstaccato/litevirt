package libvirt

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// StartGuard is what must hold before a domain's guest runs: its per-NIC
// firewall, NIC guards above all (re-review I-10, R2-I4).
//
// Before runs ahead of every start. It returns pause when what must hold can
// only be put in force once the domain exists — a NIC whose tap libvirt names
// at start (vnetN) — and then the domain is started paused, AfterPaused runs
// while it is paused, and only then does the guest run. An error from either
// leaves the domain stopped.
//
// PausedDone, when set, runs once a start that Before paused has ended: the
// guest resumed, or libvirt confirms the domain is no longer paused
// (destroyed, or never created). A failed start whose domain may still be
// paused does not call it (review I4). It is not called for a start that was
// not paused. A daemon that dies before it runs leaves
// whatever Before recorded for the paused start in place, which is how such a
// start is found again (grpcapi.ResumeStrandedStarts).
type StartGuard struct {
	Before      func(name string) (pause bool, err error)
	AfterPaused func(name string) error
	PausedDone  func(name string)
}

func (g StartGuard) pausedDone(name string) {
	if g.PausedDone != nil {
		g.PausedDone(name)
	}
}

func (g StartGuard) before(name string) (bool, error) {
	if g.Before == nil {
		return false, nil
	}
	return g.Before(name)
}

func (g StartGuard) afterPaused(name string) error {
	if g.AfterPaused == nil {
		return nil
	}
	return g.AfterPaused(name)
}

// errGuardNotReady: the client requires a guard (RequireStartGuard) and none
// was set in time.
var errGuardNotReady = errors.New("the NIC firewall is not ready yet, so no domain is started; retry shortly")

// SetStartGuard registers the guard every start goes through: StartDomain,
// a snapshot revert, a live-snapshot restore. The daemon wires the per-NIC
// firewall here, so a VM's NIC guards are in force before its first frame,
// whichever path starts it.
func (c *Client) SetStartGuard(g StartGuard) {
	c.mu.Lock()
	c.startGuard = g
	c.guardSet = true
	ready := c.guardReady
	c.mu.Unlock()
	if ready != nil {
		c.readyOnce.Do(func() { close(ready) })
	}
}

// RequireStartGuard makes a start wait, up to wait, for SetStartGuard, and
// refuse if none is set by then. The daemon calls it right after connecting:
// after a host boots, its onboot, self-heal and restart-policy starts may
// otherwise run before the firewall is wired, with the nft tables empty
// (re-review R2-I2).
//
// needs scopes the wait (re-review m3): a start of a domain it reports false
// for — a VM with no NIC guard — does not wait, and runs as it did before
// guards existed. It is asked only while no guard is set; nil means every
// start waits. It should answer true when it cannot tell.
func (c *Client) RequireStartGuard(wait time.Duration, needs func(name string) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.guardReady == nil {
		c.guardReady = make(chan struct{})
		if c.guardSet {
			c.readyOnce.Do(func() { close(c.guardReady) })
		}
	}
	c.guardWait, c.guardNeeds = wait, needs
}

// guard returns the start guard for a start of name, waiting for a required
// one when name needs it.
//
// The firmware move guard is asked first (OpStart, spec §5.1), and
// independently of the start guard's readiness: a domain RequireStartGuard
// would let start unguarded (no NIC guard) is still refused while a firmware
// move record names it.
func (c *Client) guard(name string) (StartGuard, error) {
	if err := c.firmwareGuard().check(FirmwareCall{Op: OpStart, Name: name}); err != nil {
		return StartGuard{}, err
	}
	c.mu.RLock()
	ready, wait, needs := c.guardReady, c.guardWait, c.guardNeeds
	c.mu.RUnlock()
	if ready != nil {
		select {
		case <-ready:
		default:
			if needs != nil && !needs(name) {
				return StartGuard{}, nil
			}
			select {
			case <-ready:
			case <-time.After(wait):
				return StartGuard{}, errGuardNotReady
			}
		}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.startGuard, nil
}

// guardedStart starts a domain through the guard: create(paused) starts it,
// resume lets a paused one run, destroy undoes a start the guard refused or
// that could not be resumed.
//
// A paused start's end (PausedDone) is reported only once it has really
// ended: the guest resumed, or stillPaused finds the domain no longer paused
// (destroyed, never created, or not this start's). A domain a failed create
// or a destroy that did not land leaves paused keeps the start's record, so
// the sweep names it (grpcapi.ResumeStrandedStarts; review I4).
func guardedStart(g StartGuard, name string, create func(paused bool) error, resume func() error, destroy func(), stillPaused func() bool) error {
	pause, err := g.before(name)
	if err != nil {
		return fmt.Errorf("start domain %s: %w", name, err)
	}
	ended := func() {
		if pause && !stillPaused() {
			g.pausedDone(name)
		}
	}
	if err := create(pause); err != nil {
		ended()
		return err
	}
	if !pause {
		return nil
	}
	if err := g.afterPaused(name); err != nil {
		destroy()
		ended()
		return fmt.Errorf("start domain %s: %w", name, err)
	}
	if err := resume(); err != nil {
		// Left paused, the domain would disagree with the start's error and
		// with the row (re-review m5): stop it, as a refusal does.
		destroy()
		ended()
		return fmt.Errorf("resume domain %s: %w", name, err)
	}
	g.pausedDone(name)
	return nil
}

// domainStillPaused reports whether name's domain may still be paused: true
// unless libvirt answers that it has no such domain, or that it is in a
// state other than paused. A state it cannot read counts as paused.
func domainStillPaused(v interface {
	DomainLookupByName(name string) (golibvirt.Domain, error)
	DomainGetState(dom golibvirt.Domain, flags uint32) (int32, int32, error)
}, name string) bool {
	dom, err := v.DomainLookupByName(name)
	if err != nil {
		return !IsNoDomain(err)
	}
	st, _, err := v.DomainGetState(dom, 0)
	if err != nil {
		return !IsNoDomain(err)
	}
	return golibvirt.DomainState(st) == golibvirt.DomainPaused
}

var (
	reTargetIfaceElem = regexp.MustCompile(`(?s)<interface\b.*?</interface>`)
	reTargetIfaceMAC  = regexp.MustCompile(`<mac\b[^>]*\baddress=['"]([^'"]+)['"]`)
	reTargetIfaceDev  = regexp.MustCompile(`<target\b[^>]*\bdev=['"]([^'"]+)['"]`)
)

// InterfaceTargets maps each interface's MAC (lower-case) in a domain
// definition to the tap name it names, "" for one that names none.
func InterfaceTargets(domainXML string) map[string]string {
	out := map[string]string{}
	for _, el := range reTargetIfaceElem.FindAllString(domainXML, -1) {
		m := reTargetIfaceMAC.FindStringSubmatch(el)
		if m == nil {
			continue
		}
		dev := ""
		if t := reTargetIfaceDev.FindStringSubmatch(el); t != nil {
			dev = t[1]
		}
		out[strings.ToLower(m[1])] = dev
	}
	return out
}
