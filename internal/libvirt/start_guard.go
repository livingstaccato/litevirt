package libvirt

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// StartGuard is what must hold before a domain's guest runs: its per-NIC
// firewall, NIC guards above all (re-review I-10, R2-I4).
//
// Before runs ahead of every start. It returns pause when what must hold can
// only be put in force once the domain exists — a NIC whose tap libvirt names
// at start (vnetN) — and then the domain is started paused, AfterPaused runs
// while it is paused, and only then does the guest run. An error from either
// leaves the domain stopped.
type StartGuard struct {
	Before      func(name string) (pause bool, err error)
	AfterPaused func(name string) error
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

// RequireStartGuard makes every start wait, up to wait, for SetStartGuard,
// and refuse if none is set by then. The daemon calls it right after
// connecting: after a host boots, its onboot, self-heal and restart-policy
// starts may otherwise run before the firewall is wired, with the nft tables
// empty (re-review R2-I2).
func (c *Client) RequireStartGuard(wait time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.guardReady == nil {
		c.guardReady = make(chan struct{})
		if c.guardSet {
			c.readyOnce.Do(func() { close(c.guardReady) })
		}
	}
	c.guardWait = wait
}

// guard returns the start guard, waiting for a required one.
func (c *Client) guard() (StartGuard, error) {
	c.mu.RLock()
	ready, wait := c.guardReady, c.guardWait
	c.mu.RUnlock()
	if ready != nil {
		select {
		case <-ready:
		case <-time.After(wait):
			return StartGuard{}, errGuardNotReady
		}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.startGuard, nil
}

// guardedStart starts a domain through the guard: create(paused) starts it,
// resume lets a paused one run, destroy undoes a start the guard refused.
func guardedStart(g StartGuard, name string, create func(paused bool) error, resume func() error, destroy func()) error {
	pause, err := g.before(name)
	if err != nil {
		return fmt.Errorf("start domain %s: %w", name, err)
	}
	if err := create(pause); err != nil {
		return err
	}
	if !pause {
		return nil
	}
	if err := g.afterPaused(name); err != nil {
		destroy()
		return fmt.Errorf("start domain %s: %w", name, err)
	}
	if err := resume(); err != nil {
		return fmt.Errorf("resume domain %s: %w", name, err)
	}
	return nil
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
