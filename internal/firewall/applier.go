package firewall

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/cmdbound"
)

// NftRunner is the shell-out boundary so tests can drive applier
// without a real `nft` binary. Production wires NftBinary{}.
type NftRunner interface {
	// Apply replaces the litevirt-fw table atomically by piping ruleset
	// through `nft -f -`. ruleset is the full Render() output.
	Apply(ctx context.Context, ruleset string) (string, error)
	// Flush deletes the litevirt-fw table — used on uninstall and as
	// a clean-slate before the first apply.
	Flush(ctx context.Context) (string, error)
}

// NftBinary is the production NftRunner. Calls /sbin/nft (or whatever's
// on PATH) and pipes the rendered ruleset on stdin.
type NftBinary struct {
	// Bin overrides the binary path; empty = "nft" on PATH.
	Bin string
}

func (n NftBinary) bin() string {
	if n.Bin != "" {
		return n.Bin
	}
	return "nft"
}

// Apply runs `nft -f -` with ruleset on stdin. A `table inet litevirt-fw {…}`
// block alone does NOT replace an existing table — nft MERGES it, so every
// re-apply would append the forward chain's rules again (rule duplication).
// To get a true atomic replace we prepend the standard idiom:
//
//	table inet litevirt-fw {}      # ensure it exists (no-op if already present)
//	delete table inet litevirt-fw  # remove it (safe now that it exists)
//	<ruleset>                      # recreate it fresh
//
// nft -f processes the whole input as ONE transaction, so the delete+recreate
// is atomic — traffic never sees a half-applied or empty table. The same idiom
// replaces the per-NIC bridge table when the ruleset carries that one. The
// Applier sends the two tables as separate transactions (see Applier.Apply).
func (n NftBinary) Apply(ctx context.Context, ruleset string) (string, error) {
	var preamble string
	if strings.Contains(ruleset, "table inet "+TableName+" {\n") {
		preamble += fmt.Sprintf("table inet %s {}\ndelete table inet %s\n", TableName, TableName)
	}
	if strings.Contains(ruleset, "table bridge "+NICTableName+" {\n") {
		preamble += fmt.Sprintf("table bridge %s {}\ndelete table bridge %s\n", NICTableName, NICTableName)
	}
	cmd := cmdbound.Command(ctx, n.bin(), "-f", "-")
	cmd.Stdin = strings.NewReader(preamble + ruleset)
	out, err := cmdbound.CombinedOutput(ctx, cmd)
	return string(out), err
}

// DropNICTable deletes the per-NIC bridge table if one exists. A failed
// listing means there is none (or no bridge family to hold one), which is not
// an error; a failed delete of a table that exists is.
func (n NftBinary) DropNICTable(ctx context.Context) error {
	if err := cmdbound.Run(ctx, cmdbound.Command(ctx, n.bin(), "list", "table", "bridge", NICTableName)); err != nil {
		return nil
	}
	if out, err := cmdbound.CombinedOutput(ctx, cmdbound.Command(ctx, n.bin(), "delete", "table", "bridge", NICTableName)); err != nil {
		return fmt.Errorf("delete stale per-NIC table: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// nicTableDropper is implemented by a runner that can delete the per-NIC table
// outside a ruleset transaction (NftBinary). Test fakes need not.
type nicTableDropper interface {
	DropNICTable(ctx context.Context) error
}

// Flush drops the entire table — operators only need this on
// uninstall (the typical path is Apply with an empty Plan).
func (n NftBinary) Flush(ctx context.Context) (string, error) {
	cmd := cmdbound.Command(ctx, n.bin(), "delete", "table", "inet", TableName)
	out, err := cmdbound.CombinedOutput(ctx, cmd)
	if err != nil {
		return string(out), err
	}
	return "", n.DropNICTable(ctx)
}

// ErrNICTableRefused wraps a failure to load the per-NIC bridge table. The
// inet table (NAT, isolation, routed filtering) was still applied, rendered
// so it does not rely on the refused table.
var ErrNICTableRefused = errors.New("per-NIC table refused")

// Applier serialises Apply calls and short-circuits when the rendered
// ruleset hasn't changed. Intended to be a long-lived process-wide
// instance — daemon construction wires it once.
type Applier struct {
	runner NftRunner

	mu          sync.Mutex
	lastInet    string
	lastNIC     string // the per-NIC table last loaded; "" = none loaded by this process
	nicCleaned  bool   // a stale per-NIC table from before this process was looked for
	lastApplyAt time.Time
	resyncAfter time.Duration
	now         func() time.Time

	// tally, when set, is handed the observe counters of the per-NIC table
	// before every replace or removal of it, which zeroes them.
	tally      *WouldDropTally
	lastOwners map[string]NICOwner // the NICs of lastNIC
}

// SetTally makes the applier harvest the observe counters into t before it
// replaces or removes the per-NIC table.
func (a *Applier) SetTally(t *WouldDropTally) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tally = t
}

// harvestLocked hands the counters of the table about to go to the tally. A
// table this process did not load (one left by the previous daemon, whose
// taps the running VMs still hold) is attributed by p's owners. Caller holds
// a.mu.
func (a *Applier) harvestLocked(ctx context.Context, p Plan) {
	if a.tally == nil {
		return
	}
	owners := a.lastOwners
	if a.lastNIC == "" {
		owners = nicOwners(p)
	}
	if err := a.tally.Harvest(ctx, owners); err != nil {
		slog.Warn("firewall: could not keep the observe-mode counters before replacing the per-NIC table", "error", err)
	}
}

// NewApplier wraps an NftRunner with the change-detection cache.
func NewApplier(runner NftRunner) *Applier {
	if runner == nil {
		runner = NftBinary{}
	}
	return &Applier{runner: runner, resyncAfter: DefaultResyncInterval, now: time.Now}
}

// DefaultResyncInterval bounds how long an out-of-band change to the kernel
// ruleset can persist before the reconciler re-sends the identical ruleset.
const DefaultResyncInterval = 5 * time.Minute

// SetResyncInterval overrides the resync window. Zero disables resync entirely
// (cache-only, the pre-fix behaviour).
func (a *Applier) SetResyncInterval(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.resyncAfter = d
}

// SetClock replaces the time source. Test seam.
func (a *Applier) SetClock(now func() time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.now = now
}

// Apply renders and applies p. Returns (changed, error). When changed
// is false, the daemon can skip log/event emission. Apply is goroutine-
// safe; concurrent callers serialise on a per-Applier mutex so two
// reconcilers don't fight.
//
// The two tables load as two transactions, per-NIC table first. A refusal of
// the per-NIC table (a kernel without some bridge-family support, an nft too
// old for one of its expressions) must not freeze NAT, isolation and routed
// filtering with it, so the inet table is then rendered not to rely on it and
// applied anyway, and the error is returned wrapping ErrNICTableRefused. The
// per-NIC table goes first because the inet table trusts the marks it sets:
// loading the inet table first would, for a moment, trust a table not yet
// there.
func (a *Applier) Apply(ctx context.Context, p Plan) (bool, error) {
	if _, _, err := RenderParts(p, true); err != nil {
		return false, fmt.Errorf("render: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Logging is decided again under the lock: a plan loaded before logging
	// went off (a lost group, a stopping daemon) is applied without its log
	// lines, so it cannot follow the pass that removed them with them back.
	if p.LogPolicy.Available && p.logRecheck != nil {
		if on, _ := p.logRecheck(); !on {
			p.LogPolicy = LogPolicy{}
		}
	}
	resync := a.resyncDueLocked()

	changed, sent := false, false
	nicActive := false
	var nicErr error
	_, nic, _ := RenderParts(p, true)
	switch {
	case nic != "":
		if nic != a.lastNIC || resync {
			a.harvestLocked(ctx, p)
			if out, err := a.runner.Apply(ctx, nic); err != nil {
				nicErr = fmt.Errorf("%w: nft apply: %v: %s", ErrNICTableRefused, err, strings.TrimSpace(out))
			} else {
				changed = changed || nic != a.lastNIC
				a.lastNIC, sent = nic, true
				a.lastOwners = nicOwners(p)
			}
		}
		nicActive = nicErr == nil
	case a.lastNIC != "" || !a.nicCleaned:
		// Nothing to enforce per NIC: remove a table this process, or an
		// earlier binary, left behind. libvirt reuses vnetN names, so a stale
		// chain would hold the next VM to get one to another VM's policy.
		if d, ok := a.runner.(nicTableDropper); ok {
			a.harvestLocked(ctx, p)
			if err := d.DropNICTable(ctx); err != nil {
				nicErr = err
			}
		}
		if nicErr == nil {
			changed = changed || a.lastNIC != ""
			a.lastNIC, a.nicCleaned, a.lastOwners = "", true, nil
		}
	}
	if nic != "" && nicErr == nil {
		a.nicCleaned = true
	}

	inet, _, _ := RenderParts(p, nicActive)
	if inet != a.lastInet || resync {
		if out, err := a.runner.Apply(ctx, inet); err != nil {
			return changed, fmt.Errorf("nft apply: %w: %s", err, strings.TrimSpace(out))
		}
		changed = changed || inet != a.lastInet
		a.lastInet, sent = inet, true
	}
	if sent {
		a.lastApplyAt = a.clockLocked()()
	}
	// changed reports whether the RULESET changed, not whether nft was invoked.
	return changed, nicErr
}

// resyncDueLocked reports whether the last successful apply is old enough that
// the identical ruleset should be re-sent. Caller holds a.mu.
func (a *Applier) resyncDueLocked() bool {
	if a.resyncAfter <= 0 {
		return false
	}
	if a.lastApplyAt.IsZero() {
		return true
	}
	return a.clockLocked()().Sub(a.lastApplyAt) >= a.resyncAfter
}

// clockLocked returns the time source, defaulting to time.Now for an Applier
// built as a zero value rather than through NewApplier. Caller holds a.mu.
func (a *Applier) clockLocked() func() time.Time {
	if a.now == nil {
		return time.Now
	}
	return a.now
}

// LastApplied returns the most recent ruleset bytes the applier
// successfully sent. Useful for `lv firewall show` — the operator
// sees exactly what's loaded into the kernel right now.
func (a *Applier) LastApplied() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lastNIC == "" {
		return a.lastInet
	}
	return a.lastInet + "\n" + a.lastNIC
}

// Reset clears the last-sent cache so the next Apply will re-send even
// if the bytes are identical. Use after a kernel reset / nft flush
// happened out-of-band.
func (a *Applier) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastInet, a.lastNIC = "", ""
	a.nicCleaned = false
	a.lastApplyAt = time.Time{}
}

// BridgeConntrackAvailable reports whether nf_conntrack_bridge is available
// — loaded or built in — loading it first when load is set. Per-NIC rules need
// it: without it every bridged frame is untracked, the reply to a guest's own
// connection is judged as a new one, and a `ct` expression in the bridge table
// makes the kernel refuse the table outright. The daemon loads it at start
// (load=true); tests never do (load=false): loading a module is a change to
// the host. A modprobe that succeeds is availability, whatever sysfs shows.
func BridgeConntrackAvailable(ctx context.Context, load bool) bool {
	if moduleAvailable("nf_conntrack_bridge") {
		return true
	}
	if !load {
		return false
	}
	if err := modprobe(ctx, "nf_conntrack_bridge"); err != nil {
		slog.Error("firewall: could not load nf_conntrack_bridge; per-NIC rules will not be enforced (guards only)",
			"error", err)
		return false
	}
	return true
}

// Where module state is read; tests point them elsewhere.
var (
	sysModuleDir     = "/sys/module"
	procModulesPath  = "/proc/modules"
	builtinListPath  = "" // "" = /lib/modules/<release>/modules.builtin
	modprobe         = runModprobe
	errNoModuleState = errors.New("no module state")
)

func runModprobe(ctx context.Context, name string) error {
	if out, err := cmdbound.CombinedOutput(ctx, cmdbound.Command(ctx, "modprobe", name)); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// moduleAvailable reports whether a kernel module is loaded or built in. A
// built-in module that takes no parameters has no /sys/module entry, so the
// kernel's list of built-in modules is read as well.
func moduleAvailable(name string) bool {
	if _, err := os.Stat(sysModuleDir + "/" + name); err == nil {
		return true
	}
	if b, err := os.ReadFile(procModulesPath); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) > 0 && f[0] == name {
				return true
			}
		}
	}
	path := builtinListPath
	if path == "" {
		rel, err := kernelRelease()
		if err != nil {
			return false
		}
		path = "/lib/modules/" + rel + "/modules.builtin"
	}
	if b, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			base := line[strings.LastIndex(line, "/")+1:]
			if strings.TrimSuffix(base, ".ko") == name {
				return true
			}
		}
	}
	return false
}

func kernelRelease() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", err
	}
	if r := strings.TrimSpace(string(b)); r != "" {
		return r, nil
	}
	return "", errNoModuleState
}
