package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/nictap"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// PlanLoader builds the desired Plan for *this host* from cluster
// state. The reconciler polls it; the daemon wires a real
// implementation that joins security_groups, sg_rules, vm_interfaces,
// and host config.
type PlanLoader func(ctx context.Context) (Plan, error)

// Reconciler periodically rebuilds the local firewall plan and applies
// it via the Applier. Pull-based polling beats push-via-event for
// firewall state because:
//   - Nftables is local; no network round trip is needed.
//   - A periodic re-apply self-heals out-of-band drift (e.g. a sysadmin
//     ran `nft flush` to debug).
//   - Cache short-circuit on the Applier means most ticks are free.
type Reconciler struct {
	loader   PlanLoader
	applier  *Applier
	interval time.Duration

	mu       sync.Mutex
	running  bool
	stopCh   chan struct{}
	doneCh   chan struct{}
	lastErr  error
	lastTick time.Time

	state     AppliedState
	stateHook func(context.Context, AppliedState)
	passHook  func(context.Context, bool)

	arming *Arming // SetArming; nil = nothing armed

	// Arm passes, coalesced: armRunning is the pass in progress, armNext the
	// one every Arm that arrived since will share.
	armMu      sync.Mutex
	armRunning *armRound
	armNext    *armRound
}

// armRound is one coalesced pass Arm callers wait on.
type armRound struct {
	done chan struct{}
	err  error
}

// NewReconciler wires a loader to an applier. interval controls the
// poll cadence; the daemon defaults to 30s — fast enough that a rule
// add propagates quickly, cheap enough that idle clusters don't
// burn CPU.
func NewReconciler(loader PlanLoader, applier *Applier, interval time.Duration) *Reconciler {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Reconciler{loader: loader, applier: applier, interval: interval}
}

// Start launches the reconciler in a goroutine. Calling Start while
// already running is a no-op (idempotent so daemon restart paths
// don't double-spawn).
func (r *Reconciler) Start(ctx context.Context) {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return
	}
	r.running = true
	r.stopCh = make(chan struct{})
	r.doneCh = make(chan struct{})
	r.mu.Unlock()

	go r.loop(ctx)
}

// Stop signals the reconciler to exit and waits for the goroutine to
// finish. Safe to call multiple times.
func (r *Reconciler) Stop() {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return
	}
	close(r.stopCh)
	doneCh := r.doneCh
	r.running = false
	r.mu.Unlock()
	<-doneCh
}

// LastError returns the most recent reconcile error (or nil). Useful
// for `lv firewall show` — surfaces "Corrosion unreachable" without
// the operator needing to dig through logs.
func (r *Reconciler) LastError() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastErr
}

// LastTick returns the time of the most recent successful (no-error)
// reconcile attempt.
func (r *Reconciler) LastTick() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastTick
}

// Reconcile runs one poll-load-apply cycle, exposed publicly so
// `lv firewall reload` can drive it on demand.
func (r *Reconciler) Reconcile(ctx context.Context) (err error) {
	defer func() { r.notifyPass(ctx, err == nil) }()
	plan, err := r.loader(ctx)
	if err != nil {
		r.recordErr(fmt.Errorf("load plan: %w", err))
		return err
	}
	changed, err := r.applier.Apply(ctx, plan)
	nicRefused := errors.Is(err, ErrNICTableRefused)
	if err != nil && !nicRefused {
		r.recordErr(fmt.Errorf("apply plan: %w", err))
		return err
	}
	r.recordState(ctx, plan, err)
	if nicRefused {
		// The inet table (NAT, isolation, routed filtering) was applied; only
		// the per-NIC table was refused. Report it, and carry on with the
		// rest of the pass.
		r.recordErr(fmt.Errorf("apply plan: %w", err))
		slog.Error("firewall: the per-NIC table was refused; NAT, isolation and routed filtering still applied", "error", err)
	} else {
		r.recordOK()
	}
	if changed {
		slog.Info("firewall ruleset applied",
			"rules", countRules(plan), "nics", len(plan.NICs))
	}
	return err
}

// AppliedState is what a reconcile pass put in force on this host.
type AppliedState struct {
	// Mode is the per-NIC mode rendered: NICModeEnforce, NICModeObserve or
	// NICModeGuardsOnly; "" when the host has no guest NIC.
	Mode string
	// NICTableError is why the per-NIC table was refused, "" when it was not.
	NICTableError string
	// NICs is the guest devices the per-NIC table covers.
	NICs map[string]string // device → workload
	// UnreadablePolicies are the firewall policy rows this build cannot read
	// (Plan.UnreadablePolicies).
	UnreadablePolicies []string
	// MACs is each of those devices' MAC, where known.
	MACs map[string]string // device → MAC
	// Guarded is, per workload, the MACs whose guard the per-NIC table in
	// force holds; empty when the table was refused.
	Guarded map[string]map[string]bool
	// BlockedTrunks are trunk VLANs left out because their network does not
	// allow them (Plan.BlockedTrunks).
	BlockedTrunks []BlockedTrunk
	// InvalidRows are stored rows not rendered as written (Plan.InvalidRows).
	InvalidRows []InvalidRow
	// TagGroups is what the pass could not render as the tag groups ask
	// (Plan.TagGroups).
	TagGroups TagGroupReport
	// SynFlood is the SYN-flood protection the pass rendered;
	// SynFloodUnavailable is as in the Plan.
	SynFlood            SynFlood
	SynFloodUnavailable string
	// SynFloodInForce is what the pass put in force of SYN-flood
	// protection: SynFloodInForceOn, ...IPv4Only or ...IPv6Only (one family
	// refused at start), ...Observe, ...GuardsOnly, ...NoGuestNICs,
	// ...Unavailable or ...Off; "" before the first pass. A refused per-NIC
	// table keeps the previous pass's value (unavailable with none).
	SynFloodInForce string
}

// SetStateHook registers fn to receive the applied state after every pass
// that reached nft. The daemon records health conditions from it.
func (r *Reconciler) SetStateHook(fn func(context.Context, AppliedState)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stateHook = fn
}

// SetPassHook registers fn to hear, after every pass, whether that pass put
// the per-NIC table in force: false for a pass whose plan did not load, whose
// apply failed or ran out of time, or whose per-NIC table the kernel refused.
// The daemon derives its host's NIC-guard label from it (re-review m5).
func (r *Reconciler) SetPassHook(fn func(ctx context.Context, enforcing bool)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.passHook = fn
}

func (r *Reconciler) notifyPass(ctx context.Context, enforcing bool) {
	r.mu.Lock()
	fn := r.passHook
	r.mu.Unlock()
	if fn != nil {
		fn(ctx, enforcing)
	}
}

// AppliedState returns the state the last pass put in force.
func (r *Reconciler) AppliedState() AppliedState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

// loadLogPolicy is the firewall logging block of a pass: the host's log
// policy, rendered only where the kernel loads the forms and the daemon's
// listener holds the group (opts.Logging, LogGate). An unreadable policy row
// is appended to p.UnreadablePolicies (every policy block appends; the pass
// resets the list once) naming its effect.
func loadLogPolicy(ctx context.Context, db *corrosion.Client, hostName string, opts LoaderOptions, p *Plan) error {
	p.LogPolicy = LogPolicy{}
	if opts.Logging == nil {
		return nil
	}
	lp, err := corrosion.ResolveFirewallLogPolicy(ctx, db, hostName)
	if err != nil && !errors.Is(err, corrosion.ErrUnreadableFirewallPolicy) {
		return err
	}
	if err != nil {
		p.UnreadablePolicies = append(p.UnreadablePolicies,
			fmt.Sprintf("%s: read as logging off at %d/%d", strings.TrimPrefix(err.Error(), corrosion.ErrUnreadableFirewallPolicy.Error()+": "), lp.Rate, lp.Burst))
	}
	if avail, group := opts.Logging(); avail {
		p.LogPolicy = LogPolicy{Available: true, Group: group, Default: lp.On(), Rate: lp.Rate, Burst: lp.Burst}
		p.logRecheck = opts.Logging
	}
	return nil
}

// ResolveLogDevice names the workload and MAC of a guest device through the
// plan in force; "" for a device it does not cover. The firewall log
// listener resolves each record's device with it.
func (r *Reconciler) ResolveLogDevice(dev string) (workload, mac string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state.NICs[dev], r.state.MACs[dev]
}

func (r *Reconciler) recordState(ctx context.Context, p Plan, applyErr error) {
	st := AppliedState{NICs: map[string]string{}, MACs: map[string]string{}, Guarded: map[string]map[string]bool{}, BlockedTrunks: p.BlockedTrunks,
		InvalidRows: p.InvalidRows, TagGroups: p.TagGroups,
		SynFlood: p.SynFlood, SynFloodUnavailable: p.SynFloodUnavailable, UnreadablePolicies: p.UnreadablePolicies,
		SynFloodInForce: synFloodInForce(p)}
	if applyErr != nil {
		// The kernel refused the per-NIC table and kept the previous one:
		// what that one put in force still holds; with none (a fresh boot)
		// nothing is.
		r.mu.Lock()
		st.SynFloodInForce = r.state.SynFloodInForce
		r.mu.Unlock()
		if st.SynFloodInForce == "" {
			st.SynFloodInForce = SynFloodInForceUnavailable
		}
	}
	if len(p.NICs) > 0 {
		st.Mode = p.nicMode()
	}
	for _, n := range p.NICs {
		st.NICs[n.NICDev] = n.VMName
		if n.MAC != "" {
			st.MACs[n.NICDev] = strings.ToLower(n.MAC)
		}
		if n.Guard != nil && applyErr == nil {
			if st.Guarded[n.VMName] == nil {
				st.Guarded[n.VMName] = map[string]bool{}
			}
			st.Guarded[n.VMName][strings.ToLower(n.Guard.MAC)] = true
		}
	}
	if applyErr != nil {
		st.NICTableError = applyErr.Error()
	}
	r.mu.Lock()
	r.state = st
	hook := r.stateHook
	r.mu.Unlock()
	if hook != nil {
		hook(ctx, st)
	}
}

// ReconcileForce is Reconcile with the change-detection cache cleared first, so
// the ruleset reaches nft even when the rendered bytes are unchanged.
//
// This is what `lv firewall reload` must call. Routed through plain Reconcile
// it hit the Applier's cache and did nothing — the one command an operator runs
// when they believe the kernel has drifted out from under the daemon was a
// no-op, which is the same defect as the "periodic re-apply self-heals" claim
// above.
//
// Reset also clears the resync timestamp, so the forced apply restarts the
// window rather than leaving the next tick due immediately.
func (r *Reconciler) ReconcileForce(ctx context.Context) error {
	r.applier.Reset()
	return r.Reconcile(ctx)
}

func (r *Reconciler) loop(ctx context.Context) {
	defer close(r.doneCh)
	tick := time.NewTicker(r.interval)
	defer tick.Stop()

	// Run once immediately so we don't wait for the first tick on
	// daemon startup.
	if err := r.Reconcile(ctx); err != nil {
		slog.Warn("firewall: initial reconcile failed", "error", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case <-tick.C:
			if err := r.Reconcile(ctx); err != nil {
				slog.Warn("firewall: reconcile failed", "error", err)
			}
		}
	}
}

func (r *Reconciler) recordErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastErr = err
}

func (r *Reconciler) recordOK() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastErr = nil
	r.lastTick = time.Now()
}

// RunningTaps lists the host device of every NIC of every running domain on
// this host: domain name → lower-cased MAC → tap. libvirt.Client.
// RunningDomainTaps is the production one. A domain that is not running is
// simply absent; an error means libvirt could not be asked at all.
type RunningTaps func() (map[string]map[string]string, error)

// defaultTapTimeout bounds one RunningTaps call. go-libvirt calls take no
// context, so a hung libvirtd would otherwise stall the reconciler — NAT,
// isolation and `lv firewall reload` with it.
const defaultTapTimeout = 10 * time.Second

// LoaderOptions are CorrosionPlanLoader's host-local inputs: what it cannot
// read from the replicated tables.
type LoaderOptions struct {
	// RunningTaps is asked once per pass for the taps of every running
	// domain. The tap recorded in vm_interfaces is never used: it is written
	// once, at create, and libvirt hands out a new vnetN on every start, so
	// after a stop and start, a migration or a failover it names nothing — or
	// another VM's tap on this host. nil renders no VM NIC chains at all.
	//
	// When it errors or times out, the pass fails and Reconcile keeps the
	// ruleset it last applied. Dropping the VM NICs instead would remove every
	// per-NIC chain on the host while libvirt is merely unreachable, and under
	// the default accept policy every VM would run unfiltered until it came
	// back.
	RunningTaps RunningTaps

	// TapTimeout bounds one RunningTaps call; zero means defaultTapTimeout.
	// While a timed-out call is still outstanding, later passes fail at once
	// rather than stack up goroutines behind a hung libvirtd.
	TapTimeout time.Duration

	// TapBridge names the bridge a device is a port of ("" when it is none
	// or cannot be told). nil reads /sys/class/net/<dev>/master. Routed
	// traffic to and from those bridges is decided per NIC in the bridge
	// table rather than a second time in the inet forward chain.
	TapBridge func(dev string) string

	// BridgeConntrack reports whether nf_conntrack_bridge is available on this
	// host (BridgeConntrackAvailable). false renders the guards only, and the
	// daemon raises a health condition; nil means available.
	BridgeConntrack func() bool

	// OnDuplicateSGs, when set, receives after every pass the security-group
	// names that more than one live group holds and that a NIC on this host is
	// bound to, each with the number of this host's NICs held at drop for it.
	// An empty map means none. The daemon exports it as
	// litevirt_firewall_sg_duplicate_name_nics.
	OnDuplicateSGs func(nicsByName map[string]int)

	// OnTagGroupMembers, when set, receives after every pass the number of
	// member workloads of each tag group this replica holds
	// (litevirt_firewall_tag_group_members).
	OnTagGroupMembers func(membersByGroup map[string]int)

	// OnDuplicateAddresses, when set, receives after every pass the
	// addresses on host-isolated networks that live NIC rows of more than one
	// workload hold (corrosion.HostIsolatedDuplicateAddrs); nil or empty
	// means none. A failure to read them is logged and does not fail the
	// pass. The daemon reports them with DuplicateAddressReporter.
	OnDuplicateAddresses func(ctx context.Context, dups []corrosion.DuplicateAddress)

	// Arming, when set, names VMs rendered here whatever host their row
	// names and NICs whose rows are not written yet (see Arming).
	Arming *Arming

	// SynFloodProbe reports, per family, whether the kernel accepted the
	// SYN-flood probe (ProbeSynFlood), run once at start: a refused family
	// is not rendered on this host, and the pass reports it. nil means both
	// accepted.
	SynFloodProbe func() SynFloodProbeResult

	// Now is the loader's clock (time.Now when nil): how long a rule has
	// referenced a missing set (emptySetGrace).
	Now func() time.Time

	// Logging reports whether this host renders log lines (its kernel loads
	// the logging forms, ProbeLogging, and the daemon listens) and the NFLOG
	// group they send to. nil renders none.
	Logging func() (available bool, group uint16)
}

// CorrosionPlanLoader builds a Plan from the cluster's
// security_groups + sg_rules + vm_nics/vm_interfaces tables, scoped to the
// current host.
//
// Per-NIC bindings come from corrosion.ListHostVMNICs: every live NIC in the
// vm_nics/vm_interfaces overlay, with its groups from its vm_nics row when it
// has one (a hot-attached NIC has them nowhere else) and from vm_interfaces
// otherwise. Each VM NIC owned by `hostName` produces a NICBinding on the tap libvirt
// reports for that NIC's MAC right now (opts.RunningTaps). A NIC libvirt does
// not report — its VM is not running, or the NIC is not in the live domain — is
// skipped: there is no device to filter. If libvirt cannot be asked, the pass
// fails and the applied ruleset stays.
//
// A NIC (VM or container) bound to a group name that more than one live group
// holds fails CLOSED: its chain drops everything new and renders neither
// group, with a warning per pass and opts.OnDuplicateSGs. Creating such a name
// is refused (CreateSecurityGroup, stack deploy); this covers rows that exist
// anyway — written before the refusal, by a peer on an older build, or by two
// nodes racing, since the CRDT has no UNIQUE.
func CorrosionPlanLoader(db *corrosion.Client, hostName string, defaults Plan, opts LoaderOptions) PlanLoader {
	taps := &tapFetcher{}
	memory := &rowMemory{}
	tagMem := &tagMemory{}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	tapBridge := opts.TapBridge
	if tapBridge == nil {
		tapBridge = sysfsMaster
	}
	return func(ctx context.Context) (Plan, error) {
		plan := defaults

		// Non-NIC tiers + named address lists + default policy. These were
		// dead in production before v21 (the loader only filled SecurityGroups
		// + NICs); now they come from the cluster_firewall_rules /
		// host_firewall_rules / ip_sets / firewall_defaults tables.
		//
		// A row that cannot be rendered safely (written by a peer on an older
		// build) is never rendered as written and never fails the pass: one
		// bad row would otherwise stop every host's firewall from applying,
		// leaving whatever it last applied — and no chain at all for a NIC
		// that started since. That row alone is held fail-static, and a
		// reference to a set that does not exist matches nothing (see
		// quarantine). Each is reported (Plan.InvalidRows).
		plan.InvalidRows = plan.InvalidRows[:0:0]
		// Every policy block of the pass appends here (once reset, here).
		plan.UnreadablePolicies = plan.UnreadablePolicies[:0:0]
		ipsets, err := corrosion.ListIPSets(ctx, db)
		if err != nil {
			return plan, err
		}
		// Tag groups (tag_groups.go): their sets are declared beside the
		// user's, and a rule's tag:<name> is resolved before it is judged.
		passNow := now()
		// Every host's host tier: a deny on a tag group there matches this
		// host's workloads too (tagPass.noteDeny).
		allHostRules, err := corrosion.ListHostFirewallRules(ctx, db, "")
		if err != nil {
			return plan, err
		}
		tg, err := loadTagGroups(ctx, db, hostName, passNow, tagMem, allHostRules)
		if err != nil {
			return plan, err
		}
		// A user set named for one of litevirt's own, a tag group's lv_tg_*
		// included, is left out there (userSetName).
		var badSets []InvalidRow
		var degraded map[string]bool
		plan.IPSets, badSets, degraded = quarantineIPSets(ipsets)
		plan.IPSets = append(plan.IPSets, tg.sets()...)
		prevRules, emptySince := memory.snapshot()
		q := newQuarantine(plan.IPSets, degraded, prevRules, emptySince, passNow)

		clusterRules, err := corrosion.ListClusterFirewallRules(ctx, db)
		if err != nil {
			return plan, err
		}
		plan.ClusterRules = toFWRules(q, tg, clusterRules, "cluster_firewall_rules")

		var hostRules []corrosion.FirewallRule
		for _, r := range allHostRules {
			if r.HostName == hostName {
				hostRules = append(hostRules, r)
			}
		}
		plan.HostRules = toFWRules(q, tg, hostRules, "host_firewall_rules")

		deny, err := corrosion.ResolveDefaultDeny(ctx, db, hostName)
		if err != nil {
			return plan, err
		}
		plan.DefaultDeny = deny

		// SYN-flood protection (synflood.go).
		plan.SynFlood, plan.SynFloodUnavailable, plan.UnreadablePolicies, err = loadSynFlood(ctx, db, hostName, opts.SynFloodProbe, plan.UnreadablePolicies)
		if err != nil {
			return plan, err
		}

		sgs, err := corrosion.ListSecurityGroups(ctx, db, "")
		if err != nil {
			return plan, err
		}
		// A name two live groups hold cannot be resolved: which one a NIC
		// meant is not in the data. Neither is rendered, and every NIC bound to
		// the name is held at drop (failClosed) — picking one would silently
		// hand the NIC rules nobody chose for it, and a union would accept
		// traffic both groups' owners meant to refuse.
		holders := map[string]int{}
		for _, sg := range sgs {
			holders[sg.Name]++
		}
		plan.SecurityGroups = plan.SecurityGroups[:0:0]
		for _, sg := range sgs {
			if holders[sg.Name] > 1 {
				warnUnattributableLegacyRules(ctx, db, sg.Name)
				continue
			}
			// holders[sg.Name] == 1 here: a duplicated name was skipped above.
			rules, err := corrosion.ListSGRulesFor(ctx, db, sg, true)
			if err != nil {
				return plan, err
			}
			out := SecurityGroup{Name: sg.Name}
			for _, r := range rules {
				if rule, ok := tg.rule(q, "sg_rules", r.ID, r.Direction, r.Proto, r.PortRange, r.CIDR, r.Action, ""); ok {
					out.Rules = append(out.Rules, rule)
				}
			}
			plan.SecurityGroups = append(plan.SecurityGroups, out)
		}

		// Resolve per-NIC SG bindings. Unknown SG names are dropped
		// silently — the renderer would refuse to compile otherwise,
		// taking down the whole firewall on a single typo. Operators
		// see the missing rules but the rest stays applied.
		valid := make(map[string]bool, len(plan.SecurityGroups))
		for _, sg := range plan.SecurityGroups {
			valid[sg.Name] = true
		}
		// A project's group applies only to its own project's NICs
		// (docs/design/security-group-projects.md): for any other NIC it is
		// skipped like an unknown name. A NIC whose workload row has not
		// landed (a create still pending here) passed that check where it
		// was created.
		sgProject := map[string]string{}
		for _, sg := range sgs {
			if sg.Project != "" {
				sgProject[sg.Name] = sg.Project
			}
		}
		var vmProjects, ctProjects map[string]string
		if len(sgProject) > 0 {
			if vmProjects, ctProjects, err = corrosion.WorkloadProjects(ctx, db, hostName); err != nil {
				return plan, err
			}
		}
		foreign := func(kind, owner, name string) bool {
			gp, owned := sgProject[name]
			if !owned {
				return false
			}
			projects := vmProjects
			if kind == corrosion.TagMemberCT {
				projects = ctProjects
			}
			wp, known := projects[owner]
			if !known || tenancy.AdmitAttach(wp, gp) {
				return false
			}
			if _, seen := warnedForeignSG.LoadOrStore(kind+"/"+owner+"/"+name, true); !seen {
				slog.Warn("firewall: a NIC binds another project's security group; not applying it",
					"workload", owner, "project", tenancy.NormalizeProject(wp), "group", name, "group_project", gp)
			}
			return true
		}
		ambiguous := map[string]int{} // duplicate name → this host's NICs held at drop for it
		// bind resolves one NIC's bound names — its own and those its tag
		// groups bind on its network, merged first so the ambiguity check
		// sees them all: the known ones, or, when any of them is a
		// duplicate, none at all plus the drop rules. A NIC whose tag-group
		// membership cannot be proven is held at drop instead.
		bind := func(dev, owner, kind, ctHost, network string, own []string) NICBinding {
			nb := NICBinding{NICDev: dev, VMName: owner}
			if why := tg.hold(kind, ctHost, owner, network, dev); why != "" {
				slog.Warn("firewall: NIC of a workload whose tag-group membership cannot be proven; holding it at drop",
					"workload", owner, "nic", dev, "reason", why)
				nb.ExtraRules = failClosedFor(why)
				return nb
			}
			names := tg.bound(kind, ctHost, owner, network, own)
			var dups []string
			for _, name := range names {
				if holders[name] > 1 {
					dups = append(dups, name)
				}
			}
			if len(dups) > 0 {
				for _, d := range dups {
					ambiguous[d]++
				}
				slog.Warn("firewall: NIC bound to a security-group name more than one live group holds; holding it at drop",
					"workload", owner, "nic", dev, "groups", dups)
				nb.ExtraRules = failClosed()
				return nb
			}
			nb.SecurityGroups = make([]string, 0, len(names))
			for _, name := range names {
				if valid[name] && !foreign(kind, owner, name) {
					nb.SecurityGroups = append(nb.SecurityGroups, name)
				}
			}
			return nb
		}
		armed := opts.Arming.Armed()
		if len(armed) > 0 && opts.RunningTaps != nil {
			// A VM that came here and has gone (its row names another host,
			// libvirt has none of it running here) is not drawn any more.
			gens := opts.Arming.Generations() // before the snapshots below
			gensAt := time.Now()
			// Only an answer from a call that started after gens were read
			// counts: one joined from before may predate an Arm they reflect.
			if live, startedAt, terr := taps.fetchStamped(ctx, opts.RunningTaps, opts.TapTimeout); terr == nil && !startedAt.Before(gensAt) {
				if hosts, herr := vmRowHosts(ctx, db, armed); herr == nil {
					opts.Arming.Settle(hostName, gens, hosts, func(vm string) bool { return len(live[vm]) > 0 })
					armed = opts.Arming.Armed()
				}
			}
		}
		ifaces, err := corrosion.ListHostVMNICs(ctx, db, hostName, armed...)
		if err != nil {
			return plan, err
		}
		// NICs whose rows are not written yet (a create, a hot-attach): rendered
		// from what the create path registered, unless their rows have landed.
		have := map[string]bool{}
		for _, ifc := range ifaces {
			have[ifc.VMName+"|"+strings.ToLower(ifc.MAC)] = true
		}
		for _, p := range opts.Arming.Pending() {
			if !have[p.VMName+"|"+strings.ToLower(p.MAC)] {
				ifaces = append(ifaces, p)
			}
		}
		armedVM := map[string]bool{}
		for _, vm := range armed {
			armedVM[vm] = true
		}
		var running map[string]map[string]string
		if len(ifaces) > 0 && opts.RunningTaps != nil {
			if running, err = taps.fetch(ctx, opts.RunningTaps, opts.TapTimeout); err != nil {
				return plan, fmt.Errorf("read VM taps from libvirt (keeping the applied ruleset): %w", err)
			}
		}
		// NIC guards. A read failure fails the pass like any other, keeping
		// the applied ruleset: dropping the guards instead would unguard every
		// NIC on the host while the database is unreadable.
		allGuards, err := corrosion.ListNICGuardsWithDeleted(ctx, db)
		if err != nil {
			return plan, err
		}
		guards := make(map[string]corrosion.NICGuardRecord, len(allGuards))
		for k, r := range allGuards {
			if !r.Deleted {
				guards[k] = r
			}
		}
		nets, err := corrosion.NetworkGuardInfos(ctx, db)
		if err != nil {
			return plan, err
		}
		assigned, err := corrosion.NetworkAssignedAddrs(ctx, db)
		if err != nil {
			return plan, err
		}
		if opts.OnDuplicateAddresses != nil {
			if dups, derr := corrosion.HostIsolatedDuplicateAddrs(ctx, db); derr != nil {
				slog.Warn("firewall: could not check host-isolated networks for duplicate addresses", "error", derr)
			} else {
				opts.OnDuplicateAddresses(ctx, dups)
			}
		}
		// The trunk VLANs recorded at upgrade (re-review R3-I1): once the
		// recording has run, a trunk carries only what its network allows,
		// record or not.
		recordedVLANs, trunksRecorded, err := corrosion.TrunkVLANsRecorded(ctx, db)
		if err != nil {
			return plan, err
		}
		flatVLANs, err := corrosion.FlatBridgeVLANs(ctx, db)
		if err != nil {
			return plan, err
		}
		// applyRecord sets what a NIC's guard record decides beyond the guard
		// itself: a trunk allowance and a DHCP-server allowance hold whatever
		// the record's mode.
		applyRecord := func(nb *NICBinding, rec corrosion.NICGuardRecord, mac, ip, network string) {
			nb.AllowVLANTags = rec.AllowVLANTags
			nb.DHCPServer = rec.AllowDHCPServer
			info := nets[network]
			nb.Guard = ResolveNICGuard(&rec, mac, ip, info.Subnet, info.All(), assigned[network])
		}
		// recordOf is the NIC's guard record — only one written for the
		// incarnation that runs now: a record an earlier VM of the same name
		// and MAC left guards nothing (re-review m1).
		//
		// A NIC rendered here has a live row (or is pending): a retired
		// record of its incarnation over it is a write order this replica
		// saw out of order, and guards it by default
		// (corrosion.RetiredGuardOver).
		recordOf := func(ifc corrosion.HostVMNIC) (corrosion.NICGuardRecord, bool) {
			key := corrosion.NICGuardKey(ifc.VMName, ifc.MAC)
			rec, ok := guards[key]
			if !ok {
				return corrosion.RetiredGuardOver(allGuards[key], ifc.VMUUID, nets[ifc.NetworkName].Type, ifc.NetworkName)
			}
			if rec.VMUUID != "" && ifc.VMUUID != "" && rec.VMUUID != ifc.VMUUID {
				return corrosion.NICGuardRecord{}, false
			}
			return rec, ok
		}
		plan.NICs = plan.NICs[:0:0]
		plan.BlockedTrunks = plan.BlockedTrunks[:0:0]
		claimed := map[string]string{} // tap → the VM that holds it this pass
		for _, ifc := range ifaces {
			tap := running[ifc.VMName][strings.ToLower(ifc.MAC)]
			if tap == "" {
				// Not running here. A NIC litevirt defined names its tap after
				// its MAC (nictap.Name), so it is rendered under that name
				// before it runs when it has a guard record — a NIC this build
				// created — or its VM is armed: the guard is then in force from
				// the guest's first frame (re-review I-10). Any other NIC is
				// rendered once running, as before.
				_, recorded := recordOf(ifc)
				if recorded || armedVM[ifc.VMName] {
					tap = nictap.Name(ifc.MAC)
				}
			}
			if tap == "" {
				if ifc.VMState == "running" && opts.RunningTaps != nil {
					// libvirt answered and does not have this NIC running.
					slog.Warn("firewall: a VM recorded as running has no tap for this NIC in libvirt; no chain rendered",
						"vm", ifc.VMName, "mac", ifc.MAC)
				}
				continue
			}
			if other, dup := claimed[tap]; dup {
				// Two NICs cannot hold one device; rendering both would emit one
				// chain twice and nft would refuse the whole ruleset.
				slog.Warn("firewall: two VM NICs resolved to one tap; keeping the first",
					"tap", tap, "vm", ifc.VMName, "other_vm", other)
				continue
			}
			claimed[tap] = ifc.VMName
			nb := bind(tap, ifc.VMName, corrosion.TagMemberVM, "", ifc.NetworkName, ifc.SecurityGroups)
			nb.Bridge = tapBridge(tap)
			nb.MAC = strings.ToLower(ifc.MAC)
			nb.TrunkVIDs = ifc.TrunkVIDs
			rec, recorded := recordOf(ifc)
			if recorded {
				applyRecord(&nb, rec, ifc.MAC, ifc.IP, ifc.NetworkName)
			}
			// A trunk carries only the VLANs its network allows (re-review
			// R2-I1). Lacking a guard record grants nothing (R3-I1): the
			// trunks that predate guards had their VLANs recorded into their
			// networks' lists at upgrade, and that list is what they carry.
			// Only until that recording has first run does a trunk with no
			// record keep its own VLANs, so nothing in use breaks while the
			// lists are written.
			if len(ifc.TrunkVIDs) > 0 && (recorded || trunksRecorded) {
				info, known := nets[ifc.NetworkName]
				allowed := info.AllowedVLANs
				if !known {
					// A flat bridge (no network row) carries what was
					// recorded for it at upgrade and what an operator allows
					// on it (`lv network set <bridge> --allowed-vlans`,
					// re-review R4-I1).
					allowed = append(append([]int(nil), recordedVLANs[ifc.NetworkName]...), flatVLANs[ifc.NetworkName]...)
				}
				var blocked []int
				nb.TrunkVIDs, blocked = allowedTrunkVIDs(ifc.TrunkVIDs, allowed)
				nb.TrunkDenied = len(nb.TrunkVIDs) == 0
				if len(blocked) > 0 {
					plan.BlockedTrunks = append(plan.BlockedTrunks, BlockedTrunk{Workload: ifc.VMName, Network: ifc.NetworkName, VIDs: blocked})
				}
			}
			plan.NICs = append(plan.NICs, nb)
		}

		// Container NICs: identical per-NIC SG enforcement on the veth. The loader
		// is host-scoped and ListContainerInterfacesByHost joins the live container
		// row, so only this host's MANAGED, live CT NICs appear; skip a NIC with no
		// veth yet (not provisioned), mirroring the tap_device skip above.
		ctIfaces, err := corrosion.ListContainerInterfacesByHost(ctx, db, hostName)
		if err != nil {
			return plan, err
		}
		// A container being created: its NICs before its rows exist, so the
		// guard is in force when the runtime brings its veth up (re-review
		// m10).
		haveCT := map[string]bool{}
		for _, ifc := range ctIfaces {
			haveCT[ifc.CtName+"|"+strings.ToLower(ifc.MAC)] = true
		}
		for _, p := range opts.Arming.PendingContainers() {
			if !haveCT[p.CtName+"|"+strings.ToLower(p.MAC)] {
				ctIfaces = append(ctIfaces, p)
			}
		}
		for _, ifc := range ctIfaces {
			if ifc.VethDevice == "" {
				continue
			}
			nb := bind(ifc.VethDevice, ifc.CtName, corrosion.TagMemberCT, hostName, ifc.NetworkName, ifc.SecurityGroups)
			nb.Bridge = tapBridge(ifc.VethDevice)
			nb.MAC = strings.ToLower(ifc.MAC)
			if rec, ok := ContainerGuard(guards, hostName, ifc.CtName, ifc.MAC); ok {
				applyRecord(&nb, rec, ifc.MAC, ifc.IP, ifc.NetworkName)
			}
			plan.NICs = append(plan.NICs, nb)
		}
		if opts.OnDuplicateSGs != nil {
			opts.OnDuplicateSGs(ambiguous)
		}
		plan.TagGroups = tg.finish()
		if opts.OnTagGroupMembers != nil {
			opts.OnTagGroupMembers(plan.TagGroups.Members)
		}
		plan.IPSets = append(plan.IPSets, q.sets()...)
		for _, s := range tg.emptySets() {
			// A rendering kept from an earlier pass may have declared a gone
			// group's empty set already (quarantine.judgingKept); nft refuses
			// a ruleset that declares a set twice.
			if !q.emptySets[s.Name] {
				plan.IPSets = append(plan.IPSets, s)
			}
		}
		plan.InvalidRows = append(append(plan.InvalidRows, badSets...), q.invalid...)
		warnInvalidRows(plan.InvalidRows)

		// NAT / SNAT / host-isolation infra: read this host's resolved intent
		// (written by network provisioning + LB apply) and fold it into the same
		// atomic ruleset. Empty → no nat/input chains, identical to before v40.
		intents, err := corrosion.ListHostFWIntent(ctx, db, hostName)
		if err != nil {
			return plan, err
		}
		plan.NAT, plan.HostIsolation = intentToNATIsolation(intents)

		// Per-NIC enforcement mode: the replicated policy (no row: observe),
		// unless bridge conntrack is unavailable on this host, in which case
		// only the guards and the VLAN rule — which need none — are rendered.
		enf, err := corrosion.GetFirewallEnforcement(ctx, db)
		if err != nil {
			return plan, err
		}
		plan.NICMode = NICModeObserve
		if enf.Mode == corrosion.FirewallEnforce {
			plan.NICMode = NICModeEnforce
		}
		if opts.BridgeConntrack != nil && !opts.BridgeConntrack() {
			plan.NICMode = NICModeGuardsOnly
		}
		if err := loadLogPolicy(ctx, db, hostName, opts, &plan); err != nil {
			return plan, err
		}
		// The addresses of litevirt's own dnsmasq on the guest networks: only
		// where litevirt is the network's router (re-review I-9).
		plan.Gateways = plan.Gateways[:0:0]
		for _, info := range nets {
			if info.LitevirtGateway != "" {
				plan.Gateways = append(plan.Gateways, info.LitevirtGateway)
			}
		}
		sort.Strings(plan.Gateways)
		// Every live isolated network's bridge: forwarding off it is dropped
		// (renderIsolatedForward), as it is for every bridge in the group.
		isolated := map[string]bool{}
		for _, info := range nets {
			if info.IsolatedBridge != "" {
				isolated[info.IsolatedBridge] = true
			}
		}
		plan.IsolatedBridges = plan.IsolatedBridges[:0:0]
		for br := range isolated {
			// The group lines still hold a name the renderer would refuse.
			if safeIfName(br) {
				plan.IsolatedBridges = append(plan.IsolatedBridges, br)
			}
		}
		sort.Strings(plan.IsolatedBridges)
		var lbHosts map[string]bool
		if plan.LBBackends, plan.LBSources, lbHosts, err = loadLBBackends(ctx, db); err != nil {
			return plan, err
		}
		for _, gw := range plan.Gateways {
			plan.LBSources = append(plan.LBSources, gw)
		}
		// haproxy on another host reaches a backend here from that host's
		// address (re-review m-d) — only the hosts an LB runs on (m6): any
		// other host's address would let its masqueraded guests reach a
		// backend's port past the backend's own groups.
		if len(lbHosts) > 0 {
			hosts, err := corrosion.ListHosts(ctx, db)
			if err != nil {
				return plan, err
			}
			for _, h := range hosts {
				if !lbHosts[h.Name] {
					continue
				}
				if a, err := netip.ParseAddr(h.Address); err == nil && a.Is4() {
					plan.LBSources = append(plan.LBSources, a.String())
				}
			}
		}
		memory.store(q)
		return plan, nil
	}
}

// ContainerGuard finds a container NIC's guard record. Its key names the host
// the container was created on (container names are per host), so a container
// that migrated or was relocated finds its record under the host it came from,
// by its name and MAC (re-review m-f); a record written on its current host
// (`lv firewall nic-guard set --container`) wins, then the newest.
func ContainerGuard(guards map[string]corrosion.NICGuardRecord, host, name, mac string) (corrosion.NICGuardRecord, bool) {
	if rec, ok := guards[corrosion.NICGuardKey(corrosion.ContainerGuardOwner(host, name), mac)]; ok {
		return rec, true
	}
	var best corrosion.NICGuardRecord
	found := false
	for _, rec := range guards {
		h, n, ok := corrosion.ParseContainerGuardOwner(rec.VMName)
		if !ok || n != name || h == host || !strings.EqualFold(rec.MAC, mac) {
			continue
		}
		if !found || rec.UpdatedAt > best.UpdatedAt {
			best, found = rec, true
		}
	}
	return best, found
}

// loadLBBackends lists every enabled built-in load balancer's backend
// endpoints and its VIP: haproxy, on the LB's host, connects to the backends
// from the host's address on the guest network or from the VIP.
func loadLBBackends(ctx context.Context, db *corrosion.Client) ([]LBBackend, []string, map[string]bool, error) {
	cfgs, err := corrosion.ListLBConfigs(ctx, db)
	if err != nil {
		return nil, nil, nil, err
	}
	var out []LBBackend
	var srcs []string
	hosts := map[string]bool{}
	for _, cfg := range cfgs {
		if !cfg.Enabled {
			continue
		}
		var lbHosts []string
		_ = json.Unmarshal([]byte(cfg.Hosts), &lbHosts)
		for _, h := range lbHosts {
			hosts[h] = true
		}
		if vip, err := netip.ParsePrefix(cfg.VIP); err == nil {
			srcs = append(srcs, vip.Addr().String())
		} else if vip, err := netip.ParseAddr(cfg.VIP); err == nil {
			srcs = append(srcs, vip.String())
		}
		var ports []struct {
			Target   int    `json:"target"`
			Protocol string `json:"protocol"`
		}
		_ = json.Unmarshal([]byte(cfg.Ports), &ports)
		targets := map[int]bool{}
		for _, p := range ports {
			if p.Target > 0 {
				targets[p.Target] = true
			}
		}
		if len(targets) == 0 {
			targets[80] = true // the LB's documented default backend port
		}
		bs, err := corrosion.ListLBBackends(ctx, db, cfg.Name)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, b := range bs {
			if !b.Enabled {
				continue
			}
			addr := b.Address
			if h, _, err := net.SplitHostPort(addr); err == nil {
				addr = h
			}
			for port := range targets {
				out = append(out, LBBackend{Addr: addr, Port: port})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr != out[j].Addr {
			return out[i].Addr < out[j].Addr
		}
		return out[i].Port < out[j].Port
	})
	sort.Strings(srcs)
	return out, srcs, hosts, nil
}

// allowedTrunkVIDs splits a trunk's VLANs into those its network allows and
// the rest.
func allowedTrunkVIDs(trunk, allowed []int) (keep, blocked []int) {
	ok := map[int]bool{}
	for _, v := range allowed {
		ok[v] = true
	}
	for _, v := range trunk {
		if ok[v] {
			keep = append(keep, v)
		} else {
			blocked = append(blocked, v)
		}
	}
	return keep, blocked
}

// ResolveNICGuard turns a NIC's guard record into the renderer's guard, or
// nil when the NIC is not guarded (no record, or an "off" one).
//
// Each address family is restricted only when something says which addresses
// the guest owns in it: an address litevirt assigned (nicIP, the record's
// Known list), the network's subnet when no address is assigned, or an
// address the operator listed in Allowed. A family nothing is known about is
// left unrestricted, because a guest served by a DHCP server or router
// litevirt does not run has addresses nobody told it about, and cutting it off
// would break it. The MAC, ARP, DHCP-server and router-advertisement guards
// apply regardless.
//
// An entry that does not parse is skipped rather than allowed to reach the
// renderer, which would refuse the whole ruleset.
//
// reserved are the network's infrastructure addresses — its router where it
// is litevirt's, its configured gateway and reserved addresses, the gateways
// its NICs route through (corrosion.NetworkGuardInfo.All) — which a guest
// confined to its subnet may never claim.
func ResolveNICGuard(rec *corrosion.NICGuardRecord, mac, nicIP, subnet string, reserved, assigned []string) *NICGuard {
	if rec == nil || !rec.Guarded() {
		return nil
	}
	g := &NICGuard{MAC: strings.ToLower(mac), AllowDHCPServer: rec.AllowDHCPServer, AllowRouterAdvert: rec.AllowRouterAdvert}
	var v4, v6 []string
	own := map[string]bool{}
	assigned4, assigned6 := false, false
	add := func(s string, isAssigned bool) {
		p, ok := parseGuardEntry(s, isAssigned)
		if !ok {
			if s != "" {
				slog.Warn("firewall: skipping an unparseable NIC guard address", "vm", rec.VMName, "mac", mac, "address", s)
			}
			return
		}
		if p.Addr().Is6() && p.Addr().IsLinkLocalUnicast() && p.IsSingleIP() {
			// A link-local address is the guest's on its link only; it is
			// held separately from the global ones (NICGuard.LinkLocal).
			g.LinkLocal = append(g.LinkLocal, p.Addr().String())
			return
		}
		if p.IsSingleIP() {
			own[p.Addr().String()] = true
		}
		if p.Addr().Is4() {
			v4 = append(v4, guardEntryString(p))
			assigned4 = assigned4 || isAssigned
		} else {
			v6 = append(v6, guardEntryString(p))
			assigned6 = assigned6 || isAssigned
		}
	}
	add(nicIP, true)
	for _, k := range rec.Known {
		add(k, true)
	}
	for _, a := range rec.Allowed {
		add(a, false)
	}
	if sp, err := netip.ParsePrefix(strings.TrimSpace(subnet)); err == nil && sp.Addr().Zone() == "" {
		sp = sp.Masked()
		v4net := sp.Addr().Is4()
		if (v4net && !assigned4) || (!v4net && !assigned6) {
			// No exact address is known, so the guest may use one from the
			// subnet — but never the network's own addresses, nor one that
			// is assigned to another NIC on it: claiming those is how a guest
			// impersonates the gateway or a neighbour.
			excl := subnetReserved(sp)
			for _, a := range reserved {
				if ap, err := netip.ParseAddr(a); err == nil && sp.Contains(ap) && !own[ap.String()] {
					excl = append(excl, ap.String())
				}
			}
			for _, a := range assigned {
				if ap, err := netip.ParseAddr(a); err == nil && sp.Contains(ap) && !own[ap.String()] {
					excl = append(excl, ap.String())
				}
			}
			excl = sortedAddrs(excl)
			if v4net {
				v4 = append(v4, sp.String())
				g.ExcludeV4 = excl
			} else {
				v6 = append(v6, sp.String())
				g.ExcludeV6 = excl
			}
		}
	}
	if len(v4) > 0 {
		g.V4 = v4
	}
	if len(v6) > 0 {
		g.V6 = v6
	}
	return g
}

// sortedAddrs sorts addresses numerically and drops duplicates.
func sortedAddrs(in []string) []string {
	addrs := make([]netip.Addr, 0, len(in))
	for _, a := range in {
		if ap, err := netip.ParseAddr(a); err == nil {
			addrs = append(addrs, ap)
		}
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
	out := make([]string, 0, len(addrs))
	for i, a := range addrs {
		if i == 0 || a != addrs[i-1] {
			out = append(out, a.String())
		}
	}
	return out
}

// subnetReserved is a subnet's own addresses: the network address and, for
// IPv4, the broadcast address. The router is not among them: it is whatever
// the network says it is (ResolveNICGuard's reserved), not simply the first
// host.
func subnetReserved(sp netip.Prefix) []string {
	out := []string{sp.Addr().String()}
	if sp.Addr().Is4() {
		b := sp.Addr().As4()
		bits := sp.Bits()
		for i := 0; i < 4; i++ {
			for j := 0; j < 8; j++ {
				if i*8+j >= bits {
					b[i] |= 0x80 >> j
				}
			}
		}
		out = append(out, netip.AddrFrom4(b).String())
	}
	return out
}

// parseGuardEntry reads one guard address. An assigned address is a host
// address even when written with its prefix length ("10.0.0.5/24" is
// 10.0.0.5); an allowed entry's prefix length means a prefix.
func parseGuardEntry(s string, assigned bool) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, false
	}
	if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Zone() == "" {
		if assigned {
			return netip.PrefixFrom(p.Addr(), p.Addr().BitLen()), true
		}
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// guardEntryString renders a host prefix as a bare address, the form nft
// prints and the form operators write.
func guardEntryString(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// failClosed is the chain body of a NIC whose groups cannot be resolved: drop
// everything new in both directions. Replies to connections the NIC already
// had still pass (the forward chain accepts established flows before any NIC
// chain). The nft comment is fixed text, because nft caps a comment at 128
// bytes and a group name is unbounded; the names go to the log and the metric.
func failClosed() []Rule {
	return failClosedFor("ambiguous security group name: held at drop")
}

// failClosedFor is failClosed with why as the rules' comment.
func failClosedFor(why string) []Rule {
	return []Rule{
		{Direction: Ingress, Proto: "all", Action: Drop, Comment: why},
		{Direction: Egress, Proto: "all", Action: Drop, Comment: why},
	}
}

// tapFetcher runs at most one RunningTaps call at a time under a deadline.
// Reconcile is not serialized (the 30s loop, `lv firewall reload` and the RPCs
// that reconcile after provisioning a network all call it), so a pass that
// arrives while a call is in flight JOINS it and shares its answer. It waits
// under its own deadline, measured from when it arrived.
//
// The call cannot be cancelled (go-libvirt takes no context). A call that has
// overrun the deadline is presumed hung: until it returns, every pass fails at
// once with errTapFetchOutstanding instead of waiting on it again or stacking
// another call behind it.
type tapFetcher struct {
	mu       sync.Mutex
	inflight *tapCall
}

// tapCall is one in-flight RunningTaps call. taps and err are written once,
// before done is closed.
type tapCall struct {
	started time.Time
	done    chan struct{}
	taps    map[string]map[string]string
	err     error
}

var errTapFetchOutstanding = errors.New("an earlier libvirt tap lookup overran its deadline and has not returned")

func (f *tapFetcher) fetch(ctx context.Context, src RunningTaps, timeout time.Duration) (map[string]map[string]string, error) {
	taps, _, err := f.fetchStamped(ctx, src, timeout)
	return taps, err
}

// fetchStamped is fetch, also saying when the libvirt call that answered
// started: a pass that joined an older call gets an older answer.
func (f *tapFetcher) fetchStamped(ctx context.Context, src RunningTaps, timeout time.Duration) (map[string]map[string]string, time.Time, error) {
	if timeout <= 0 {
		timeout = defaultTapTimeout
	}
	f.mu.Lock()
	call := f.inflight
	if call != nil && time.Since(call.started) > timeout {
		f.mu.Unlock()
		return nil, time.Time{}, errTapFetchOutstanding
	}
	if call == nil {
		call = &tapCall{started: time.Now(), done: make(chan struct{})}
		f.inflight = call
		go func() {
			m, err := src()
			f.mu.Lock()
			call.taps, call.err = m, err
			f.inflight = nil
			f.mu.Unlock()
			close(call.done)
		}()
	}
	f.mu.Unlock()

	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-call.done:
		return call.taps, call.started, call.err
	case <-t.C:
		return nil, time.Time{}, fmt.Errorf("libvirt did not answer within %s", timeout)
	case <-ctx.Done():
		return nil, time.Time{}, ctx.Err()
	}
}

// intentToNATIsolation aggregates per-host firewall intent rows into the
// renderer's NAT + isolation inputs.
//
// Isolation is OWNED by network intent (scope "net:<name>"): only a net row can
// mark a bridge isolated. An LB row (scope "lb:<name>") contributes VIP:port
// exceptions and SNAT but never isolation authority — so a stale LB row can't keep
// a bridge dropped after the network's isolation is removed. SNAT likewise renders
// only while the bridge still has a base isolated-network intent.
func intentToNATIsolation(intents []corrosion.HostFWIntent) ([]NATRule, []IsolationChain) {
	isolated := map[string]bool{}
	for _, in := range intents {
		if in.Bridge != "" && in.Isolate && strings.HasPrefix(in.ScopeKey, "net:") {
			isolated[in.Bridge] = true
		}
	}

	var nat []NATRule
	exc := map[string][]IsolationException{}
	for _, in := range intents {
		if in.MasqueradeSubnet != "" {
			nat = append(nat, NATRule{Subnet: in.MasqueradeSubnet, Bridge: in.Bridge})
		}
		if in.SNATVIP != "" && isolated[in.Bridge] {
			nat = append(nat, NATRule{OutIface: in.SNATOutIface, Subnet: in.SNATSubnet, SNATTo: in.SNATVIP})
		}
		for _, e := range in.Exceptions {
			exc[in.Bridge] = append(exc[in.Bridge], IsolationException{VIP: e.VIP, Ports: e.Ports})
		}
	}

	// One isolation chain per isolated bridge, merging exceptions from every row
	// (the net base + any LB holes) for it. Sorted for determinism (renderer re-sorts).
	bridges := make([]string, 0, len(isolated))
	for b := range isolated {
		bridges = append(bridges, b)
	}
	sort.Strings(bridges)
	var iso []IsolationChain
	for _, b := range bridges {
		iso = append(iso, IsolationChain{Bridge: b, Exceptions: exc[b]})
	}
	return nat, iso
}

// toFWRules converts the on-disk cluster/host-tier rows of table into
// renderer Rules, preserving the operator-supplied comment. A row that cannot
// be rendered as written is handled by q.
func toFWRules(q *quarantine, tg *tagPass, in []corrosion.FirewallRule, table string) []Rule {
	out := make([]Rule, 0, len(in))
	for _, r := range in {
		if rule, ok := tg.rule(q, table, r.ID, r.Direction, r.Proto, r.PortRange, r.CIDR, r.Action, r.Comment); ok {
			out = append(out, rule)
		}
	}
	return out
}

func countRules(p Plan) int {
	n := len(p.ClusterRules) + len(p.HostRules)
	for _, sg := range p.SecurityGroups {
		n += len(sg.Rules)
	}
	for _, nic := range p.NICs {
		n += len(nic.ExtraRules)
	}
	return n
}

// sysfsMaster reads the bridge a device is enslaved to from sysfs. A name
// that is not a safe interface name is never returned: it is rendered into
// the ruleset.
func sysfsMaster(dev string) string {
	if dev == "" || strings.ContainsAny(dev, "/ ") {
		return ""
	}
	target, err := os.Readlink(filepath.Join("/sys/class/net", dev, "master"))
	if err != nil {
		return ""
	}
	name := filepath.Base(target)
	for _, r := range name {
		if !(r == '-' || r == '_' || r == '.' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return ""
		}
	}
	return name
}

// vmRowHosts is the host each live VM of names has on its row; a name with no
// live VM row (a container, a VM not created yet) is absent.
func vmRowHosts(ctx context.Context, db *corrosion.Client, names []string) (map[string]string, error) {
	args := make([]interface{}, len(names))
	for i, n := range names {
		args[i] = n
	}
	rows, err := db.Query(ctx, `SELECT name, COALESCE(host_name, '') AS host_name FROM vms
		 WHERE deleted_at IS NULL AND name IN (?`+strings.Repeat(", ?", len(names)-1)+`)`, args...)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.String("name")] = r.String("host_name")
	}
	return out, nil
}
