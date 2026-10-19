package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/litevirt/litevirt/internal/cmdbound"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// SYN-flood protection on guest NICs (docs/firewall.md, "SYN-flood
// protection"): in the per-NIC bridge table, in enforce and observe mode, two
// dynamic sets keyed per (guest NIC, source address) and one line per family
// in the forward and output chains, immediately before the nic_in_ dispatch.
// Guards-only mode renders neither.

// SynFlood is the SYN-flood policy in force on this host. Rate is new SYNs
// per second per (guest NIC, source address), Burst packets; each 1-100000
// when On.
type SynFlood struct {
	On          bool
	Rate, Burst int
}

const (
	synFloodMin = 1
	synFloodMax = 100000

	setSyn4 = "lv_syn4"
	setSyn6 = "lv_syn6"

	// SynFloodComment prefixes the comment of the enforce-mode drop counters:
	// "lv-sf 4" and "lv-sf 6".
	SynFloodComment = "lv-sf"
)

// validateSynFlood refuses a rate or burst the renderer would not write as
// recorded.
func validateSynFlood(s SynFlood) error {
	if !s.On {
		return nil
	}
	if s.Rate < synFloodMin || s.Rate > synFloodMax || s.Burst < synFloodMin || s.Burst > synFloodMax {
		return fmt.Errorf("SYN-flood rate %d and burst %d must each be %d-%d", s.Rate, s.Burst, synFloodMin, synFloodMax)
	}
	return nil
}

// renderSynFloodSets declares the two meters' sets when the plan limits SYNs.
func renderSynFloodSets(b *strings.Builder, p Plan) {
	if !p.SynFlood.On {
		return
	}
	for _, s := range []struct{ name, addr string }{{setSyn4, "ipv4_addr"}, {setSyn6, "ipv6_addr"}} {
		fmt.Fprintf(b, "    set %s {\n        type ifname . %s\n        size 65536\n        flags dynamic,timeout\n        timeout 60s\n    }\n\n", s.name, s.addr)
	}
}

// renderSynFloodLines emits the per-family limit, which a chain places
// immediately before its nic_in_ dispatch. `meta protocol` comes first, so
// the bridge family adds no implicit `ether type` (which would miss a trunk's
// tagged SYNs), and `meta l4proto tcp` finds TCP behind IPv6 extension
// headers. No source is exempt: the load balancer's flows to its backends are
// accepted earlier in the chain, by (source, backend, port). An IPv6 source
// is keyed by its /64, so one host rotating addresses within its prefix
// shares one budget. The comment ends the rule: nft refuses a verdict after
// it.
func renderSynFloodLines(b *strings.Builder, p Plan) {
	if !p.SynFlood.On {
		return
	}
	limit := fmt.Sprintf("limit rate over %d/second burst %d packets", p.SynFlood.Rate, p.SynFlood.Burst)
	for _, f := range []struct{ fam, set, key, n string }{
		{"ip", setSyn4, "ip saddr", "4"},
		{"ip6", setSyn6, "ip6 saddr & " + synFloodV6Mask, "6"},
	} {
		action := "counter drop comment " + quoteComment(SynFloodComment+" "+f.n)
		if p.nicMode() == NICModeObserve {
			action = verdict(p, "-", "in", "synflood")
		}
		fmt.Fprintf(b, "        oifname @%s meta protocol %s meta l4proto tcp tcp flags & (fin|syn|rst|ack) == syn update @%s { oifname . %s %s } %s\n",
			setNICDevs, f.fam, f.set, f.key, limit, action)
	}
}

// synFloodV6Mask keys an IPv6 source by its /64.
const synFloodV6Mask = "ffff:ffff:ffff:ffff::"

// ProbeSynFlood asks the kernel, without loading anything, whether it accepts
// the renderer's own SYN-flood sets and lines (ProbeRuleset): the set they
// name, the meters, and one line per family in a forward chain. The daemon
// runs it once at start (LoaderOptions.SynFloodProbe).
func ProbeSynFlood(ctx context.Context) error {
	p := Plan{SynFlood: SynFlood{On: true, Rate: corrosion.SynfloodDefaultRate, Burst: corrosion.SynfloodDefaultBurst}}
	var b strings.Builder
	renderIfnameSet(&b, setNICDevs, nil)
	renderSynFloodSets(&b, p)
	b.WriteString("    chain forward {\n        type filter hook forward priority 0; policy accept;\n")
	renderSynFloodLines(&b, p)
	b.WriteString("    }\n")
	return ProbeRuleset(ctx, b.String())
}

// loadSynFlood is the loader's SYN-flood block: host's policy (its own row,
// else the cluster's, else off) as this host renders it.
//   - A row this build cannot read protects at the defaults, and is reported
//     (unreadable).
//   - A kernel that refused the probe renders nothing, and is reported
//     (unavailable) while the policy asks for protection.
//
// Whatever the path, the result passes validateSynFlood, which would
// otherwise refuse the whole plan.
//
// unreadable is the pass's list so far (Plan.UnreadablePolicies, shared with
// the other policy blocks); the SYN-flood entry is appended to it.
func loadSynFlood(ctx context.Context, db *corrosion.Client, host string, probe func() error, unreadable []string) (sf SynFlood, unavailable string, _ []string, err error) {
	pol, err := corrosion.ResolveFirewallSynflood(ctx, db, host)
	switch {
	case errors.Is(err, corrosion.ErrUnreadableFirewallPolicy):
		// <key> holds "<value>": <what is enforced>, the shape every
		// policy block appends for firewall.policy.unreadable's one raiser.
		held := strings.TrimPrefix(err.Error(), corrosion.ErrUnreadableFirewallPolicy.Error()+": ")
		unreadable = append(unreadable, fmt.Sprintf("%s: read as on at %d/%d",
			held, corrosion.SynfloodDefaultRate, corrosion.SynfloodDefaultBurst))
	case err != nil:
		return SynFlood{}, "", unreadable, err
	}
	if !pol.On() {
		return SynFlood{}, "", unreadable, nil
	}
	// The resolver reads an out-of-range row as unreadable (on at the
	// defaults), so an on policy is always in range here.
	sf = SynFlood{On: true, Rate: pol.Rate, Burst: pol.Burst}
	if probe != nil {
		if perr := probe(); perr != nil {
			return SynFlood{}, perr.Error(), unreadable, nil
		}
	}
	return sf, "", unreadable, nil
}

// nftListNICTable lists the per-NIC table as JSON: nft's stdout, or its
// stderr when it fails. Tests replace it.
var nftListNICTable = func(ctx context.Context) ([]byte, error) {
	out, err := cmdbound.Output(ctx, cmdbound.Command(ctx, "nft", "-j", "list", "table", "bridge", NICTableName))
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.Stderr, err
	}
	return out, err
}

// SynFloodDrops reads this host's SYN-flood drops per family since the per-NIC
// table was last loaded: the lv-sf 4 and lv-sf 6 counters. A host with no
// per-NIC table has dropped nothing; any other failure is an error, so a
// count that could not be read is never reported as zero.
func SynFloodDrops(ctx context.Context) (v4, v6 uint64, err error) {
	out, err := nftListNICTable(ctx)
	if err != nil {
		if strings.Contains(string(out), "No such file or directory") {
			return 0, 0, nil
		}
		return 0, 0, fmt.Errorf("list the per-NIC table: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return parseSynFloodDrops(out)
}

// parseSynFloodDrops sums the lv-sf counters of `nft -j` output per family.
func parseSynFloodDrops(js []byte) (v4, v6 uint64, err error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(js, &doc); err != nil {
		return 0, 0, fmt.Errorf("parse nft json: %w", err)
	}
	for _, obj := range doc.Nftables {
		raw, ok := obj["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Comment string            `json:"comment"`
			Expr    []json.RawMessage `json:"expr"`
		}
		if json.Unmarshal(raw, &rule) != nil {
			continue
		}
		var total *uint64
		switch rule.Comment {
		case SynFloodComment + " 4":
			total = &v4
		case SynFloodComment + " 6":
			total = &v6
		default:
			continue
		}
		for _, e := range rule.Expr {
			var c struct {
				Counter *struct {
					Packets uint64 `json:"packets"`
				} `json:"counter"`
			}
			if json.Unmarshal(e, &c) == nil && c.Counter != nil {
				*total += c.Counter.Packets
			}
		}
	}
	return v4, v6, nil
}

// What a pass put in force of SYN-flood protection (AppliedState.SynFloodInForce).
const (
	SynFloodInForceOn          = "on"
	SynFloodInForceObserve     = "observe"
	SynFloodInForceGuardsOnly  = "guards-only"
	SynFloodInForceUnavailable = "unavailable"
	SynFloodInForceOff         = "off"
	SynFloodInForceNoGuestNICs = "no-guest-nics"
)

// synFloodInForce is what a plan puts in force of SYN-flood protection: the
// lines drop only in enforce mode; observe mode counts them; guards-only mode,
// and a host with no guest NIC (no per-NIC table), render none.
func synFloodInForce(p Plan) string {
	switch {
	case p.SynFloodUnavailable != "":
		return SynFloodInForceUnavailable
	case !p.SynFlood.On:
		return SynFloodInForceOff
	case len(p.NICs) == 0:
		// No per-NIC table is rendered: nothing to limit yet.
		return SynFloodInForceNoGuestNICs
	case p.nicMode() == NICModeGuardsOnly:
		return SynFloodInForceGuardsOnly
	case p.nicMode() == NICModeObserve:
		return SynFloodInForceObserve
	}
	return SynFloodInForceOn
}
