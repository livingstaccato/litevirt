package firewall

import (
	"fmt"
	"strings"
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
// headers. The load balancer's sources are exempt. The comment ends the rule:
// nft refuses a verdict after it.
func renderSynFloodLines(b *strings.Builder, p Plan) {
	if !p.SynFlood.On {
		return
	}
	limit := fmt.Sprintf("limit rate over %d/second burst %d packets", p.SynFlood.Rate, p.SynFlood.Burst)
	for _, f := range []struct{ fam, ip, set, exempt, n string }{
		{"ip", "ip", setSyn4, fmt.Sprintf(" ip saddr != @%s", setLBSrc4), "4"},
		{"ip6", "ip6", setSyn6, "", "6"},
	} {
		action := "counter drop comment " + quoteComment(SynFloodComment+" "+f.n)
		if p.nicMode() == NICModeObserve {
			action = verdict(p, "-", "in", "synflood")
		}
		fmt.Fprintf(b, "        oifname @%s meta protocol %s meta l4proto tcp tcp flags & (fin|syn|rst|ack) == syn%s update @%s { oifname . %s saddr %s } %s\n",
			setNICDevs, f.fam, f.exempt, f.set, f.ip, limit, action)
	}
}
