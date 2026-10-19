package firewall

import (
	"strings"
	"testing"
)

// SYN-flood protection on guest NICs (spec §1.5): two dynamic sets in the
// bridge table and one line per family in the forward and output chains,
// immediately before the nic_in_ dispatch.

const (
	wantSynSet4 = "    set lv_syn4 {\n        type ifname . ipv4_addr\n        size 65536\n        flags dynamic,timeout\n        timeout 60s\n    }\n"
	wantSynSet6 = "    set lv_syn6 {\n        type ifname . ipv6_addr\n        size 65536\n        flags dynamic,timeout\n        timeout 60s\n    }\n"

	// The counter's comment is the rule's last word: nft refuses a verdict
	// after it (TestKernelChild_SynFloodShapeLoads).
	wantSynLine4 = `oifname @lv_nic_devs meta protocol ip meta l4proto tcp tcp flags & (fin|syn|rst|ack) == syn update @lv_syn4 { oifname . ip saddr limit rate over 250/second burst 1500 packets } counter drop comment "lv-sf 4"`
	wantSynLine6 = `oifname @lv_nic_devs meta protocol ip6 meta l4proto tcp tcp flags & (fin|syn|rst|ack) == syn update @lv_syn6 { oifname . ip6 saddr & ffff:ffff:ffff:ffff:: limit rate over 250/second burst 1500 packets } counter drop comment "lv-sf 6"`
)

func synFloodPlan(mode string) Plan {
	return Plan{
		NICMode:   mode,
		SynFlood:  SynFlood{On: true, Rate: 250, Burst: 1500},
		LBSources: []string{"10.0.0.1"},
		NICs: []NICBinding{
			{NICDev: "tap-b", VMName: "b"},
			{NICDev: "tap-a", VMName: "a"},
		},
	}
}

func renderNICPart(t *testing.T, p Plan) string {
	t.Helper()
	_, nic, err := RenderParts(p, true)
	if err != nil {
		t.Fatalf("RenderParts: %v", err)
	}
	return nic
}

// synChainLines is the trimmed lines of the named chain of a rendered table.
func synChainLines(t *testing.T, script, chain string) []string {
	t.Helper()
	start := strings.Index(script, "    chain "+chain+" {\n")
	if start < 0 {
		t.Fatalf("no chain %q in:\n%s", chain, script)
	}
	rest := script[start+len("    chain "+chain+" {\n"):]
	end := strings.Index(rest, "\n    }\n")
	var out []string
	for _, l := range strings.Split(rest[:end], "\n") {
		out = append(out, strings.TrimSpace(l))
	}
	return out
}

func countContaining(lines []string, sub string) int {
	n := 0
	for _, l := range lines {
		if strings.Contains(l, sub) {
			n++
		}
	}
	return n
}

// When on, the bridge table declares the two sets, ahead of every chain, and
// the forward and output chains carry one line per family immediately before
// the nic_in_ dispatch: after the sender's egress (whose accept returns), so a
// guest-to-guest SYN meets it, and before the receiver's ingress accept. The
// match names `meta protocol` first (no implicit `ether type`, which misses a
// trunk's tagged SYNs) and `meta l4proto tcp` (TCP behind IPv6 extension
// headers); no source is exempt (the load balancer's flows to its backends
// are accepted earlier in each chain); IPv6 sources are keyed per /64; each
// line counts what it drops under "lv-sf <family>".
//
// Mutations: move the lines after the dispatch; use `ip6 nexthdr tcp`; drop
// the `meta protocol` prefix; exempt lv_lb_src4 again; key IPv6 per address.
func TestRender_SynFloodLines(t *testing.T) {
	nic := renderNICPart(t, synFloodPlan(NICModeEnforce))

	for _, set := range []string{wantSynSet4, wantSynSet6} {
		if n := strings.Count(nic, set); n != 1 {
			t.Errorf("set declared %d times, want once:\n%s", n, set)
		}
		if i, c := strings.Index(nic, set), strings.Index(nic, "    chain "); i < 0 || i > c {
			t.Errorf("set not declared before the first chain:\n%s", set)
		}
	}

	for _, chain := range []string{"forward", "output"} {
		lines := synChainLines(t, nic, chain)
		first := -1
		for i, l := range lines {
			if strings.Contains(l, " jump nic_in_") {
				first = i
				break
			}
		}
		if first < 2 {
			t.Fatalf("%s: no room before the nic_in_ dispatch:\n%s", chain, strings.Join(lines, "\n"))
		}
		if lines[first-2] != wantSynLine4 || lines[first-1] != wantSynLine6 {
			t.Errorf("%s: the two lines before the nic_in_ dispatch are\n  %s\n  %s\nwant\n  %s\n  %s",
				chain, lines[first-2], lines[first-1], wantSynLine4, wantSynLine6)
		}
		if n4, n6 := countContaining(lines, "@lv_syn4"), countContaining(lines, "@lv_syn6"); n4 != 1 || n6 != 1 {
			t.Errorf("%s: %d IPv4 and %d IPv6 lines, want one each", chain, n4, n6)
		}
	}
	for _, chain := range []string{"prerouting", "input"} {
		if n := countContaining(synChainLines(t, nic, chain), "lv_syn"); n != 0 {
			t.Errorf("%s: %d SYN-flood lines, want none", chain, n)
		}
	}
	for _, l := range []string{wantSynLine4, wantSynLine6} {
		if !strings.Contains(l, "meta l4proto tcp") || strings.Contains(l, "nexthdr") {
			t.Errorf("not matched by meta l4proto: %s", l)
		}
	}
}

// In observe mode the line counts what it would drop under the would-drop
// comment the tally reads ("lv-wd - in synflood") and drops nothing.
//
// Mutation: render drop in observe mode.
func TestRender_SynFloodObserve(t *testing.T) {
	nic := renderNICPart(t, synFloodPlan(NICModeObserve))
	if strings.Contains(nic, "lv-sf") {
		t.Error("observe mode renders an lv-sf drop counter")
	}
	for _, chain := range []string{"forward", "output"} {
		var got []string
		for _, l := range synChainLines(t, nic, chain) {
			if strings.Contains(l, "@lv_syn") {
				got = append(got, l)
			}
		}
		if len(got) != 2 {
			t.Fatalf("%s: %d SYN-flood lines, want 2", chain, len(got))
		}
		for _, l := range got {
			if !strings.HasSuffix(l, ` counter comment "lv-wd - in synflood"`) {
				t.Errorf("%s: %s\nwant it to end in the would-drop counter", chain, l)
			}
			if strings.Contains(l, "drop") {
				t.Errorf("%s: observe mode drops: %s", chain, l)
			}
		}
	}
	// The would-drop parser reads the comment as a table-wide ingress counter.
	js := `{"nftables":[{"rule":{"comment":"lv-wd - in synflood","expr":[{"counter":{"packets":7,"bytes":420}}]}}]}`
	wd, err := parseWouldDrops([]byte(js))
	if err != nil || len(wd) != 1 || wd[0].Device != "-" || wd[0].Side != "in" || wd[0].Rule != "synflood" || wd[0].Packets != 7 {
		t.Errorf("parseWouldDrops = %+v, %v", wd, err)
	}
}

// Guards-only renders neither set nor line (it has no forward or output
// chain); off renders nothing either, whatever rate it carries.
//
// Mutation: render the sets in guards-only mode.
func TestRender_SynFloodGuardsOnlyAndOff(t *testing.T) {
	nic := renderNICPart(t, synFloodPlan(NICModeGuardsOnly))
	if strings.Contains(nic, "lv_syn") || strings.Contains(nic, "lv-sf") || strings.Contains(nic, "synflood") {
		t.Errorf("guards-only renders SYN-flood protection:\n%s", nic)
	}

	for _, mode := range []string{NICModeEnforce, NICModeObserve} {
		off := synFloodPlan(mode)
		off.SynFlood = SynFlood{}
		plain := renderNICPart(t, off)
		if strings.Contains(plain, "lv_syn") || strings.Contains(plain, "synflood") || strings.Contains(plain, "lv-sf") {
			t.Errorf("%s: off renders SYN-flood protection", mode)
		}
		off.SynFlood = SynFlood{Rate: 250, Burst: 1500}
		if got := renderNICPart(t, off); got != plain {
			t.Errorf("%s: off with a rate renders differently from off", mode)
		}
	}
}

// A rate or burst outside 1-100000 is refused: the plan changes nothing in
// the kernel, rather than a line nft might refuse or a limit other than the
// one recorded.
//
// Mutation: drop the range check.
func TestRender_SynFloodRangeRefused(t *testing.T) {
	for _, tc := range []struct {
		rate, burst int
		ok          bool
	}{
		{0, 1000, false},
		{100001, 1000, false},
		{200, 0, false},
		{200, 100001, false},
		{-1, 1000, false},
		{1, 100000, true},
		{100000, 1, true},
	} {
		p := synFloodPlan(NICModeEnforce)
		p.SynFlood.Rate, p.SynFlood.Burst = tc.rate, tc.burst
		_, _, err := RenderParts(p, true)
		if tc.ok != (err == nil) {
			t.Errorf("rate %d burst %d: err = %v, want ok=%v", tc.rate, tc.burst, err, tc.ok)
		}
		if err != nil && !strings.Contains(err.Error(), "SYN-flood") {
			t.Errorf("rate %d burst %d: error %q does not name SYN-flood protection", tc.rate, tc.burst, err)
		}
	}
}

// No source address is exempt from the limiter (Track B review I-1): a
// routed network's gateway and an LB host's address are in lv_lb_src4, so a
// NAT'd guest masqueraded to one, or a spoofer, would bypass it. The load
// balancer's own flows are accepted before the SYN-flood line, by their
// (source, backend, port), in both chains.
//
// Mutation: render the `ip saddr != @lv_lb_src4` exemption again — red.
func TestRender_SynFloodNoSourceExemption(t *testing.T) {
	nic := renderNICPart(t, synFloodPlan(NICModeEnforce))
	for _, chain := range []string{"forward", "output"} {
		lines := synChainLines(t, nic, chain)
		lbAccept, syn := -1, -1
		for i, l := range lines {
			if strings.Contains(l, "ip saddr @lv_lb_src4 ip daddr . tcp dport @lv_lb4 accept") {
				lbAccept = i
			}
			if strings.Contains(l, "@lv_syn4") {
				syn = i
				if strings.Contains(l, "lv_lb_src4") {
					t.Errorf("%s: the SYN-flood line exempts lv_lb_src4: %s", chain, l)
				}
			}
		}
		if lbAccept < 0 || syn < 0 || lbAccept > syn {
			t.Errorf("%s: the LB accept (line %d) must come before the SYN-flood line (line %d)", chain, lbAccept, syn)
		}
	}
}

// The load balancer's accepts name `meta protocol ip` first, as the
// SYN-flood line does, so an LB flow tagged toward a trunk NIC's VLAN is
// accepted before the limit like an untagged one (Track B round-1 re-review
// N-m1): without it the bridge family adds an implicit `ether type ip`,
// which misses 802.1Q frames.
//
// Mutation: drop `meta protocol ip` from either accept — red.
func TestRender_LBAcceptsMatchTaggedFrames(t *testing.T) {
	nic := renderNICPart(t, synFloodPlan(NICModeEnforce))
	for _, chain := range []string{"forward", "output"} {
		n := 0
		for _, l := range synChainLines(t, nic, chain) {
			if strings.Contains(l, "ip saddr @lv_lb_src4 ip daddr . tcp dport @lv_lb4 accept") {
				n++
				if !strings.Contains(l, "meta protocol ip ip saddr @lv_lb_src4") {
					t.Errorf("%s: the LB accept does not name meta protocol first: %s", chain, l)
				}
			}
		}
		if n != 1 {
			t.Errorf("%s: %d LB accepts, want 1", chain, n)
		}
	}
}
