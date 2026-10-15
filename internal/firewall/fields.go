package firewall

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall/rulefield"
)

// ValidateRuleFields checks a rule's fields against the grammar the renderer
// can write into an nft script (rulefield): every rule writer calls it before
// a row is stored, and validate calls it for every rule it renders.
func ValidateRuleFields(direction, proto, port, cidr, action, comment string) error {
	return rulefield.Rule(direction, proto, port, cidr, action, comment)
}

// InvalidRow is a stored firewall row the loader does not render as written,
// because the renderer would refuse it: text that would add or break nft
// syntax (a peer on an older build can still replicate one), a reference to
// an ip set that is not rendered, an IPv6 CIDR nft cannot read or paired with
// icmp, an action other than accept, drop or reject. Before, any of these
// refused the whole plan, so the host kept its last ruleset (and rendered no
// chain for a NIC that started since); an injected one applied. Reported as
// the condition firewall.rule.invalid.
type InvalidRow struct {
	Table    string // cluster_firewall_rules, host_firewall_rules, sg_rules or ip_sets
	ID       string
	Reason   string
	Handling string
}

// Handlings of an invalid row. Each keeps the host's policy at or below what
// the row asked for: nothing it did not admit is admitted.
const (
	// An accept that cannot be rendered is left out: it admits nothing.
	HandlingLeftOut = "left out"
	// A drop or reject (or a row whose verdict cannot be read) is rendered as
	// a drop with each unreadable match removed: it drops at least what the
	// row asked for. Leaving it out instead would admit what it refused.
	HandlingWidened = "rendered as a drop without its unreadable matches"
	// An ip set with an unreadable name or element is left out under its
	// name, every row of that name; a rule referencing it is then handled as
	// above.
	HandlingSetLeftOut = "set left out"
)

// quarantineRule turns one stored rule row into the rules the renderer
// renders for it, and reports it when that is not the row as written.
// knownSets are the ip-set names the plan renders.
//
// It refuses only what the renderer refuses (rulefield's syntax level, an
// unknown set, an IPv6 CIDR nft cannot read or that is paired with icmp, an
// action other than accept, drop or reject): a row that applies today renders
// exactly as before. The direction is never written as text and is read as it
// always was (FromCorrosionRule).
func quarantineRule(table, id, direction, proto, port, cidr, action string, knownSets map[string]bool) ([]Rule, *InvalidRow) {
	r := FromCorrosionRule(direction, proto, port, cidr, action)
	protoErr := rulefield.RenderProto(r.Proto)
	portErr := rulefield.RenderPort(r.Proto, r.PortRange)
	cidrErr := rulefield.RenderCIDR(r.CIDR)
	actErr := rulefield.Action(action)
	switch {
	case cidrErr != nil:
	case strings.HasPrefix(cidr, "@") && !knownSets[strings.TrimPrefix(cidr, "@")]:
		cidrErr = fmt.Errorf("cidr %q references an ip set that is not rendered", cidr)
	case isIPv6Literal(cidr) && !validAddrOrPrefix(cidr, true):
		cidrErr = fmt.Errorf("cidr %q is not an IPv6 address or prefix", cidr)
	case protoErr == nil && isIPv6Literal(cidr) && ruleFamily(proto) == "ip":
		cidrErr = fmt.Errorf("cidr %q is IPv6 but proto %q is IPv4-only", cidr, proto)
	}
	var reasons []string
	for _, err := range []error{protoErr, portErr, cidrErr, actErr} {
		if err != nil {
			reasons = append(reasons, err.Error())
		}
	}
	if len(reasons) == 0 {
		return []Rule{r}, nil
	}
	inv := &InvalidRow{Table: table, ID: id, Reason: strings.Join(reasons, "; ")}
	if actErr == nil && (r.Action == Accept || r.Action == "") {
		inv.Handling = HandlingLeftOut
		return nil, inv
	}
	if actErr != nil {
		r.Action = Drop
	}
	if protoErr != nil {
		r.Proto, r.PortRange = "all", ""
	}
	if portErr != nil {
		r.PortRange = ""
	}
	if cidrErr != nil {
		r.CIDR = ""
	}
	inv.Handling = HandlingWidened
	return []Rule{r}, inv
}

// quarantineIPSets returns the ip sets the plan renders: every row of a name
// any of whose rows the renderer would refuse is left out, so that the set is
// never rendered smaller than its rows say (a smaller set referenced by a drop
// would drop less).
func quarantineIPSets(sets []corrosion.IPSet) ([]IPSet, []InvalidRow) {
	bad := map[string]bool{}
	var inv []InvalidRow
	for _, s := range sets {
		err := rulefield.RenderSetName(s.Name)
		for _, e := range s.CIDRs {
			if err != nil {
				break
			}
			if isIPv6Literal(e) && !validAddrOrPrefix(e, true) {
				err = fmt.Errorf("ip set element %q is not an IPv6 address or prefix", e)
			} else {
				err = rulefield.RenderSetElement(e)
			}
		}
		if err != nil {
			bad[s.Name] = true
			inv = append(inv, InvalidRow{Table: "ip_sets", ID: s.ID, Reason: err.Error(), Handling: HandlingSetLeftOut})
		}
	}
	var out []IPSet
	for _, s := range sets {
		if !bad[s.Name] {
			out = append(out, IPSet{Name: s.Name, CIDRs: s.CIDRs})
		}
	}
	return out, inv
}

// warnInvalidRows logs each invalid row of a pass.
func warnInvalidRows(rows []InvalidRow) {
	for _, r := range rows {
		slog.Warn("firewall: a stored row fails the rule grammar and is not rendered as written",
			"table", r.Table, "id", r.ID, "reason", r.Reason, "handling", r.Handling)
	}
}

// quoteComment is a comment as an nft quoted string. nft's quoted string has
// no escape, so a double quote would end it and the rest would be read as
// rules: it becomes a single quote. The text is cut to nft's comment limit,
// which would otherwise refuse the whole ruleset. A comment a writer stored is
// already within both (rulefield.Comment); this holds the line for text the
// renderer composes, such as a security group's name in an observe-mode label,
// and for a row a peer on an older build wrote.
func quoteComment(s string) string {
	s = strings.ReplaceAll(s, `"`, "'")
	for rulefield.QuotedLen(s) > rulefield.MaxCommentBytes {
		rs := []rune(s)
		s = string(rs[:len(rs)-1])
	}
	return fmt.Sprintf("%q", s)
}
