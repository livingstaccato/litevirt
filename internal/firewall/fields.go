package firewall

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall/rulefield"
)

// ValidateRuleFields checks a rule's fields against the grammar the renderer
// can write into an nft script (rulefield): every rule writer calls it before
// a row is stored, and validate calls it for every rule it renders.
func ValidateRuleFields(direction, proto, port, cidr, action, comment string) error {
	return rulefield.Rule(direction, proto, port, cidr, action, comment)
}

// InvalidRow is a stored firewall row the loader does not render as written:
// it carries text that would add or break nft syntax (a peer on an older build
// can still replicate one), an IPv6 CIDR nft cannot read or paired with icmp,
// an action other than accept, drop or reject; or it references an ip set that
// does not exist; or it is an ip set with unreadable elements. Before, every
// one of these refused the whole plan, so the host kept its whole last ruleset
// (and rendered no chain for a NIC that started since); an injected one
// applied. Reported as the condition firewall.rule.invalid.
type InvalidRow struct {
	Table    string // cluster_firewall_rules, host_firewall_rules, sg_rules or ip_sets
	ID       string
	Action   string // the action as stored ("" for an ip set)
	Reason   string
	Handling string
}

// Handlings of an invalid row. None renders anything the row did not ask for,
// and none renders a drop beyond the row's own matches.
const (
	// A row that cannot be rendered safely is held fail-static, the spec's
	// contract for one row: the host keeps rendering the version of it that it
	// last rendered...
	HandlingKeptLast = "kept as this host last rendered it"
	// ...or, when it has none (the row was never readable here), leaves it
	// out.
	HandlingLeftOut = "left out: this host has no earlier rendering of it to keep"
	// A rule referencing an ip set that does not exist (deleted, or not
	// replicated here yet) is rendered against an empty set of that name, so
	// it matches nothing: what deleting a set means, and what nft does with an
	// empty one. Only a positive reference (@x): "not in an empty set" is
	// every address, so a negated one (!= @x) to a missing set is held
	// fail-static like an unreadable row instead (kept as last rendered when
	// that rendering's set still exists, else left out). Reported only once
	// it has lasted emptySetGrace: a rule replicated just before its set, or a
	// stack redeploy, is not an incident.
	HandlingEmptySet = "its ip set does not exist: rendered against an empty set, so it matches nothing"
	// An ip set is rendered without the elements that cannot be rendered (they
	// never worked: each one injected or broke the load).
	HandlingElementsLeftOut = "rendered without its unreadable elements"
	// An ip set whose name cannot be rendered is left out; a rule referencing
	// it cannot be rendered either and is held fail-static.
	HandlingSetLeftOut = "set left out: its name cannot be rendered"
)

// rowMemory is what a loader last rendered for each rule row, by table/id, so
// a row that turns unreadable (an older peer rewrote it) keeps its last
// rendering. It lives as long as the loader: after a restart a row that is
// unreadable from the start is left out.
type rowMemory struct {
	mu    sync.Mutex
	rules map[string]Rule
	// emptySince is when each row was first rendered against a missing set.
	emptySince map[string]time.Time
}

func (m *rowMemory) snapshot() (map[string]Rule, map[string]time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rules, m.emptySince
}

func (m *rowMemory) store(q *quarantine) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules, m.emptySince = q.next, q.emptyNext
}

// emptySetGrace is how long a rule may reference a missing set before the
// condition names it: about two reconcile passes.
const emptySetGrace = 60 * time.Second

// quarantine is one loader pass's handling of stored rule rows.
type quarantine struct {
	knownSets map[string]bool // ip sets the plan renders
	v6Sets    map[string]bool // of those, the ones with an IPv6 companion
	prev      map[string]Rule // last pass's renderings
	next      map[string]Rule // this pass's
	emptySets map[string]bool // missing sets rendered empty
	invalid   []InvalidRow

	now       time.Time
	emptyPrev map[string]time.Time // rows rendered against a missing set, since
	emptyNext map[string]time.Time
}

func newQuarantine(sets []IPSet, prev map[string]Rule, emptyPrev map[string]time.Time, now time.Time) *quarantine {
	q := &quarantine{knownSets: map[string]bool{}, prev: prev, next: map[string]Rule{},
		emptySets: map[string]bool{}, v6Sets: setsWithIPv6(sets),
		now: now, emptyPrev: emptyPrev, emptyNext: map[string]time.Time{}}
	for _, s := range sets {
		q.knownSets[s.Name] = true
	}
	return q
}

// rule returns the rule the renderer renders for one stored row, and false
// when the row is left out. A row that applies today renders exactly as
// before: only what the renderer refuses (rulefield's syntax level, an IPv6
// CIDR nft cannot read or paired with icmp, an action other than accept,
// drop or reject) makes a row unreadable. The direction is never written as
// text and is read as it always was (FromCorrosionRule).
func (q *quarantine) rule(table, id, direction, proto, port, cidr, action, comment string) (Rule, bool) {
	r := FromCorrosionRule(direction, proto, port, cidr, action)
	r.Comment = comment
	key := table + "/" + id
	why := q.unreadable(r, action)
	if why == "" {
		why = q.negatedMissing(r)
	}
	if why != "" {
		inv := InvalidRow{Table: table, ID: id, Action: action, Reason: why, Handling: HandlingLeftOut}
		old, ok := q.prev[key]
		if !ok || q.negatedMissing(old) != "" {
			q.invalid = append(q.invalid, inv)
			return Rule{}, false
		}
		inv.Handling = HandlingKeptLast
		q.invalid = append(q.invalid, inv)
		r = old
	}
	q.next[key] = r
	if name, ok := rulefield.SetRef(r.CIDR); ok && !q.knownSets[name] {
		// A positive reference (negatedMissing held the others): renders
		// against an empty set and matches nothing.
		q.emptySets[name] = true
		since, seen := q.emptyPrev[key]
		if !seen {
			since = q.now
		}
		q.emptyNext[key] = since
		if q.now.Sub(since) >= emptySetGrace {
			q.invalid = append(q.invalid, InvalidRow{Table: table, ID: id, Action: action,
				Reason: fmt.Sprintf("ip set %q does not exist", name), Handling: HandlingEmptySet})
		}
	}
	return r, true
}

// negatedMissing is why r cannot be rendered against an empty set: its
// reference to a missing set is negated, and "not in an empty set" is every
// address — a drop would drop everything, an accept admit everything.
func (q *quarantine) negatedMissing(r Rule) string {
	if name, ok := rulefield.SetRef(r.CIDR); ok && !q.knownSets[name] && rulefield.NegatedSetRef(r.CIDR) {
		return fmt.Sprintf("negated reference to ip set %q, which does not exist (it would match every address)", name)
	}
	return ""
}

// unreadable is why the renderer would refuse r, or "".
func (q *quarantine) unreadable(r Rule, action string) string {
	var reasons []string
	for _, err := range []error{
		rulefield.RenderProto(r.Proto), rulefield.RenderPort(r.Proto, r.PortRange),
		rulefield.RenderCIDR(r.CIDR), rulefield.Action(action),
	} {
		if err != nil {
			reasons = append(reasons, err.Error())
		}
	}
	if name, ok := rulefield.SetRef(r.CIDR); ok {
		if err := rulefield.RenderSetName(name); err != nil {
			reasons = append(reasons, err.Error())
		} else if base, isComp := strings.CutSuffix(name, ipv6SetSuffix); isComp && q.v6Sets[base] && !q.knownSets[name] {
			reasons = append(reasons, fmt.Sprintf("cidr %q names the IPv6 companion of set %q; reference the set itself", r.CIDR, base))
		}
	} else if isIPv6Literal(r.CIDR) {
		if !validAddrOrPrefix(r.CIDR, true) {
			reasons = append(reasons, fmt.Sprintf("cidr %q is not an IPv6 address or prefix", r.CIDR))
		} else if ruleFamily(r.Proto) == "ip" {
			reasons = append(reasons, fmt.Sprintf("cidr %q is IPv6 but proto %q is IPv4-only", r.CIDR, r.Proto))
		}
	}
	return strings.Join(reasons, "; ")
}

// sets returns the empty sets the pass's rules reference.
func (q *quarantine) sets() []IPSet {
	names := make([]string, 0, len(q.emptySets))
	for n := range q.emptySets {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]IPSet, 0, len(names))
	for _, n := range names {
		out = append(out, IPSet{Name: n})
	}
	return out
}

// quarantineIPSets returns the ip sets the plan renders: each without the
// elements that cannot be rendered, and none whose name cannot be.
func quarantineIPSets(sets []corrosion.IPSet) ([]IPSet, []InvalidRow) {
	var out []IPSet
	var inv []InvalidRow
	for _, s := range sets {
		if err := rulefield.RenderSetName(s.Name); err != nil {
			inv = append(inv, InvalidRow{Table: "ip_sets", ID: s.ID, Reason: err.Error(), Handling: HandlingSetLeftOut})
			continue
		}
		var keep []string
		var bad []string
		for _, e := range s.CIDRs {
			err := rulefield.RenderSetElement(e)
			if err == nil && isIPv6Literal(e) && !validAddrOrPrefix(e, true) {
				err = fmt.Errorf("ip set element %q is not an IPv6 address or prefix", e)
			}
			if err != nil {
				bad = append(bad, err.Error())
				continue
			}
			keep = append(keep, e)
		}
		if len(bad) > 0 {
			if len(bad) > 3 {
				bad = append(bad[:3], fmt.Sprintf("and %d more", len(bad)-3))
			}
			inv = append(inv, InvalidRow{Table: "ip_sets", ID: s.ID, Reason: strings.Join(bad, "; "), Handling: HandlingElementsLeftOut})
		}
		out = append(out, IPSet{Name: s.Name, CIDRs: keep})
	}
	return out, inv
}

// warnInvalidRows logs each invalid row of a pass.
func warnInvalidRows(rows []InvalidRow) {
	for _, r := range rows {
		slog.Warn("firewall: a stored row is not rendered as written",
			"table", r.Table, "id", r.ID, "action", r.Action, "reason", r.Reason, "handling", r.Handling)
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
	// Cut in one step to the limit in bytes (at a rune boundary): quoting
	// never shortens text, so nothing past it can fit. Then trim the few
	// runes that escaping pushed over.
	if len(s) > rulefield.MaxCommentBytes {
		cut := rulefield.MaxCommentBytes
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	for rulefield.QuotedLen(s) > rulefield.MaxCommentBytes {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return fmt.Sprintf("%q", s)
}
