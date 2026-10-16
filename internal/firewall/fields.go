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

// ValidateRuleFields checks a rule's fields against the write grammar
// (rulefield.Rule), which the rule handlers run before a row is stored, with
// the forms a later build adds (rulefield.Extensions). The renderer never
// runs it: validate and the loader check stored rows with the syntax checks
// alone (rulefield.Render*), so a stored row an extension accepted is judged
// there as any other.
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
	// An ip set whose name cannot be rendered, or is the name of one of
	// litevirt's own sets (userSetName), is left out; a rule referencing it cannot be
	// rendered either and is held fail-static.
	HandlingSetLeftOut = "set left out: its name cannot be rendered or is reserved for litevirt"
	// A set named <x>_v6 while a set x holds IPv6 elements: x's IPv6 elements
	// render as the set <x>_v6, and nft refuses a second set of that name. The
	// row so named is left out; a rule referencing it cannot be rendered and
	// is held fail-static.
	HandlingSetLeftOutCompanion = "set left out: its name is the IPv6 companion of another set"
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
	degraded  map[string]bool // sets rendered without some of their elements
	invalid   []InvalidRow
	// ownRef is the tag group set the row being judged names because the
	// tag pass rewrote its tag:<g> (tagPass.rule), "" for any other row. Only
	// that reference is exempt from userSetName: a row written as @lv_tg_<g>
	// is a user set reference and is left out (D5a fix I-1).
	ownRef string

	now       time.Time
	emptyPrev map[string]time.Time // rows rendered against a missing set, since
	emptyNext map[string]time.Time
}

func newQuarantine(sets []IPSet, degraded map[string]bool, prev map[string]Rule, emptyPrev map[string]time.Time, now time.Time) *quarantine {
	q := &quarantine{knownSets: map[string]bool{}, degraded: degraded, prev: prev, next: map[string]Rule{},
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
		// The last rendering is kept only while it is still renderable under
		// this pass's sets (re-review 2 m-b): readable, and, when negated, its
		// set present and whole.
		old, ok := q.prev[key]
		if !ok || q.unreadable(old, string(old.Action)) != "" || q.negatedMissing(old) != "" {
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
//
// A set that lost any element to quarantine counts as missing here too
// (re-review 2 I-1): "not in" a set rendered without some of its elements
// matches the addresses it was meant to list, and every address when it lost
// them all.
func (q *quarantine) negatedMissing(r Rule) string {
	name, ok := rulefield.SetRef(r.CIDR)
	if !ok || !rulefield.NegatedSetRef(r.CIDR) {
		return ""
	}
	switch {
	case !q.knownSets[name]:
		return fmt.Sprintf("negated reference to ip set %q, which does not exist (it would match every address)", name)
	case q.degraded[name]:
		return fmt.Sprintf("negated reference to ip set %q, whose unreadable elements were left out (it would match the addresses the set lists)", name)
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
	// What nft would refuse the whole ruleset over, judged on this host
	// without the network: a port or protocol it cannot resolve (fw-0.4 review
	// I-3; set-freeze review I-2), an ordering operator in front of a list,
	// range or prefix (review I-3), an IPv4 address, prefix or range it cannot
	// read (review m-2). Each only once the field's syntax is sound.
	field := func(name, value, why string) {
		if why != "" {
			reasons = append(reasons, (&rulefield.FieldError{Field: name, Value: value, Reason: why}).Error())
		}
	}
	if rulefield.RenderPort(r.Proto, r.PortRange) == nil && rulefield.RendersPort(r.Proto) && r.PortRange != "" {
		field("port", r.PortRange, rulefield.RelationalMisuse("port", r.PortRange))
		field("port", r.PortRange, rulefield.PortUnresolvable(r.Proto, r.PortRange))
	}
	if rulefield.RenderProto(r.Proto) == nil && rulefield.RendersProto(r.Proto) {
		field("proto", r.Proto, rulefield.RelationalMisuse("proto", r.Proto))
		field("proto", r.Proto, rulefield.ProtoUnresolvable(strings.ToLower(r.Proto)))
	}
	if rulefield.RenderCIDR(r.CIDR) == nil && !isIPv6Literal(r.CIDR) && !strings.Contains(r.CIDR, "@") {
		field("cidr", r.CIDR, rulefield.RelationalMisuse("cidr", r.CIDR))
		field("cidr", r.CIDR, rulefield.CIDRUnloadable(r.CIDR))
	}
	if name, op, ok := rulefield.SetRefOp(r.CIDR); ok {
		if !rulefield.SetRefOpOK(op) {
			reasons = append(reasons, fmt.Sprintf("cidr %q compares a set with %s, which nft refuses", r.CIDR, op))
		}
		if err := userSetName(name); err != nil && (q.ownRef == "" || name != q.ownRef) {
			reasons = append(reasons, err.Error())
		} else if base, isComp := strings.CutSuffix(name, ipv6SetSuffix); isComp && q.v6Sets[base] && !q.knownSets[name] {
			reasons = append(reasons, fmt.Sprintf("cidr %q names the IPv6 companion of set %q; reference the set itself", r.CIDR, base))
		}
	} else if strings.Contains(r.CIDR, "@") {
		// A set reference behind a mask or inside braces (re-review 2 m-a):
		// nft refuses `{ @x }`, and the set's presence cannot be checked.
		reasons = append(reasons, fmt.Sprintf("cidr %q references a set other than as @name, != @name or == @name", r.CIDR))
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
// elements that cannot be rendered, and none whose name cannot be, nor one
// named as the IPv6 companion of a set with IPv6 elements.
//
// degraded names the sets that lost an element: a negated reference to one is
// not rendered (quarantine.negatedMissing).
func quarantineIPSets(sets []corrosion.IPSet) (out []IPSet, inv []InvalidRow, degraded map[string]bool) {
	degraded = map[string]bool{}
	var ids []string // out[i]'s row id
	for _, s := range sets {
		if err := userSetName(s.Name); err != nil {
			inv = append(inv, InvalidRow{Table: "ip_sets", ID: s.ID, Reason: err.Error(), Handling: HandlingSetLeftOut})
			continue
		}
		// The IPv6 elements render as the set <name>_v6, so they need that
		// name to render too (a 253-byte name's companion is too long).
		companion := rulefield.RenderSetName(s.Name + ipv6SetSuffix)
		var keep []string
		var bad []string
		for _, e := range s.CIDRs {
			err := rulefield.RenderSetElement(e)
			if err == nil && isIPv6Literal(e) && !validAddrOrPrefix(e, true) {
				err = fmt.Errorf("ip set element %q is not an IPv6 address or prefix", e)
			}
			if why := rulefield.SetElementUnloadable(e); err == nil && why != "" {
				err = fmt.Errorf("ip set element %q: %s", e, why)
			}
			if err == nil && isIPv6Literal(e) && companion != nil {
				err = fmt.Errorf("ip set element %q: the set's IPv6 companion cannot be named: %v", e, companion)
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
			degraded[s.Name] = true
		}
		out = append(out, IPSet{Name: s.Name, CIDRs: keep})
		ids = append(ids, s.ID)
	}
	return leaveOutCompanionClashes(out, ids, inv, degraded)
}

// internalSetNames are the sets the renderer declares itself in the per-NIC
// bridge table; internalSetPrefixes start the names of the ones it will
// declare per object (lv_tg_<group>, tag groups). The inet table declares
// none.
var (
	internalSetNames    = map[string]bool{setNICDevs: true, setVLANOK: true, setDHCPSrv: true, setGateways4: true, setGateways6: true, setLB4: true, setLBSrc4: true}
	internalSetPrefixes = []string{"lv_tg_"}
)

// userSetName is why a stored user set, or a rule's reference to one, cannot
// be rendered: nft cannot read the name (rulefield.RenderSetName), or it is a
// name of the renderer's own sets. A user set of that name would merge into
// the internal one (lv_gw4: guests may reach its addresses for DHCP and DNS)
// or, typed differently, make nft refuse the bridge table. Any other lv_
// name, which writers refuse now but a main-era cluster may hold, renders as
// it did (review I-5): a deny rule on it keeps denying.
func userSetName(name string) error {
	if err := rulefield.RenderSetName(name); err != nil {
		return err
	}
	collides := internalSetNames[name]
	for _, p := range internalSetPrefixes {
		collides = collides || strings.HasPrefix(name, p)
	}
	if collides {
		return &rulefield.FieldError{Field: "ipset name", Value: name,
			Reason: "it is the name of one of litevirt's internal sets, which the prefix \"lv_\" is reserved for; recreate the set under another name"}
	}
	return nil
}

// leaveOutCompanionClashes leaves out every set row named <x>_v6 while a set
// x that renders holds IPv6 elements (fw-grammar re-review 3 N-2): x's IPv6
// elements render as the set <x>_v6, and nft refuses the whole ruleset over a
// second set of that name. Shorter names are settled first, so a row left out
// here never makes its own companion clash.
func leaveOutCompanionClashes(sets []IPSet, ids []string, inv []InvalidRow, degraded map[string]bool) ([]IPSet, []InvalidRow, map[string]bool) {
	v6 := setsWithIPv6(sets)
	names := make([]string, 0, len(sets))
	seen := map[string]bool{}
	for _, s := range sets {
		if !seen[s.Name] {
			seen[s.Name] = true
			names = append(names, s.Name)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) < len(names[j])
		}
		return names[i] < names[j]
	})
	kept := map[string]bool{}
	clashes := map[string]string{} // left-out name → the set whose companion it is
	for _, n := range names {
		if base, ok := strings.CutSuffix(n, ipv6SetSuffix); ok && kept[base] && v6[base] {
			clashes[n] = base
			continue
		}
		kept[n] = true
	}
	if len(clashes) == 0 {
		return sets, inv, degraded
	}
	out := sets[:0:0]
	for i, s := range sets {
		if base, ok := clashes[s.Name]; ok {
			inv = append(inv, InvalidRow{Table: "ip_sets", ID: ids[i], Handling: HandlingSetLeftOutCompanion,
				Reason: fmt.Sprintf("ip set %q holds IPv6 elements, which render as the set %q", base, s.Name)})
			continue
		}
		out = append(out, s)
	}
	return out, inv, degraded
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
