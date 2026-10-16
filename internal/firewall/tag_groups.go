package firewall

// Tag groups in the plan (firewall extras spec §4.5, §4.6).
//
// Each readable group becomes the ip set lv_tg_<name>, holding its members'
// leased addresses (IPv6 ones in the _v6 companion), and a stored rule's
// "tag:<name>" is rewritten to "@lv_tg_<name>" before the rule is judged.
// Every NIC of a member is also bound to the group's security groups on the
// networks its binding covers, merged with the NIC's own before the
// ambiguous-name check. Wherever membership cannot be proven the pass fails
// closed: a rule naming a group this replica cannot render matches nothing
// when it accepts, and loses its address match when it denies; a workload
// whose tags row cannot be read, or whose identity another live workload
// holds too, has its NICs held at drop.

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall/rulefield"
)

// TagGroupSetPrefix starts the nft set of every tag group: lv_tg_<name>.
const TagGroupSetPrefix = "lv_tg_"

// TagGroupRef is a stored rule that references a tag group this pass did not
// render as the group's set, or, with no ID, an unreadable group itself.
type TagGroupRef struct {
	Table, ID string
	Group     string
	Action    string // as stored
	// Reason says why the group was not rendered (an unreadable group).
	Reason   string
	Handling string
}

// Handlings of a TagGroupRef.
const (
	// The group's set is declared empty, so the accept matches nothing.
	TagHandlingEmptySet = "an accept: rendered against an empty set, so it matches nothing"
	// The deny renders without its address match: it denies everything else
	// it names (direction, protocol, port), which fails closed.
	TagHandlingNoAddress = "a drop or reject: rendered without its address match, so it denies everything else it names"
	// The group's name cannot be declared as a set (it is another group's
	// IPv6 companion, or no group name at all), so the accept is left out:
	// it matches nothing either way.
	TagHandlingLeftOut = "an accept: left out, so it matches nothing"
)

// TagWorkloadHold is one workload, on this host, a pass reports.
type TagWorkloadHold struct {
	Kind, Name, Host, FWID string // Host: a container's; "" for a VM
	// Holders are, for a shared identity, every live workload holding it.
	Holders []string
	// NICs are this host's devices of the workload held at drop, sorted.
	NICs []string
}

// TagGroupReport is what a pass could not render as the tag groups ask. The
// daemon raises its conditions from it.
type TagGroupReport struct {
	// Members is each group's number of member workloads
	// (litevirt_firewall_tag_group_members).
	Members map[string]int
	// Missing are the rules that have named, for emptySetGrace, a group this
	// replica does not hold (firewall.tag_group.missing).
	Missing []TagGroupRef
	// Unreadable are the groups whose rows cannot be read here (no ID), and
	// the rules naming them (firewall.tag_group.unreadable).
	Unreadable []TagGroupRef
	// TagsUnreadable are this host's workloads whose firewall-tags row cannot
	// be read (firewall.tag_group.tags_unreadable).
	TagsUnreadable []TagWorkloadHold
	// SharedIdentity are this host's workloads whose firewall identity another
	// live workload holds too (firewall.tag_group.identity_shared).
	SharedIdentity []TagWorkloadHold
	// IdentityLost are this host's workloads with no firewall identity whose
	// name an orphaned, non-empty tags row still names
	// (firewall.tag_group.identity_lost; corrosion IdentityLost).
	IdentityLost []TagWorkloadHold
}

// tagMemory is what a loader remembers between passes: since when each rule
// has named a missing group, so the condition waits out emptySetGrace.
// Passes may overlap (Reconcile is not serialized), hence the lock.
type tagMemory struct {
	mu    sync.Mutex
	since map[string]time.Time
}

func (m *tagMemory) snapshot() map[string]time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.since
}

func (m *tagMemory) store(since map[string]time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.since = since
}

// tagPass is one loader pass's view of the tag groups.
type tagPass struct {
	host      string
	now       time.Time
	mem       *tagMemory
	sincePrev map[string]time.Time

	groups   map[string]corrosion.FirewallTagGroup
	readable map[string]bool   // groups rendered as their set
	whyNot   map[string]string // the others this replica holds: why not
	members  *corrosion.TagGroupMembership

	empty    map[string]bool // sets declared empty for an accept on a group not rendered
	denyRef  bool            // a deny rule matches a rendered group's set
	since    map[string]time.Time
	report   TagGroupReport
	reported map[string]bool

	bindings map[string][]string        // kind|host|name|network -> bound security groups
	shared   map[string][]string        // kind|host|name -> every holder of its identity
	tagsBad  map[string]bool            // kind|host|name -> its tags row is unreadable
	held     map[string]map[string]bool // kind|host|name -> devices held
}

// loadTagGroups reads every group and its members (one query set, none
// beyond the groups when there are none).
func loadTagGroups(ctx context.Context, db *corrosion.Client, host string, now time.Time, mem *tagMemory) (*tagPass, error) {
	m, err := corrosion.ListTagGroupMembers(ctx, db)
	if err != nil {
		return nil, err
	}
	t := &tagPass{host: host, now: now, mem: mem, sincePrev: mem.snapshot(), members: m,
		groups: map[string]corrosion.FirewallTagGroup{}, readable: map[string]bool{}, whyNot: map[string]string{},
		empty: map[string]bool{}, since: map[string]time.Time{}, reported: map[string]bool{},
		bindings: map[string][]string{}, shared: map[string][]string{}, tagsBad: map[string]bool{},
		held: map[string]map[string]bool{}}
	t.report.Members = map[string]int{}
	for _, v := range m.Groups {
		t.groups[v.Group.Name] = v.Group
	}
	for _, v := range m.Groups {
		g := v.Group
		switch {
		case g.Unreadable:
			t.whyNot[g.Name] = "its row cannot be read"
		case t.shadows(g.Name):
			// lv_tg_<x>_v6 is group x's IPv6 companion: declaring it for
			// this group too would make nft refuse the whole ruleset.
			t.whyNot[g.Name] = fmt.Sprintf("its set would be the IPv6 companion of group %q's", strings.TrimSuffix(g.Name, ipv6SetSuffix))
		default:
			t.readable[g.Name] = true
			t.report.Members[g.Name] = len(v.Members)
			for _, mb := range v.Members {
				if len(g.Def.SecurityGroups) == 0 {
					continue
				}
				for _, n := range mb.Bound {
					k := tagKey(mb.Kind, mb.Host, mb.Name) + "|" + n
					t.bindings[k] = append(t.bindings[k], g.Def.SecurityGroups...)
				}
			}
			continue
		}
		t.report.Members[g.Name] = 0
		t.report.Unreadable = append(t.report.Unreadable, TagGroupRef{Group: g.Name, Reason: t.whyNot[g.Name]})
	}
	for k, sgs := range t.bindings {
		slices.Sort(sgs)
		t.bindings[k] = slices.Compact(sgs)
	}
	holders := map[string][]string{}
	for _, w := range m.SharedFWID {
		holders[w.Kind+"/"+w.FWID] = append(holders[w.Kind+"/"+w.FWID], tagWho(w.Kind, w.Host, w.Name))
	}
	for _, w := range m.SharedFWID {
		all := slices.Clone(holders[w.Kind+"/"+w.FWID])
		slices.Sort(all)
		t.shared[tagKey(w.Kind, w.Host, w.Name)] = all
	}
	for _, w := range m.TagsUnreadable {
		t.tagsBad[tagKey(w.Kind, w.Host, w.Name)] = true
	}
	return t, nil
}

// shadows reports whether name is another group's IPv6 companion: x_v6 while
// a group x exists.
func (t *tagPass) shadows(name string) bool {
	base, ok := strings.CutSuffix(name, ipv6SetSuffix)
	_, exists := t.groups[base]
	return ok && exists
}

func tagKey(kind, host, name string) string { return kind + "|" + host + "|" + name }

// tagWho names a workload as the conditions show it.
func tagWho(kind, host, name string) string {
	if kind == corrosion.TagMemberCT {
		return "container " + host + "/" + name
	}
	return "VM " + name
}

// sets are the readable groups' sets, each with its members' addresses.
func (t *tagPass) sets() []IPSet {
	var out []IPSet
	for _, v := range t.members.Groups {
		if !t.readable[v.Group.Name] {
			continue
		}
		s := IPSet{Name: TagGroupSetPrefix + v.Group.Name}
		for _, mb := range v.Members {
			for _, a := range mb.Addrs {
				s.CIDRs = append(s.CIDRs, a.Addr.String())
			}
		}
		slices.Sort(s.CIDRs)
		s.CIDRs = slices.Compact(s.CIDRs)
		out = append(out, s)
	}
	return out
}

// emptySets are the sets declared empty for accepts naming a group that is
// not rendered.
func (t *tagPass) emptySets() []IPSet {
	var out []IPSet
	for _, n := range slices.Sorted(maps.Keys(t.empty)) {
		out = append(out, IPSet{Name: n})
	}
	return out
}

// leaveOutReserved removes the user ip sets named with the tag-group prefix:
// such a set would be merged into a group's (widening who its rules match)
// or declared twice.
func leaveOutReserved(sets []corrosion.IPSet) ([]corrosion.IPSet, []InvalidRow) {
	var out []corrosion.IPSet
	var inv []InvalidRow
	for _, s := range sets {
		if strings.HasPrefix(s.Name, TagGroupSetPrefix) {
			inv = append(inv, InvalidRow{Table: "ip_sets", ID: s.ID,
				Reason:   fmt.Sprintf("ip set %q: the prefix %q names tag groups' sets", s.Name, TagGroupSetPrefix),
				Handling: HandlingSetLeftOut})
			continue
		}
		out = append(out, s)
	}
	return out, inv
}

// isAccept reports whether a stored action accepts ("" is accept); any other
// action is handled as a deny, which fails closed.
func isAccept(action string) bool {
	a := strings.ToLower(strings.TrimSpace(action))
	return a == "" || a == string(Accept)
}

// tagRef returns the group a stored cidr names: ok when it is a tag-group
// reference at all, valid when it is one in the exact form (tag:<name>).
func tagRef(cidr string) (name string, ok, valid bool) {
	if name, ok := rulefield.TagCIDRName(cidr); ok {
		return name, true, true
	}
	rest, ok := cutPrefixFold(strings.TrimSpace(cidr), rulefield.TagCIDRPrefix)
	return rest, ok, false
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return "", false
}

// rule is quarantine.rule for one stored row, with its tag-group reference
// resolved first, and false when the row is left out.
func (t *tagPass) rule(q *quarantine, table, id, direction, proto, port, cidr, action, comment string) (Rule, bool) {
	if name, ok, valid := tagRef(cidr); ok {
		set := TagGroupSetPrefix + name
		switch {
		case valid && t.readable[name]:
			cidr = "@" + set
			if !isAccept(action) {
				t.denyRef = true
			}
		case !isAccept(action):
			// A deny keeps everything but the address (I-6).
			t.refer(table, id, name, action, TagHandlingNoAddress)
			cidr = ""
		case valid && !t.shadows(name):
			// An accept matches nothing: against an empty set of the
			// group's name, which a negated reference must not take for a
			// whole one.
			t.refer(table, id, name, action, TagHandlingEmptySet)
			t.empty[set] = true
			q.knownSets[set] = true
			if q.degraded == nil {
				q.degraded = map[string]bool{}
			}
			q.degraded[set] = true
			cidr = "@" + set
		default:
			t.refer(table, id, name, action, TagHandlingLeftOut)
			return Rule{}, false
		}
	}
	r, ok := q.rule(table, id, direction, proto, port, cidr, action, comment)
	if !ok {
		return r, false
	}
	// A rendering this host kept from an earlier pass (the row turned
	// unreadable) may name a group's set this pass does not render: a deny
	// on it then loses the address, as above.
	if name, isRef := rulefield.SetRef(r.CIDR); isRef && !rulefield.NegatedSetRef(r.CIDR) {
		if group, isTag := strings.CutPrefix(name, TagGroupSetPrefix); isTag && !t.readable[group] && r.Action != Accept && r.Action != "" {
			t.refer(table, id, group, action, TagHandlingNoAddress)
			r.CIDR = ""
		}
	}
	return r, true
}

// refer records a rule naming a group this pass does not render.
func (t *tagPass) refer(table, id, group, action, handling string) {
	key := table + "/" + id
	if t.reported[key] {
		return
	}
	t.reported[key] = true
	ref := TagGroupRef{Table: table, ID: id, Group: group, Action: action, Handling: handling}
	if why, held := t.whyNot[group]; held {
		ref.Reason = why
		t.report.Unreadable = append(t.report.Unreadable, ref)
		return
	}
	ref.Reason = "no tag group of this name exists on this host's replica"
	since, seen := t.sincePrev[key]
	if !seen {
		since = t.now
	}
	t.since[key] = since
	if t.now.Sub(since) >= emptySetGrace {
		t.report.Missing = append(t.report.Missing, ref)
	}
}

// bound adds to a NIC's own groups those of every group it is a member of
// whose binding covers network, keeping the NIC's own first.
func (t *tagPass) bound(kind, host, name, network string, own []string) []string {
	extra := t.bindings[tagKey(kind, host, name)+"|"+network]
	if len(extra) == 0 {
		return own
	}
	out := slices.Clone(own)
	for _, sg := range extra {
		if !slices.Contains(out, sg) {
			out = append(out, sg)
		}
	}
	return out
}

// hold reports why a NIC of this workload on network is held at drop, or "".
func (t *tagPass) hold(kind, host, name, network, dev string) string {
	k := tagKey(kind, host, name)
	why := ""
	switch {
	case t.shared[k] != nil:
		// Its membership is unknown on every network.
		why = "firewall identity shared: held at drop"
	case t.tagsBad[k] && t.covers(network):
		why = "firewall tags unreadable: held at drop"
	}
	if why != "" {
		if t.held[k] == nil {
			t.held[k] = map[string]bool{}
		}
		t.held[k][dev] = true
	}
	return why
}

// covers reports whether a workload of unknown membership must be held on
// network: some group binds security groups there, or a deny rule matches a
// group's set (its address may be one the deny should match, on any network).
func (t *tagPass) covers(network string) bool {
	if t.denyRef {
		return true
	}
	for name, g := range t.groups {
		if t.readable[name] && len(g.Def.SecurityGroups) > 0 && g.BindsNetwork(network) {
			return true
		}
	}
	return false
}

// finish completes the report: this host's workloads, the holds and the
// rules still naming a missing group, sorted.
func (t *tagPass) finish() TagGroupReport {
	t.mem.store(t.since)
	here := func(w corrosion.TagWorkload) bool { return w.On == t.host }
	hold := func(w corrosion.TagWorkload) TagWorkloadHold {
		h := TagWorkloadHold{Kind: w.Kind, Name: w.Name, Host: w.Host, FWID: w.FWID}
		h.NICs = slices.Sorted(maps.Keys(t.held[tagKey(w.Kind, w.Host, w.Name)]))
		return h
	}
	for _, w := range t.members.SharedFWID {
		if here(w) {
			h := hold(w)
			h.Holders = t.shared[tagKey(w.Kind, w.Host, w.Name)]
			t.report.SharedIdentity = append(t.report.SharedIdentity, h)
		}
	}
	for _, w := range t.members.TagsUnreadable {
		if here(w) {
			t.report.TagsUnreadable = append(t.report.TagsUnreadable, hold(w))
		}
	}
	for _, w := range t.members.IdentityLost {
		if here(w) {
			t.report.IdentityLost = append(t.report.IdentityLost, hold(w))
		}
	}
	for _, refs := range [][]TagGroupRef{t.report.Missing, t.report.Unreadable} {
		sort.SliceStable(refs, func(i, j int) bool {
			if refs[i].Group != refs[j].Group {
				return refs[i].Group < refs[j].Group
			}
			return refs[i].Table+"/"+refs[i].ID < refs[j].Table+"/"+refs[j].ID
		})
	}
	return t.report
}
