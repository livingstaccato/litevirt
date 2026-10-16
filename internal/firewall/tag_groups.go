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

	// Handlings of an unreadable or shadowed group (controller ruling
	// 2026-10-16, amending spec §4.6).
	TagHandlingKeptLastRead = "kept as last read: rendered from the last definition this host read"
	TagHandlingHeldTagged   = "never read on this host: every NIC of every workload here with tags is held at drop until it reads"
	TagHandlingShadowed     = "its bindings are rendered; its set cannot be declared, so its accepts match nothing and its denies lose their address"
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
	// UnreadableHolds are this host's workloads with tags, held at drop on
	// every network because a group could not be read and was never read
	// here (TagHandlingHeldTagged).
	UnreadableHolds []TagWorkloadHold
}

// tagMemory is what a loader remembers between passes: since when each rule
// has named a missing group, so the condition waits out emptySetGrace.
// Passes may overlap (Reconcile is not serialized), hence the lock.
//
// defs is each group's last readable definition, which a group whose row
// turns unreadable is rendered from (controller ruling 2026-10-16). It lives
// as long as the loader: after a restart, a group unreadable from the start
// has none.
type tagMemory struct {
	mu    sync.Mutex
	since map[string]time.Time
	defs  map[string]corrosion.FirewallTagGroupDef
}

func (m *tagMemory) snapshot() (map[string]time.Time, map[string]corrosion.FirewallTagGroupDef) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.since, m.defs
}

func (m *tagMemory) store(since map[string]time.Time, defs map[string]corrosion.FirewallTagGroupDef) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.since, m.defs = since, defs
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
	// binds are the definitions whose bindings render: the readable groups,
	// those kept as last read, and the shadowed ones.
	binds map[string]corrosion.FirewallTagGroupDef
	defs  map[string]corrosion.FirewallTagGroupDef // this pass's readable definitions, for the memory
	// holdAll: a group cannot be read and was never read here, so every
	// tagged workload's membership is unknown.
	holdAll bool
	tagged  map[string]bool // kind|host|name of every workload with tags

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
//
// hostRules are every host's host-tier rules: a deny on a tag group in any
// host's tier matches this host's workloads' addresses there (denyRef).
func loadTagGroups(ctx context.Context, db *corrosion.Client, host string, now time.Time, mem *tagMemory,
	hostRules []corrosion.FirewallRule) (*tagPass, error) {
	sincePrev, kept := mem.snapshot()
	m, err := corrosion.ListTagGroupMembersKeeping(ctx, db, kept)
	if err != nil {
		return nil, err
	}
	t := &tagPass{host: host, now: now, mem: mem, sincePrev: sincePrev, members: m,
		groups: map[string]corrosion.FirewallTagGroup{}, readable: map[string]bool{}, whyNot: map[string]string{},
		binds: map[string]corrosion.FirewallTagGroupDef{}, defs: map[string]corrosion.FirewallTagGroupDef{},
		tagged: map[string]bool{},
		empty:  map[string]bool{}, since: map[string]time.Time{}, reported: map[string]bool{},
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
			// Never read here: neither its selector nor its networks are
			// known, so every tagged workload is held (hold).
			t.whyNot[g.Name] = "its row cannot be read"
			t.holdAll = true
			t.report.Members[g.Name] = 0
			t.report.Unreadable = append(t.report.Unreadable, TagGroupRef{Group: g.Name, Reason: t.whyNot[g.Name], Handling: TagHandlingHeldTagged})
			continue
		case t.shadows(g.Name):
			// lv_tg_<x>_v6 is group x's IPv6 companion: declaring it for
			// this group too would make nft refuse the whole ruleset. Its
			// bindings need no set and are rendered.
			t.whyNot[g.Name] = fmt.Sprintf("its set would be the IPv6 companion of group %q's", strings.TrimSuffix(g.Name, ipv6SetSuffix))
			// Its bindings apply to its real members (re-review m-B).
			t.report.Members[g.Name] = len(v.Members)
			t.report.Unreadable = append(t.report.Unreadable, TagGroupRef{Group: g.Name, Reason: t.whyNot[g.Name], Handling: TagHandlingShadowed})
		case v.Kept:
			t.readable[g.Name] = true
			t.report.Members[g.Name] = len(v.Members)
			t.report.Unreadable = append(t.report.Unreadable, TagGroupRef{Group: g.Name, Reason: "its row cannot be read", Handling: TagHandlingKeptLastRead})
		default:
			t.readable[g.Name] = true
			t.report.Members[g.Name] = len(v.Members)
		}
		t.defs[g.Name] = g.Def
		t.binds[g.Name] = g.Def
		for _, mb := range v.Members {
			if len(g.Def.SecurityGroups) == 0 {
				continue
			}
			for _, n := range mb.Bound {
				k := tagKey(mb.Kind, mb.Host, mb.Name) + "|" + n
				t.bindings[k] = append(t.bindings[k], g.Def.SecurityGroups...)
			}
		}
	}
	for _, w := range m.Tagged {
		t.tagged[tagKey(w.Kind, w.Host, w.Name)] = true
	}
	for _, r := range hostRules {
		t.noteDeny(r.CIDR, r.Action)
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

// noteDeny records that a deny matches a rendered group's set (denyRef). It
// is given two kinds of cidr:
//   - every host's stored host-tier rows (loadTagGroups): tag:<g>, and a
//     positive @lv_tg_<g> stored before writes refused one, counted although
//     its own host leaves it out, which only widens the hold;
//   - this host's renderings (rule): the tag pass's rewrite of tag:<g> to
//     @lv_tg_<g>, this pass's or one kept from an earlier pass.
func (t *tagPass) noteDeny(cidr, action string) {
	if isAccept(action) {
		return
	}
	if name, ok, valid := tagRef(cidr); ok && valid && t.readable[name] {
		t.denyRef = true
	}
	if set, ok := rulefield.SetRef(cidr); ok && !rulefield.NegatedSetRef(cidr) {
		if g, isTag := strings.CutPrefix(set, TagGroupSetPrefix); isTag && t.readable[g] {
			t.denyRef = true
		}
	}
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

// isAccept reports whether a stored action accepts ("" is accept, and so is
// a logged accept, "accept+log"); any other action is handled as a deny,
// which fails closed. tag-group rm --force judges references the same way.
func isAccept(action string) bool {
	a, _ := rulefield.LogActionVerdict(action)
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
	ownRef := ""
	if name, ok, valid := tagRef(cidr); ok {
		set := TagGroupSetPrefix + name
		if valid {
			// This row's renderings, this pass's and any kept from an
			// earlier one, name the group's set because it says tag:<name>.
			ownRef = set
		}
		switch {
		case valid && t.readable[name]:
			cidr = "@" + set
			// Before q.rule, which may render a kept rendering instead: a
			// set never rendered then only widens the hold (fails closed).
			t.noteDeny(cidr, action)
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
	if set, isRef := rulefield.SetRef(cidr); isRef && rulefield.NegatedSetRef(cidr) && !isAccept(action) {
		if g, isTag := strings.CutPrefix(set, TagGroupSetPrefix); isTag && !t.readable[g] {
			// "Deny all not in" a group this pass does not render: whom it
			// spares is unknown, so it denies everyone, as a tag: deny does
			// (D4 re-review I-A). Left out, it would deny no one. Only a row
			// stored as != @lv_tg_<g> reaches this, from before writes refused
			// one; on a group this pass renders, the same row is a user set
			// reference and is left out (userSetName), as on integration.
			t.refer(table, id, g, action, TagHandlingNoAddress)
			cidr = ""
		}
	}
	q.ownRef = ownRef
	r, ok := q.rule(table, id, direction, proto, port, cidr, action, comment)
	q.ownRef = ""
	if !ok {
		return r, false
	}
	if set, isRef := rulefield.SetRef(r.CIDR); isRef && strings.HasPrefix(set, TagGroupSetPrefix) && rulefield.NegatedSetRef(r.CIDR) &&
		(r.Action == Accept || r.Action == "") {
		// Defence in depth: "not a member" accepted would admit every
		// workload whose membership cannot be proven (D4 review I-3), so it is
		// left out, which matches nothing. No rendering should reach this —
		// the tag pass writes the positive @lv_tg_<g>, a row stored as
		// != @lv_tg_<g> is left out by userSetName (or, as a deny on a group
		// not rendered, loses its address above), and a kept rendering is one
		// of those — but the firewall fails closed when that is wrong.
		delete(q.next, table+"/"+id)
		q.invalid = append(q.invalid, InvalidRow{Table: table, ID: id, Action: action,
			Reason:   fmt.Sprintf("cidr %q accepts what is not in a tag group's set, which would admit a workload whose membership cannot be proven", r.CIDR),
			Handling: HandlingLeftOut})
		return Rule{}, false
	}
	t.noteDeny(r.CIDR, string(r.Action))
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
	case t.holdAll && (t.tagged[k] || t.tagsBad[k]):
		// A group could not be read and never was here: whether this
		// workload is one of its members is unknown, on any network.
		why = "tag group unreadable: held at drop"
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
	for _, def := range t.binds {
		if len(def.SecurityGroups) > 0 && (len(def.Networks) == 0 || slices.Contains(def.Networks, network)) {
			return true
		}
	}
	return false
}

// finish completes the report: this host's workloads, the holds and the
// rules still naming a missing group, sorted.
func (t *tagPass) finish() TagGroupReport {
	t.mem.store(t.since, t.defs)
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
	if t.holdAll {
		for _, w := range t.members.Tagged {
			if here(w) {
				t.report.UnreadableHolds = append(t.report.UnreadableHolds, hold(w))
			}
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
