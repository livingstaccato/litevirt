package rulefield

import (
	"strings"
	"testing"
)

// Extensions are the rule forms a later build adds to the write grammar. A
// nil field is a form this build does not accept: Rule and StoredRule refuse
// it as they refuse any malformed field. A hook can only narrow what its form
// accepts: the form itself is fixed here (TagCIDRName, LogActionVerdict), so
// a hook cannot widen the grammar beyond it.
type Extensions struct {
	// LogAction decides whether a stored action in the server's log form
	// ("drop+log", LogActionVerdict) is accepted. Only StoredRule consults
	// it: a client never sends the suffix (it asks for logging through the
	// rule's log field), so Rule refuses it whatever this says. The verdict
	// in front of the suffix is checked as any action.
	LogAction func(action string) (verdict string, ok bool)
	// TagCIDR checks a cidr in the tag-group form ("tag:<name>",
	// TagCIDRName): ok is false for a cidr it does not take, which is then
	// checked as any other; err refuses a malformed one. A cidr it reports ok
	// must also be in that form.
	TagCIDR func(cidr string) (ok bool, err error)
}

// ruleExtensions are this build's: the server's log action (C2) and the
// tag-group cidr (D5). Nothing assigns them at run time (SetExtensionsForTest
// is for tests).
var ruleExtensions = Extensions{LogAction: logAction, TagCIDR: tagCIDR}

// logAction takes the server's log form when it names a verdict: a bare
// "+log" names none, so it is refused rather than read as an accept.
func logAction(action string) (string, bool) {
	verdict, ok := LogActionVerdict(action)
	return verdict, ok && verdict != ""
}

// tagCIDR takes a cidr that starts "tag:" in any case, padded or not, and
// refuses it unless it is exactly tag:<group name>: a client that means a tag
// group is told the form, rather than that it is not an IPv6 address.
func tagCIDR(cidr string) (bool, error) {
	v := trimBlank(cidr)
	if len(v) < len(TagCIDRPrefix) || !strings.EqualFold(v[:len(TagCIDRPrefix)], TagCIDRPrefix) {
		return false, nil
	}
	if _, ok := TagCIDRName(cidr); !ok {
		return true, refuse("cidr", cidr, "a tag-group cidr is %s<group>, the group name [a-z][a-z0-9_]{0,30}", TagCIDRPrefix)
	}
	return true, nil
}

// SetExtensionsForTest replaces this build's extensions for the rest of the
// test and restores them when it ends. It changes package state, so a test
// using it must not run in parallel with any test that checks a rule.
func SetExtensionsForTest(tb testing.TB, e Extensions) {
	tb.Helper()
	old := ruleExtensions
	ruleExtensions = e
	tb.Cleanup(func() { ruleExtensions = old })
}

// TagCIDRPrefix starts a tag-group cidr.
const TagCIDRPrefix = "tag:"

// LogActionSuffix ends a stored action the server's writer marked as logged.
const LogActionSuffix = "+log"

// TagCIDRName returns the group a tag-group cidr names: exactly
// "tag:<name>", where name is a tag group name (TagGroupName; it renders as
// the set reference @lv_tg_<name>). Anything else is not a tag-group cidr.
func TagCIDRName(cidr string) (string, bool) {
	name, ok := strings.CutPrefix(cidr, TagCIDRPrefix)
	if !ok || !TagGroupName(name) {
		return "", false
	}
	return name, true
}

// TagGroupName reports whether name is a tag group name: [a-z][a-z0-9_]{0,30}.
// Its set, lv_tg_<name> (and lv_tg_<name>_v6), is then always one nft word
// within nft's name limit.
func TagGroupName(name string) bool {
	if name == "" || len(name) > 31 || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for _, r := range name[1:] {
		if !(r >= 'a' && r <= 'z' || isDigit(r) || r == '_') {
			return false
		}
	}
	return true
}

// LogActionVerdict returns the verdict a stored action in the log form names
// ("DROP+log" names "drop"), and whether it is in that form.
func LogActionVerdict(action string) (string, bool) {
	return strings.CutSuffix(strings.ToLower(strings.TrimSpace(action)), LogActionSuffix)
}

// StoredRule is Rule for a row as the server stores it, which every rule
// writer checks: the server's own writer may add the log suffix to an action
// (Extensions.LogAction).
func StoredRule(direction, proto, port, cidr, action, comment string) error {
	if f := ruleExtensions.LogAction; f != nil {
		if verdict, ok := LogActionVerdict(action); ok {
			if _, take := f(action); take {
				action = verdict
			}
		}
	}
	return Rule(direction, proto, port, cidr, action, comment)
}

// NormaliseRule lowercases a rule's protocol, port and action, as every rule
// writer stores them: the renderer writes them into the nft script as words,
// and nft resolves a service name only in lower case (`tcp dport SSH` is
// refused, which would stop every host's firewall from applying).
func NormaliseRule(proto, port, action string) (string, string, string) {
	return strings.ToLower(proto), strings.ToLower(port), strings.ToLower(action)
}
