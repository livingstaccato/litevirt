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

// ruleExtensions are this build's: none yet. C2 and D5 fill them here, in
// this file; nothing assigns them at run time (SetExtensionsForTest is for
// tests).
var ruleExtensions Extensions

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
// "tag:<name>", where name is an nft set name (it renders as a set
// reference). Anything else is not a tag-group cidr.
func TagCIDRName(cidr string) (string, bool) {
	name, ok := strings.CutPrefix(cidr, TagCIDRPrefix)
	if !ok || SetName(name) != nil {
		return "", false
	}
	return name, true
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
