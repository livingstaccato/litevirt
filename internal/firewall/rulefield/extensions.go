package rulefield

import "testing"

// Extensions are the rule forms a later build adds to the write grammar. A
// nil field is a form this build does not accept: Rule and StoredRule refuse
// it as they refuse any malformed field.
type Extensions struct {
	// LogAction reads a stored action that carries the server's log suffix
	// ("drop+log"), returning the verdict it names and ok; ok is false for an
	// action without the suffix. Only StoredRule consults it: a client never
	// sends the suffix (it asks for logging through the rule's log field), so
	// Rule refuses it whatever this says.
	LogAction func(action string) (verdict string, ok bool)
	// TagCIDR checks a cidr in the tag-group form ("tag:<name>"): ok is false
	// for a cidr not in that form, which is then checked as any other; err
	// refuses a malformed one. A cidr it reports ok is not checked further,
	// so it refuses anything the renderer could not write.
	TagCIDR func(cidr string) (ok bool, err error)
}

// RuleExtensions are this build's: none yet.
var RuleExtensions Extensions

// SetExtensionsForTest replaces RuleExtensions for the rest of the test and
// restores them when it ends.
func SetExtensionsForTest(tb testing.TB, e Extensions) {
	tb.Helper()
	old := RuleExtensions
	RuleExtensions = e
	tb.Cleanup(func() { RuleExtensions = old })
}

// StoredRule is Rule for a row as the server stores it, which every rule
// writer checks: the server's own writer may add the log suffix to an action
// (RuleExtensions.LogAction).
func StoredRule(direction, proto, port, cidr, action, comment string) error {
	if f := RuleExtensions.LogAction; f != nil {
		if verdict, ok := f(action); ok {
			action = verdict
		}
	}
	return Rule(direction, proto, port, cidr, action, comment)
}
