package rulefield

import (
	"errors"
	"strings"
	"testing"
)

// fakeLogAction and fakeTagCIDR stand in for the forms C2 and D5 add.
func fakeLogAction(a string) (string, bool) {
	v, ok := strings.CutSuffix(strings.ToLower(a), "+log")
	return v, ok
}

func fakeTagCIDR(c string) (bool, error) {
	name, ok := strings.CutPrefix(c, "tag:")
	if !ok {
		return false, nil
	}
	if name == "" {
		return true, refuse("cidr", c, "empty tag-group name")
	}
	return true, nil
}

// With no extension this build's grammar refuses the "+log" action and the
// tag-group cidr, at the client grammar (Rule) and at the writers' (StoredRule).
// LogAction is honoured by StoredRule only, never by Rule: a client never
// sends the suffix, and the verdict it names is still checked. TagCIDR is
// honoured by both, and its refusal is the grammar's.
//
// Mutations: Rule honours LogAction — a client "drop+log" passes, red;
// StoredRule ignores LogAction — the server's row is refused, red; the
// verdict is not checked — "bogus+log" passes, red; CIDR ignores TagCIDR —
// "tag:web" is refused with the extension, red.
func TestRuleExtensions(t *testing.T) {
	stored := func(cidr, action string) error { return StoredRule("ingress", "tcp", "22", cidr, action, "") }
	client := func(cidr, action string) error { return Rule("ingress", "tcp", "22", cidr, action, "") }
	isField := func(err error) bool {
		var fe *FieldError
		return errors.As(err, &fe)
	}

	for _, f := range []func(string, string) error{client, stored} {
		if err := f("10.0.0.0/8", "drop+log"); !isField(err) {
			t.Errorf("no extension: drop+log: %v, want refused", err)
		}
		if err := f("tag:web", "accept"); !isField(err) {
			t.Errorf("no extension: tag:web: %v, want refused", err)
		}
	}

	SetExtensionsForTest(t, Extensions{LogAction: fakeLogAction, TagCIDR: fakeTagCIDR})
	if err := client("10.0.0.0/8", "drop+log"); !isField(err) {
		t.Errorf("client drop+log with LogAction: %v, want refused", err)
	}
	if err := stored("10.0.0.0/8", "DROP+LOG"); err != nil {
		t.Errorf("stored DROP+LOG with LogAction: %v", err)
	}
	if err := stored("10.0.0.0/8", "bogus+log"); !isField(err) {
		t.Errorf("stored bogus+log: %v, want the verdict refused", err)
	}
	for _, f := range []func(string, string) error{client, stored} {
		if err := f("tag:web", "accept"); err != nil {
			t.Errorf("tag:web with TagCIDR: %v", err)
		}
		if err := f("tag:", "accept"); err == nil || !strings.Contains(err.Error(), "empty tag-group name") {
			t.Errorf("tag: with TagCIDR: %v, want its refusal", err)
		}
		if err := f("10.0.0.0/8; accept", "accept"); !isField(err) {
			t.Errorf("an injected cidr with TagCIDR set: %v, want refused", err)
		}
	}
}
