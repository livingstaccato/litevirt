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

	SetExtensionsForTest(t, Extensions{})
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

// A hook can only narrow its form (review m-1): one that takes anything still
// gets only "tag:<set name>" and "<verdict>+log" past the grammar, so a
// careless C2 or D5 hook cannot store text the renderer cannot write.
//
// Mutations: CIDR returns the hook's verdict without TagCIDRName — tag:x;drop
// passes, red; StoredRule takes the hook's verdict without LogActionVerdict —
// "drop;x" passes, red.
func TestRuleExtensions_HookCannotWiden(t *testing.T) {
	SetExtensionsForTest(t, Extensions{
		LogAction: func(a string) (string, bool) { return "drop", true },
		TagCIDR:   func(string) (bool, error) { return true, nil },
	})
	for _, cidr := range []string{"tag:x;drop", "tag:", "tag:a b", "tag:x\n", "10.0.0.0/8; accept", "tag :web", "tag:web-1"} {
		if err := StoredRule("ingress", "tcp", "22", cidr, "drop", ""); err == nil {
			t.Errorf("cidr %q taken by a hook that takes anything", cidr)
		}
	}
	if err := StoredRule("ingress", "tcp", "22", "tag:web_1", "drop", ""); err != nil {
		t.Errorf("tag:web_1: %v", err)
	}
	for _, action := range []string{"drop;x", "accept log", "drop+log;x"} {
		if err := StoredRule("ingress", "tcp", "22", "tag:web", action, ""); err == nil {
			t.Errorf("action %q taken by a hook that takes anything", action)
		}
	}
	if err := StoredRule("ingress", "tcp", "22", "tag:web", "Reject+LOG", ""); err != nil {
		t.Errorf("Reject+LOG: %v", err)
	}
}

// The shared predicates name the forms the corrosion classifier uses too.
func TestTagCIDRNameAndLogActionVerdict(t *testing.T) {
	for cidr, want := range map[string]bool{"tag:web": true, "tag:web_1": true, "tag:lv_x": true, "tag:web-1.a": false,
		"tag:Web": false, "tag:": false, "tag:a:b": false, " tag:web": false, "tag:a b": false, "tag:1a": false,
		"tag:" + strings.Repeat("a", 31): true, "tag:" + strings.Repeat("a", 32): false, "@web": false} {
		if _, ok := TagCIDRName(cidr); ok != want {
			t.Errorf("TagCIDRName(%q) = %v, want %v", cidr, ok, want)
		}
	}
	for action, want := range map[string]string{"drop+log": "drop", " DROP+LOG ": "drop", "accept+log": "accept"} {
		if v, ok := LogActionVerdict(action); !ok || v != want {
			t.Errorf("LogActionVerdict(%q) = %q, %v; want %q", action, v, ok, want)
		}
	}
	if _, ok := LogActionVerdict("drop"); ok {
		t.Error("LogActionVerdict(drop) = ok")
	}
}

// NormaliseRule lowercases proto, port and action, and nothing else changes.
func TestNormaliseRule(t *testing.T) {
	p, port, a := NormaliseRule("TCP", "{ 80, HTTPS } ", "DROP+Log")
	if p != "tcp" || port != "{ 80, https } " || a != "drop+log" {
		t.Errorf("NormaliseRule = %q %q %q", p, port, a)
	}
}

// D5a: this build's grammar takes the tag-group cidr, tag:<group>, with the
// group-name grammar ([a-z][a-z0-9_]{0,30}), at the client grammar and the
// writers'. A cidr meant as one but outside that form is refused naming the
// form, not judged as an IPv6 address.
//
// Mutations: leave ruleExtensions.TagCIDR nil — tag:web is refused, red;
// TagCIDRName takes any nft set name — tag:web-1 passes, red; tagCIDR
// declines a mis-cased prefix — TAG:web is refused as "not an IPv6 address",
// red.
func TestTagCIDR_ThisBuild(t *testing.T) {
	for _, cidr := range []string{"tag:web", "tag:db_2", "tag:lv_x"} {
		if err := Rule("ingress", "tcp", "5432", cidr, "accept", ""); err != nil {
			t.Errorf("Rule %q: %v", cidr, err)
		}
		if err := StoredRule("ingress", "tcp", "5432", cidr, "drop", ""); err != nil {
			t.Errorf("StoredRule %q: %v", cidr, err)
		}
	}
	for _, cidr := range []string{"tag:web-1", "tag:Web", "TAG:web", " tag:web", "tag:", "tag:1a", "Tag:a.b"} {
		err := Rule("ingress", "tcp", "5432", cidr, "accept", "")
		if err == nil || !strings.Contains(err.Error(), "a tag-group cidr is tag:<group>") {
			t.Errorf("Rule %q: %v, want refused naming the tag-group form", cidr, err)
		}
	}
	// A cidr that is not in the tag form is judged as before.
	if err := Rule("ingress", "tcp", "22", "2001:db8::/32", "accept", ""); err != nil {
		t.Errorf("an IPv6 cidr: %v", err)
	}
}

// TagGroupName is the tag group grammar corrosion's group writer uses too.
func TestTagGroupName(t *testing.T) {
	for name, want := range map[string]bool{"web": true, "a": true, "a_1": true, "lv_x": true,
		strings.Repeat("a", 31): true, strings.Repeat("a", 32): false, "": false, "1a": false, "_a": false,
		"Web": false, "a-b": false, "a.b": false} {
		if got := TagGroupName(name); got != want {
			t.Errorf("TagGroupName(%q) = %v, want %v", name, got, want)
		}
	}
}

// C2: this build's own extensions take the server's log form at the writers'
// grammar (StoredRule) when it names a verdict, and never at the client's
// (Rule). A bare "+log" names no verdict and is refused, as is any suffix but
// "+log".
//
// Mutations: leave LogAction nil — drop+log is refused, red; take a bare
// "+log" — it passes, red.
func TestRuleExtensions_ThisBuildTakesTheLogForm(t *testing.T) {
	stored := func(action string) error { return StoredRule("ingress", "tcp", "22", "10.0.0.0/8", action, "") }
	for _, a := range []string{"drop+log", "accept+log", "reject+log", "DROP+LOG"} {
		if err := stored(a); err != nil {
			t.Errorf("stored %q: %v", a, err)
		}
	}
	for _, a := range []string{"+log", " +log", "drop+foo", "bogus+log", "drop+log+log", "drop +log"} {
		if err := stored(a); err == nil {
			t.Errorf("stored %q accepted", a)
		}
	}
	if err := Rule("ingress", "tcp", "22", "10.0.0.0/8", "drop+log", ""); err == nil {
		t.Error("a client drop+log passed the client grammar")
	}
}
