package nictap

import (
	"regexp"
	"testing"
)

// TestName: a guest NIC's host tap name is fixed by its MAC — known before
// the domain starts, the same on every host it migrates to — and is a valid,
// non-reserved Linux interface name.
func TestName(t *testing.T) {
	a := Name("52:54:00:AA:bb:cc")
	if a != Name("52:54:00:aa:BB:CC") {
		t.Errorf("the name depends on the MAC's case")
	}
	if a == Name("52:54:00:aa:bb:cd") {
		t.Errorf("two MACs share a tap name")
	}
	if len(a) > 15 || !regexp.MustCompile(`^lvt[0-9a-f]{12}$`).MatchString(a) {
		t.Errorf("Name = %q: not a 15-character lvt<hex> interface name", a)
	}
	if Name("not-a-mac") != "" {
		t.Errorf("an unparseable MAC must name no tap")
	}
}
