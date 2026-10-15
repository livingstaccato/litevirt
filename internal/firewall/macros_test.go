package firewall

import (
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/firewall/rulefield"
)

// Every catalog row is an ordinary rule: it passes the write grammar that the
// rule handlers run (rulefield.Rule), for both directions.
//
// Mutation: add a row with a malformed port (`tcp 80,`) or an icmp macro to
// the catalog, red.
func TestMacros_EveryRowPassesWriteGrammar(t *testing.T) {
	if len(Macros()) == 0 {
		t.Fatal("empty catalog")
	}
	for _, m := range Macros() {
		if len(m.Rows) == 0 {
			t.Errorf("%s: no rows", m.Name)
		}
		for _, r := range m.Rows {
			for _, dir := range []string{"ingress", "egress"} {
				if err := rulefield.Rule(dir, r.Proto, r.Port, "", "accept", "macro "+m.Name); err != nil {
					t.Errorf("%s row %s %s: %v", m.Name, r.Proto, r.Port, err)
				}
				if err := rulefield.StoredRule(dir, r.Proto, r.Port, "", "accept", "macro "+m.Name); err != nil {
					t.Errorf("%s row %s %s: StoredRule: %v", m.Name, r.Proto, r.Port, err)
				}
			}
			if r.Proto != "tcp" && r.Proto != "udp" {
				t.Errorf("%s: proto %q; the catalog holds tcp/udp ports only", m.Name, r.Proto)
			}
			if r.Port == "" {
				t.Errorf("%s: a %s row with no port", m.Name, r.Proto)
			}
		}
	}
}

// There is no ICMP macro: litevirt rules have no ICMP type field.
//
// Mutation: add `Ping` (or any icmp row) to the catalog, red.
func TestMacros_NoICMP(t *testing.T) {
	for _, m := range Macros() {
		if strings.EqualFold(m.Name, "ping") || strings.Contains(strings.ToLower(m.Name), "icmp") {
			t.Errorf("catalog has %q", m.Name)
		}
		for _, r := range m.Rows {
			if strings.Contains(strings.ToLower(r.Proto), "icmp") {
				t.Errorf("%s has an icmp row", m.Name)
			}
		}
	}
	if _, err := Expand("Ping", "ingress", "", "accept"); err == nil {
		t.Error("Expand(Ping) succeeded")
	}
}

// DNS is udp 53, then tcp 53, in that order, whatever the case of the name.
//
// Mutation: swap the DNS rows, red; make Expand non-deterministic (range a
// map), red.
func TestExpand_DNSOrderAndCase(t *testing.T) {
	want := []ExpandedRule{
		{Direction: "egress", Proto: "udp", Port: "53", CIDR: "@admins", Action: "accept"},
		{Direction: "egress", Proto: "tcp", Port: "53", CIDR: "@admins", Action: "accept"},
	}
	for _, name := range []string{"DNS", "dns", "Dns"} {
		got, err := Expand(name, "egress", "@admins", "accept")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Expand(%q) = %+v, want %+v", name, got, want)
		}
	}
	// Deterministic.
	a, _ := Expand("ceph", "ingress", "", "accept")
	for i := 0; i < 20; i++ {
		b, _ := Expand("ceph", "ingress", "", "accept")
		if !reflect.DeepEqual(a, b) {
			t.Fatal("expansion varies between calls")
		}
	}
	if len(a) != 3 || a[0].Port != "6789" || a[1].Port != "3300" || a[2].Port != "6800-7300" {
		t.Errorf("Ceph = %+v", a)
	}
}

// Names print in Proxmox's spelling, found case-insensitively.
func TestLookupMacro_CanonicalSpelling(t *testing.T) {
	m, ok := LookupMacro("pOsTgReSqL")
	if !ok || m.Name != "PostgreSQL" {
		t.Errorf("LookupMacro = %+v, %v", m, ok)
	}
	if _, ok := LookupMacro(""); ok {
		t.Error("empty name found")
	}
}

// An unknown name is refused and the refusal lists the catalog.
//
// Mutation: drop the catalog from the message, red.
func TestExpand_UnknownListsCatalog(t *testing.T) {
	_, err := Expand("gopher", "ingress", "", "accept")
	if err == nil {
		t.Fatal("unknown macro accepted")
	}
	for _, m := range Macros() {
		if !strings.Contains(err.Error(), m.Name) {
			t.Errorf("refusal does not list %s: %v", m.Name, err)
		}
	}
}

// A macro expands to rows that pass the grammar together with the caller's
// direction, cidr and action; a bad one is refused before any row is returned.
//
// Mutation: skip the grammar check in Expand, red.
func TestExpand_RefusesBadFields(t *testing.T) {
	rows, err := Expand("ssh", "ingress", "10.0.0.0/8;", "accept")
	if err == nil {
		t.Errorf("injection-class cidr accepted: %+v", rows)
	}
	if rows != nil {
		t.Errorf("rows returned with an error: %+v", rows)
	}
	rows, err = Expand("web", "ingress", "", "allow")
	if err == nil {
		t.Error("bad action accepted")
	}
	if rows != nil {
		t.Errorf("rows returned with an error: %+v", rows)
	}
}

// The returned catalog is a copy: a caller cannot change what a macro means.
func TestMacros_ReturnsCopy(t *testing.T) {
	Macros()[0].Rows[0].Port = "1"
	if Macros()[0].Rows[0].Port == "1" {
		t.Error("catalog mutated through Macros()")
	}
}

// Every catalog macro expands, in both directions, to one rule per row in row
// order, and each expanded rule passes the write grammar.
//
// Mutation: add a malformed row to any macro, or drop a row in Expand, red.
func TestExpand_EveryMacroBothDirections(t *testing.T) {
	for _, m := range Macros() {
		for _, dir := range []string{"ingress", "egress"} {
			rows, err := Expand(strings.ToUpper(m.Name), dir, "10.0.0.0/8", "accept")
			if err != nil {
				t.Errorf("%s %s: %v", m.Name, dir, err)
				continue
			}
			if len(rows) != len(m.Rows) {
				t.Errorf("%s %s: %d rules, want %d", m.Name, dir, len(rows), len(m.Rows))
				continue
			}
			for i, r := range rows {
				if r.Proto != m.Rows[i].Proto || r.Port != m.Rows[i].Port || r.Direction != dir {
					t.Errorf("%s %s row %d = %+v", m.Name, dir, i, r)
				}
				if err := rulefield.Rule(r.Direction, r.Proto, r.Port, r.CIDR, r.Action, ""); err != nil {
					t.Errorf("%s %s row %d: %v", m.Name, dir, i, err)
				}
			}
		}
	}
}
