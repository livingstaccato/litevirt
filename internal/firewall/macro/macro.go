package macro

import (
	"fmt"
	"strings"

	"github.com/litevirt/litevirt/internal/firewall/rulefield"
)

// MacroRow is one tcp or udp destination-port row of a macro.
type MacroRow struct {
	Proto string
	Port  string
}

// Macro is a named set of rows that share every other field of a rule.
type Macro struct {
	Name string // Proxmox's spelling
	Rows []MacroRow
}

// ExpandedRule is one ordinary rule a macro expands to.
type ExpandedRule struct {
	Direction string
	Proto     string
	Port      string
	CIDR      string
	Action    string
}

// macroCatalog is the authority for rule macros: tcp/udp destination ports
// only. There is no ICMP macro, because a rule has no ICMP type field. Rows
// are in the order they expand.
var macroCatalog = []Macro{
	{"SSH", []MacroRow{{"tcp", "22"}}},
	{"HTTP", []MacroRow{{"tcp", "80"}}},
	{"HTTPS", []MacroRow{{"tcp", "443"}}},
	{"Web", []MacroRow{{"tcp", "80"}, {"tcp", "443"}}},
	{"DNS", []MacroRow{{"udp", "53"}, {"tcp", "53"}}},
	{"NTP", []MacroRow{{"udp", "123"}}},
	{"SMTP", []MacroRow{{"tcp", "25"}}},
	{"SMTPS", []MacroRow{{"tcp", "465"}}},
	{"Submission", []MacroRow{{"tcp", "587"}}},
	{"IMAP", []MacroRow{{"tcp", "143"}}},
	{"IMAPS", []MacroRow{{"tcp", "993"}}},
	{"POP3", []MacroRow{{"tcp", "110"}}},
	{"POP3S", []MacroRow{{"tcp", "995"}}},
	{"LDAP", []MacroRow{{"tcp", "389"}}},
	{"LDAPS", []MacroRow{{"tcp", "636"}}},
	{"MySQL", []MacroRow{{"tcp", "3306"}}},
	{"PostgreSQL", []MacroRow{{"tcp", "5432"}}},
	{"RDP", []MacroRow{{"tcp", "3389"}}},
	{"VNC", []MacroRow{{"tcp", "5900-5999"}}},
	{"SNMP", []MacroRow{{"udp", "161-162"}, {"tcp", "161"}}},
	{"Syslog", []MacroRow{{"udp", "514"}, {"tcp", "514"}}},
	{"Telnet", []MacroRow{{"tcp", "23"}}},
	{"Rsync", []MacroRow{{"tcp", "873"}}},
	{"Git", []MacroRow{{"tcp", "9418"}}},
	{"BGP", []MacroRow{{"tcp", "179"}}},
	{"Ceph", []MacroRow{{"tcp", "6789"}, {"tcp", "3300"}, {"tcp", "6800-7300"}}},
}

// Macros returns a copy of the catalog, in catalog order.
func Macros() []Macro {
	out := make([]Macro, len(macroCatalog))
	for i, m := range macroCatalog {
		out[i] = Macro{Name: m.Name, Rows: append([]MacroRow(nil), m.Rows...)}
	}
	return out
}

// LookupMacro finds a macro by name, ignoring case, and returns it under its
// canonical spelling.
func LookupMacro(name string) (Macro, bool) {
	for _, m := range macroCatalog {
		if strings.EqualFold(m.Name, name) {
			return Macro{Name: m.Name, Rows: append([]MacroRow(nil), m.Rows...)}, true
		}
	}
	return Macro{}, false
}

// Expand turns a macro into ordinary rules, one per row in catalog order,
// each carrying the given direction, cidr and action. An unknown name is
// refused with the catalog listed. Every row is checked against the write
// grammar (rulefield.Rule) before any is returned, so a caller never writes
// half a macro for a bad cidr or action.
func Expand(name, direction, cidr, action string) ([]ExpandedRule, error) {
	m, ok := LookupMacro(name)
	if !ok {
		names := make([]string, len(macroCatalog))
		for i, c := range macroCatalog {
			names[i] = c.Name
		}
		return nil, fmt.Errorf("unknown macro %q; the catalog is: %s", name, strings.Join(names, ", "))
	}
	out := make([]ExpandedRule, 0, len(m.Rows))
	for _, r := range m.Rows {
		if err := rulefield.Rule(direction, r.Proto, r.Port, cidr, action, ""); err != nil {
			return nil, fmt.Errorf("macro %s: %w", m.Name, err)
		}
		out = append(out, ExpandedRule{Direction: direction, Proto: r.Proto, Port: r.Port, CIDR: cidr, Action: action})
	}
	return out, nil
}
