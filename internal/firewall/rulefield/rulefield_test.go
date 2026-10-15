package rulefield

import (
	"errors"
	"strings"
	"testing"
)

// Every "ok" value below was checked with `nft -c` (nftables 1.1.6) in the
// position the renderer writes the field; every refused one either fails
// there or adds syntax of its own.
func TestGrammar(t *testing.T) {
	type tc struct {
		check func(string) error
		field string
		ok    []string
		bad   []string
	}
	long := strings.Repeat("a", MaxCommentBytes)
	tcpPort := func(s string) error { return Port("tcp", s) }
	cases := []tc{
		// Direction is never written as text: anything but ingress/egress has
		// always been read as ingress, and stays accepted.
		{Direction, "direction",
			[]string{"", "ingress", "egress", "INGRESS", "Egress", "in", "out"},
			[]string{"ingress\n", "in\x00"}},
		{Action, "action",
			[]string{"", "accept", "drop", "reject", "DROP"},
			[]string{"allow", "log", "drop\n", "accept;", " drop", "drop counter", "accept }"}},
		{Proto, "proto",
			[]string{"", "all", "ALL", "tcp", "UDP", "TCP", "icmp", "icmpv6", "ipv6-icmp", "esp", "ESP", "ax.25", "47", "0", "255",
				" esp", "!=tcp", "!= tcp", "== 6", "{ tcp, udp }", "{tcp,esp}", "!= { 6, 17 }"},
			[]string{"tcp;", "tcp\n", "esp accept", "256", "3pc", "tcp,udp", "{ tcp", "{}", "{ tcp,, udp }",
				"!=all", "{ all }", "  ", "esp }", "\"esp\"", "esp#"}},
		{tcpPort, "port",
			[]string{"", "22", "0", "65535", "8000-9000", "8000 - 9000", "22-22", "20-ssh", "ssh", "http-alt", "x11",
				" 22 ", "!=22", "!= 22", "< 1024", "<1024", "eq 22", "ne 22",
				"{ 80, 443 }", "{80,443}", "{ 80, 8000-9000 }", "!= { 80, 443 }", "{ ssh, http }"},
			[]string{"22 accept\n", "22;", "22 accept", "22\n", "80,443", "80, 443", "70000", "9000-8000",
				"1-70000", "{ 80", "80 }", "{ }", "  ", "-22", "22-", "3com", "22 }\n{", "\"22\"", "22 - meta mark"}},
		{CIDR, "cidr",
			[]string{"", "10.0.0.0/8", "10.0.0.1", "10.0.0.1/8", " 10.0.0.0/8", "!=10.0.0.0/8", "!= 10.0.0.0/8",
				"10.0.0.1-10.0.0.9", "10.0.0.1 - 10.0.0.9", " @office", "{ 10.0.0.0/8, 192.168.0.0/16 }", "{ 10.0.0.1-10.0.0.5 }",
				"@office", "@web-trusted.set", "@_x", "@a/b", "!= @office", "!=@office",
				"gw.example.com", "my-host", "!= gw.example.com",
				"2001:db8::/32", "fd00::1", "::ffff:10.0.0.1"},
			[]string{"10.0.0.0/8 }", "10.0.0.0/8\n", "10.0.0.0/8;", "10.0.0.0/8 accept", "10.0.0.0/33",
				"10.0.0.0/8,192.168.0.0/16", "10.0.0.9-10.0.0.1", "  ", "1.2.3",
				"@", "@1abc", "@a b", "@a\n", "@a;", "{ @office }",
				"2001:db8::/300", "fd00::1\n", " fd00::1", "!=fd00::1", "fe80::1%eth0", "not-an-address:"}},
		{Comment, "comment",
			[]string{"", "admin ssh", "a # b", "it's", "a } b {", "a; b", "héllo", "a\\b", "a\nb", long, long[:121], long[:127]},
			[]string{`say "hi"`, `x"; ip saddr 0.0.0.0/0 accept; #`, long + "a", strings.Repeat("\n", 65)}},
		{SetName, "ipset name",
			[]string{"abc", "A_B9", "a-b", "a/b", "a.b", "_x", ".x", strings.Repeat("a", 255)},
			[]string{"", "1abc", "-a", "a b", "a\n", "a;", "a{", "a}", `a"`, "@a", strings.Repeat("a", 256)}},
		{SetElement, "ipset element",
			[]string{"10.0.0.0/8", "10.0.0.1", " 10.0.0.1", "10.0.0.1-10.0.0.5", "gw.example.com", "fd00::/8", "2001:db8::1"},
			[]string{"", "  ", "10.0.0.0/8 }", "10.0.0.0/8\n", "10.0.0.0/8 accept", "{ 10.0.0.1 }", "!=10.0.0.1",
				"@other", "fd00::/8\n", " fd00::1"}},
	}
	for _, c := range cases {
		for _, v := range c.ok {
			if err := c.check(v); err != nil {
				t.Errorf("%s %q refused: %v", c.field, v, err)
			}
		}
		for _, v := range c.bad {
			err := c.check(v)
			if err == nil {
				t.Errorf("%s %q accepted", c.field, v)
				continue
			}
			var fe *FieldError
			if !errors.As(err, &fe) || fe.Field != c.field || fe.Value != v {
				t.Errorf("%s %q: error %v does not name the field and value", c.field, v, err)
			}
			if !strings.Contains(err.Error(), c.field) {
				t.Errorf("%s %q: message %q does not name the field", c.field, v, err)
			}
		}
	}
	// A port is written only for tcp and udp: for any other protocol it was
	// never part of a script, so only a control character is refused.
	if err := Port("esp", "22 whatever"); err != nil {
		t.Errorf("port of an esp rule refused: %v", err)
	}
	if err := Port("esp", "22\n"); err == nil {
		t.Error("port with a newline accepted for esp")
	}
}

// TestSyntax is the renderer's level: it refuses only text that adds or breaks
// nft syntax, and passes every word through for nft to judge, as before.
func TestSyntax(t *testing.T) {
	for _, v := range []string{"70000", "9000-8000", "SSH", "nosuchservice", "{ 80, 443 }", "!= 22", "< 1024", "8000 - 9000"} {
		if err := RenderPort("tcp", v); err != nil {
			t.Errorf("RenderPort(%q): %v", v, err)
		}
	}
	for _, v := range []string{"22\n", "22;", "22 accept", "22 }", "22 #", `22"`, "80,443", "{ 80", "22 - meta mark"} {
		if err := RenderPort("tcp", v); err == nil {
			t.Errorf("RenderPort(%q) accepted", v)
		}
	}
	if err := RenderPort("esp", "22 anything"); err != nil {
		t.Errorf("an esp rule's port is never written: %v", err)
	}
	for _, v := range []string{"TCP", "esp", "3pc", "256", "!=tcp", "{ tcp, udp }"} {
		if err := RenderProto(v); err != nil {
			t.Errorf("RenderProto(%q): %v", v, err)
		}
	}
	for _, v := range []string{"esp;", "esp\n", "esp accept", "esp }"} {
		if err := RenderProto(v); err == nil {
			t.Errorf("RenderProto(%q) accepted", v)
		}
	}
	for _, v := range []string{"any", "gw.example.com", "10.0.0.1 - 10.0.0.9", "!= @x", "{ @x }", "fd00::/8\n", "@x\n"} {
		if err := RenderCIDR(v); err != nil {
			t.Errorf("RenderCIDR(%q): %v (an IPv6 CIDR and a set reference are the renderer's own checks)", v, err)
		}
	}
	for _, v := range []string{"10.0.0.0/8 }", "10.0.0.0/8;", "10.0.0.0/8\n", "10.0.0.0/8 accept"} {
		if err := RenderCIDR(v); err == nil {
			t.Errorf("RenderCIDR(%q) accepted", v)
		}
	}
	if err := RenderSetName("1abc"); err != nil {
		t.Errorf("RenderSetName(1abc): %v", err)
	}
	for _, v := range []string{"a b", "a\n", "a;", "a{", "@a"} {
		if err := RenderSetName(v); err == nil {
			t.Errorf("RenderSetName(%q) accepted", v)
		}
	}
}

// TestRule_PlanCases are plan Task 0.4's cases.
func TestRule_PlanCases(t *testing.T) {
	bad := map[string][6]string{
		"port newline":  {"ingress", "tcp", "22 accept\n", "", "accept", ""},
		"proto semi":    {"ingress", "tcp;", "", "", "accept", ""},
		"cidr brace":    {"ingress", "tcp", "22", "10.0.0.0/8 }", "accept", ""},
		"action allow":  {"ingress", "tcp", "22", "", "allow", ""},
		"comment quote": {"ingress", "tcp", "22", "", "accept", `a"b`},
	}
	for name, f := range bad {
		if err := Rule(f[0], f[1], f[2], f[3], f[4], f[5]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	good := [][6]string{
		{"ingress", "tcp", "ssh", "", "accept", ""},
		{"ingress", "tcp", "{ 80, 443 }", "", "accept", ""},
		{"ingress", "tcp", "8000-9000", "", "accept", ""},
		{"egress", "esp", "", "", "drop", ""},
		{"ingress", "tcp", "22", "@office", "accept", "office ssh"},
		{"ingress", "tcp", "22", "2001:db8::/32", "accept", ""},
		{"", "", "", "", "", ""},
	}
	for _, f := range good {
		if err := Rule(f[0], f[1], f[2], f[3], f[4], f[5]); err != nil {
			t.Errorf("%q: %v", f, err)
		}
	}
	// A bare list is refused with the braced form as the way out.
	if err := Port("tcp", "80,443"); err == nil || !strings.Contains(err.Error(), "{ a, b }") {
		t.Errorf("bare port list: %v, want a hint to brace it", err)
	}
}
