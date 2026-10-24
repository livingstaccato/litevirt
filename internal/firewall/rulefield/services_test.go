package rulefield

import (
	"strings"
	"testing"
)

// testServices is the services database the port tests resolve against.
var testServices = map[string]uint64{"ssh": 22, "http": 80, "www": 80, "netbios-ns": 137, "bootps": 67}

// TestPortUnresolvable (fw-0.4 review I-3, and the octal reading behind a
// backwards range): nft refuses the whole ruleset over a port it cannot
// resolve, so the renderer leaves out a row carrying one. Every refused value
// below was refused by `nft -c` (nftables 1.1.6) with that word missing from
// /etc/services ("Could not resolve service", "Service out of range", "Range
// negative size"); every accepted one loaded.
//
// Mutation: make PortUnresolvable return "" — every bad value accepted, red.
func TestPortUnresolvable(t *testing.T) {
	defer SetServicesForTest(testServices)()
	for _, v := range []string{"", "22", "ssh", "SSH", "www", "netbios-ns", "{ ssh, http }", "22-ssh", "ssh - http",
		"!= ssh", "& 0xff00 == 0x1600", "& ssh == 0x16", "026", "0000022", "00000000022", "08", "019", "0xffff",
		"0x00000016", "65535", "010-9", "{ 08, 22 }", "{ 80, 443, }", "eq\tssh"} {
		if why := PortUnresolvable("tcp", v); why != "" {
			t.Errorf("tcp port %q refused: %s", v, why)
		}
	}
	for _, v := range []string{"bogus", "{ ssh, bogus }", "ssh-http", "22-bogus", "bogus - 22", "!= bogus",
		"& bogus == 0x16", "70000", "0x10000", "99999999999999999999", "9-010", "9 - 010", "{ 9-010 }",
		"http - ssh", "1.5", "0x"} {
		if why := PortUnresolvable("udp", v); why == "" {
			t.Errorf("udp port %q accepted", v)
		}
	}
	if why := PortUnresolvable("esp", "bogus"); why != "" {
		t.Errorf("an esp rule's port is never written: %s", why)
	}
}

// TestPort_RefusesWhatNftCannotResolve: the write grammar refuses a port nft
// cannot resolve on this host, and reads a leading-zero port as nft does.
//
// Mutation: drop the PortUnresolvable check from Port — red.
func TestPort_RefusesWhatNftCannotResolve(t *testing.T) {
	defer SetServicesForTest(testServices)()
	for _, v := range []string{"bogus", "{ ssh, bogus }", "ssh-http", "22-bogus", "9-010", "http - ssh"} {
		if err := Port("tcp", v); err == nil {
			t.Errorf("Port(%q) accepted", v)
		} else if !strings.Contains(err.Error(), "port") {
			t.Errorf("Port(%q): %v does not name the field", v, err)
		}
	}
	for _, v := range []string{"ssh", "SSH", "22-ssh", "010-9", "{ ssh, http }"} {
		if err := Port("tcp", v); err != nil {
			t.Errorf("Port(%q): %v", v, err)
		}
	}
}

// TestParseServices_ReadsTheFile: the services database PortUnresolvable
// resolves against holds a name or an alias under any protocol, matched
// exactly; comments ignored; no file resolves nothing.
func TestParseServices_ReadsTheFile(t *testing.T) {
	// rtmp is listed for ddp only, which getaddrinfo does not try: nft
	// refuses `tcp dport rtmp` (review I-4). amqp is sctp only, which it does.
	got := parseServices([]byte("# comment ssh 22/tcp\nssh\t\t22/tcp\t\t\t# SSH\nhttp 80/tcp www # web\nbootps 67/udp\nbroken\nx 99999/tcp\n" +
		"rtmp 1/ddp\namqp 5672/sctp\nd 9/dccp\nl 10/udplite\n"))
	want := map[string]uint64{"ssh": 22, "http": 80, "www": 80, "bootps": 67, "amqp": 5672, "d": 9, "l": 10}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d", k, got[k], v)
		}
	}
	d := &nameDB{path: t.TempDir() + "/missing", parse: parseServices}
	if _, ok := d.lookup("ssh"); ok {
		t.Error("a missing services file resolved ssh")
	}
}

// TestProtoUnresolvable (set-freeze review I-2): nft resolves a protocol name
// with its own parser (tcp, esp, gre, ...: they load with /etc/protocols
// emptied) or getprotobyname, case-sensitively, and a number with strtoumax
// base 0. Refused values fail `nft -c` on 1.0.9 and 1.1.6: "Could not resolve
// protocol name", "Protocol out of range", "Range negative size".
//
// Mutation: make ProtoUnresolvable return "" — red; drop nftProtoNames —
// esp is refused, red.
func TestProtoUnresolvable(t *testing.T) {
	defer SetProtocolsForTest(map[string]uint64{"ospf": 89, "IPSEC-ESP": 50, "ipv6-icmp": 58})()
	for _, v := range []string{"", "tcp", "esp", "gre", "ah", "sctp", "ESP", "ospf", "47", "0x6", "0377", "017", "{ tcp, udp }",
		"!= esp", "6-17", "& 0xf == 6", "< 6", "gt esp", "{ ospf, 47 }"} {
		if why := ProtoUnresolvable(strings.ToLower(v)); why != "" {
			t.Errorf("proto %q refused: %s", v, why)
		}
	}
	for _, v := range []string{"bogus", "mptcp", "ipsec-esp", "ip-encap", "{ esp, bogus }", "256", "0400", "08", "17-6", "!= bogus"} {
		if why := ProtoUnresolvable(v); why == "" {
			t.Errorf("proto %q accepted", v)
		}
	}
	if err := Proto("bogus"); err == nil || !strings.Contains(err.Error(), "protocols") {
		t.Errorf("Proto(bogus) = %v, want a refusal naming the protocols database", err)
	}
	if err := Proto("OSPF"); err != nil {
		t.Errorf("Proto(OSPF): %v", err)
	}
}

// TestRelationalMisuse (set-freeze review I-3): nft refuses an ordering
// operator in front of a set, a range or a prefix ("Relational expression (<)
// is undefined for set/range/prefix expressions"), and the whole ruleset with
// it; a single value takes one.
//
// Mutation: make RelationalMisuse return "" — red.
func TestRelationalMisuse(t *testing.T) {
	defer SetServicesForTest(testServices)()
	bad := map[string][]string{
		"port":  {"< { 80, 443 }", "lt { 22 }", "< 20-30", "> 20 - 30", ">= { ssh }", "& 0xff00 < { 1 }"},
		"cidr":  {"< 10.0.0.0/8", "< 10.0.0.1-10.0.0.5", "< 10.0.0.1 - 10.0.0.5", "> { 10.0.0.1 }", "< 10.0.0.1/32", "le 10.0.0.0/0"},
		"proto": {"< { 6, 17 }", "< 6-17", "ge { tcp }"},
	}
	good := map[string][]string{
		"port":  {"< 1024", "<= ssh", ">= 0x16", "gt 22", "< netbios-ns", "!= { 80, 443 }", "& 0xff00 < 0x1600", "20-30", "== 20-30"},
		"cidr":  {"< 10.0.0.1", "ge 10.0.0.1", "& 255.0.0.0 < 10.0.0.0", "!= { 10.0.0.1, 10.0.0.2 }", "!= 10.0.0.0/8", "10.0.0.1-10.0.0.5", "< @x"},
		"proto": {"< 6", "< tcp", "gt esp", "!= { 6, 17 }"},
	}
	for f, vs := range bad {
		for _, v := range vs {
			if RelationalMisuse(f, v) == "" {
				t.Errorf("%s %q accepted", f, v)
			}
		}
	}
	for f, vs := range good {
		for _, v := range vs {
			if why := RelationalMisuse(f, v); why != "" {
				t.Errorf("%s %q refused: %s", f, v, why)
			}
		}
	}
	for _, err := range []error{Port("tcp", "< { 80, 443 }"), CIDR("< 10.0.0.0/8"), Proto("< { 6, 17 }")} {
		if err == nil {
			t.Error("a writer accepted an ordering operator before a list or prefix")
		}
	}
}

// TestCIDRUnloadable (set-freeze review m-2): what nft refuses in an IPv4
// cidr or set element that can be judged without the network — "Range
// negative size", "Prefix length 33 is invalid", "Could not resolve
// hostname" for an octet past 255. Words nft reads some other way (010.0.0.1,
// 10/8, 0x0a000001, 10.0.0.1/032) and DNS names are left to it.
//
// Mutation: make v4ValueUnloadable return "" — red.
func TestCIDRUnloadable(t *testing.T) {
	for _, v := range []string{"10.0.0.5-10.0.0.1", "10.0.0.5 - 10.0.0.1", "10.0.0.0/33", "10.0.0.256", "256.0.0.0/8",
		"10.0.0.1-10.0.0.256", "{ 10.0.0.1, 10.0.0.0/40 }", "!= 10.0.0.256", "& 255.0.0.256 == 10.0.0.0"} {
		if CIDRUnloadable(v) == "" {
			t.Errorf("cidr %q accepted", v)
		}
	}
	for _, v := range []string{"", "10.0.0.1", "10.0.0.0/8", "010.0.0.1", "10/8", "1.2.3.4/0", "10.0.0.1/032", "0x0a000001",
		"167772161", "gw.example.com", "@x", "fd00::/8", "10.0.0.1-10.0.0.5", "{ 10.0.0.1, 10.0.0.2 }"} {
		if why := CIDRUnloadable(v); why != "" {
			t.Errorf("cidr %q refused: %s", v, why)
		}
	}
	if SetElementUnloadable("10.0.0.1, 10.0.0.5-10.0.0.1") == "" || SetElementUnloadable("10.0.0.1,fd00::1") != "" {
		t.Error("SetElementUnloadable judges each comma-separated piece")
	}
}
