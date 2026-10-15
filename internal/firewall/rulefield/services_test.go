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

// TestKnownService_ReadsTheFile: a name or an alias under any protocol, matched
// exactly; comments ignored; no file resolves nothing.
func TestKnownService_ReadsTheFile(t *testing.T) {
	got := parseServices([]byte("# comment ssh 22/tcp\nssh\t\t22/tcp\t\t\t# SSH\nhttp 80/tcp www # web\nbootps 67/udp\nbroken\nx 99999/tcp\n"))
	want := map[string]uint64{"ssh": 22, "http": 80, "www": 80, "bootps": 67}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d", k, got[k], v)
		}
	}
	d := &serviceDB{path: t.TempDir() + "/missing"}
	if _, ok := d.lookup("ssh"); ok {
		t.Error("a missing services file resolved ssh")
	}
}
