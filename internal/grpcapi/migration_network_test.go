package grpcapi

import (
	"context"
	"net"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestParseMigrationNetwork(t *testing.T) {
	for _, ok := range []string{"10.20.0.0/24", "192.168.5.7/16", "10.0.0.0/8"} {
		if _, err := ParseMigrationNetwork(ok); err != nil {
			t.Errorf("ParseMigrationNetwork(%q) = %v, want accepted", ok, err)
		}
	}
	for bad, why := range map[string]string{
		"10.20.0.1":    "not a CIDR",
		"fd00::/64":    "IPv6",
		"0.0.0.0/0":    "whole address space",
		"not-a-cidr":   "garbage",
		"10.20.0.0/33": "bad prefix",
	} {
		if _, err := ParseMigrationNetwork(bad); err == nil {
			t.Errorf("ParseMigrationNetwork(%q) accepted (%s)", bad, why)
		}
	}
}

func TestLocalAddressIn(t *testing.T) {
	s := testServer(t)
	s.SetLocalIPsForTest(func() ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.1.5"), net.ParseIP("10.20.0.9"), net.ParseIP("10.20.0.3"), net.ParseIP("fd00::5")}, nil
	})
	if got := s.localAddressIn("10.20.0.0/24"); got != "10.20.0.3" {
		t.Errorf("localAddressIn = %q, want the lowest address in the network, 10.20.0.3", got)
	}
	if got := s.localAddressIn("10.99.0.0/24"); got != "" {
		t.Errorf("localAddressIn for a network the host is not in = %q, want empty", got)
	}
	if got := s.localAddressIn("127.0.0.0/8"); got != "" {
		t.Errorf("a loopback address was offered as a migration address: %q", got)
	}
	if got := s.localAddressIn("garbage"); got != "" {
		t.Errorf("an invalid network answered %q", got)
	}
}

func TestEnsureDisksAnswersWithItsAddressInTheAskedNetwork(t *testing.T) {
	s := testServer(t)
	s.SetLocalIPsForTest(func() ([]net.IP, error) { return []net.IP{net.ParseIP("10.20.0.3")}, nil })
	resp := &pb.EnsureDisksResponse{}
	s.answerMigrationNetwork(&pb.EnsureDisksRequest{MigrationNetwork: "10.20.0.0/24"}, resp)
	if resp.MigrationAddress != "10.20.0.3" {
		t.Fatalf("migration_address = %q, want 10.20.0.3", resp.MigrationAddress)
	}
	resp = &pb.EnsureDisksResponse{}
	s.answerMigrationNetwork(&pb.EnsureDisksRequest{}, resp)
	if resp.MigrationAddress != "" {
		t.Fatalf("answered %q although no network was asked for", resp.MigrationAddress)
	}
}

func TestChooseMigrationRoute(t *testing.T) {
	target := corrosion.HostRecord{Name: "h2", Address: "192.168.1.2"}
	cases := []struct {
		name        string
		network     string
		migAddr     string
		withStorage bool
		bothTLS     bool
		wantAddr    string
		wantDirect  bool
		wantWarn    bool
		wantWhy     string // a phrase of the warning, when one is wanted
	}{
		{"unset", "", "", false, true, "192.168.1.2", false, false, ""},
		{"unset ignores an answer", "", "10.20.0.2", true, true, "192.168.1.2", false, false, ""},
		{"storage uses the address", "10.20.0.0/24", "10.20.0.2", true, true, "10.20.0.2", false, false, ""},
		{"storage uses it even in plaintext", "10.20.0.0/24", "10.20.0.2", true, false, "10.20.0.2", false, false, ""},
		{"memory with TLS leaves the tunnel", "10.20.0.0/24", "10.20.0.2", false, true, "10.20.0.2", true, false, ""},
		{"memory without TLS stays tunnelled", "10.20.0.0/24", "10.20.0.2", false, false, "192.168.1.2", false, true, ""},
		{"no answer", "10.20.0.0/24", "", true, true, "192.168.1.2", false, true, "reported no address"},
		{"answer outside the network", "10.20.0.0/24", "172.16.0.2", true, true, "192.168.1.2", false, true, ""},
		{"loopback answer", "10.20.0.0/24", "127.0.0.1", true, true, "192.168.1.2", false, true, ""},
		{"garbage answer", "10.20.0.0/24", "evil.example", true, true, "192.168.1.2", false, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := testServer(t)
			s.migrationNetwork = c.network
			got := s.chooseMigrationRoute(context.Background(), "vm1", target, c.migAddr, c.withStorage, c.bothTLS)
			if got.addr != c.wantAddr || got.direct != c.wantDirect {
				t.Errorf("route = %+v, want addr %s direct %v", got, c.wantAddr, c.wantDirect)
			}
			evs, _ := corrosion.ListVMEvents(context.Background(), s.db, "vm1", 10, "")
			warned := false
			for _, e := range evs {
				if e.Type == "vm.migrate.network_fallback" {
					warned = true
					if c.wantWhy != "" && !strings.Contains(e.Detail, c.wantWhy) {
						t.Errorf("the warning = %q, want it to say %q", e.Detail, c.wantWhy)
					}
					if !strings.Contains(e.Detail, "192.168.1.2") {
						t.Errorf("the warning does not name the address used: %q", e.Detail)
					}
				}
			}
			if warned != c.wantWarn {
				t.Errorf("warning recorded = %v, want %v", warned, c.wantWarn)
			}
		})
	}
}
