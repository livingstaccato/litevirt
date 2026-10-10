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
	ctx := context.Background()
	if got := s.localAddressIn(ctx, "10.20.0.0/24"); got != "10.20.0.3" {
		t.Errorf("localAddressIn = %q, want the lowest address in the network, 10.20.0.3", got)
	}
	if got := s.localAddressIn(ctx, "10.99.0.0/24"); got != "" {
		t.Errorf("localAddressIn for a network the host is not in = %q, want empty", got)
	}
	if got := s.localAddressIn(ctx, "127.0.0.0/8"); got != "" {
		t.Errorf("a loopback address was offered as a migration address: %q", got)
	}
	if got := s.localAddressIn(ctx, "garbage"); got != "" {
		t.Errorf("an invalid network answered %q", got)
	}
}

// What a host must not answer as its migration address: link-local, a
// load-balancer VIP, an address on a bridge litevirt made or a virtual
// interface. migration.address, inside the network, is taken as given.
//
// Mutation: drop the VIP, bridge, interface-prefix or link-local exclusion in
// localAddressIn - the matching row answers the floating address.
func TestLocalAddressIn_NeverAFloatingAddress(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "lan2", Type: "isolated", Config: "{}"}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `INSERT INTO lb_configs (name, stack_name, vip, algorithm, hosts, ports, enabled, updated_at)
		VALUES ('lb', '', '10.20.0.1', 'rr', '', '[]', 1, ?)`, s.db.NowTS()); err != nil {
		t.Fatalf("seed a load balancer: %v", err)
	}
	s.SetLocalAddrsForTest(func() ([]localAddr, error) {
		return []localAddr{
			{net.ParseIP("10.20.0.1"), "eth1"},        // an LB VIP
			{net.ParseIP("10.20.0.2"), "br-iso-lan2"}, // litevirt's bridge for network lan2
			{net.ParseIP("10.20.0.3"), "virbr0"},      // libvirt's
			{net.ParseIP("10.20.0.4"), "vnet7"},       // a guest's
			{net.ParseIP("169.254.1.1"), "eth1"},      // link-local
			{net.ParseIP("10.20.0.9"), "eth1"},        // the real one
		}, nil
	})
	if got := s.localAddressIn(ctx, "10.20.0.0/16"); got != "10.20.0.9" {
		t.Errorf("answered %q, want the one real address 10.20.0.9", got)
	}
	s.SetMigrationAddress("10.20.0.77")
	if got := s.localAddressIn(ctx, "10.20.0.0/16"); got != "10.20.0.77" {
		t.Errorf("migration.address was not taken as given: %q", got)
	}
	s.SetMigrationAddress("192.168.9.9") // outside the network: ignored
	if got := s.localAddressIn(ctx, "10.20.0.0/16"); got != "10.20.0.9" {
		t.Errorf("an address outside the network was answered: %q", got)
	}
}

func TestCheckMigrationNetwork(t *testing.T) {
	mk := func(c string) *net.IPNet { n, _ := ParseMigrationNetwork(c); return n }
	cluster, route := net.ParseIP("192.168.1.5"), net.ParseIP("203.0.113.7")
	for _, c := range []struct {
		name    string
		cidr    string
		allow   bool
		wantErr string
	}{
		{"private /24", "10.20.0.0/24", false, ""},
		{"private 172.16", "172.20.4.0/22", false, ""},
		{"private 192.168 elsewhere", "192.168.50.0/24", false, ""},
		{"public", "203.0.113.0/24", false, "not inside a private range"},
		{"public wider than private", "10.0.0.0/7", false, "not inside a private range"},
		{"contains the cluster address", "192.168.0.0/16", false, "contains this host's cluster or default-route address 192.168.1.5"},
		{"contains the default route address", "10.0.0.0/8", false, ""},
		{"public with the override", "203.0.113.0/24", true, ""},
		{"cluster net with the override", "192.168.0.0/16", true, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := CheckMigrationNetwork(mk(c.cidr), c.allow, cluster, route)
			if c.wantErr == "" && err != nil || c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
				t.Fatalf("CheckMigrationNetwork(%s, allow=%v) = %v, want %q", c.cidr, c.allow, err, c.wantErr)
			}
		})
	}
	// The default-route source address inside a private range.
	if err := CheckMigrationNetwork(mk("10.20.0.0/24"), false, net.ParseIP("10.20.0.5")); err == nil {
		t.Error("a network containing the default-route source address was accepted")
	}
}

func TestEnsureDisksAnswersWithItsAddressInTheAskedNetwork(t *testing.T) {
	s := testServer(t)
	s.SetLocalIPsForTest(func() ([]net.IP, error) { return []net.IP{net.ParseIP("10.20.0.3")}, nil })
	resp := &pb.EnsureDisksResponse{}
	s.answerMigrationNetwork(context.Background(), &pb.EnsureDisksRequest{MigrationNetwork: "10.20.0.0/24"}, resp)
	if resp.MigrationAddress != "10.20.0.3" {
		t.Fatalf("migration_address = %q, want 10.20.0.3", resp.MigrationAddress)
	}
	resp = &pb.EnsureDisksResponse{}
	s.answerMigrationNetwork(context.Background(), &pb.EnsureDisksRequest{}, resp)
	if resp.MigrationAddress != "" {
		t.Fatalf("answered %q although no network was asked for", resp.MigrationAddress)
	}
}

func TestChooseMigrationRoute(t *testing.T) {
	target := corrosion.HostRecord{Name: "h2", Address: "192.168.1.2"}
	cases := []struct {
		name       string
		network    string
		migAddr    string
		kind       routeKind
		bothTLS    bool
		noSrcAddr  bool // this host has no address in the network
		wantAddr   string
		wantDirect bool
		wantWarn   bool
		wantWhy    string // a phrase of the warning, when one is wanted
	}{
		{"unset", "", "", routeMemory, true, false, "192.168.1.2", false, false, ""},
		{"unset ignores an answer", "", "10.20.0.2", routeStorage, true, false, "192.168.1.2", false, false, ""},
		{"encrypted storage uses the address", "10.20.0.0/24", "10.20.0.2", routeStorage, true, false, "10.20.0.2", false, false, ""},
		{"unencrypted storage stays on the cluster address", "10.20.0.0/24", "10.20.0.2", routeStorage, false, false, "192.168.1.2", false, true, "stays on the cluster address"},
		{"cold uses the address (mTLS inherent)", "10.20.0.0/24", "10.20.0.2", routeCold, false, false, "10.20.0.2", false, false, ""},
		{"memory with TLS leaves the tunnel", "10.20.0.0/24", "10.20.0.2", routeMemory, true, false, "10.20.0.2", true, false, ""},
		{"memory without TLS stays tunnelled", "10.20.0.0/24", "10.20.0.2", routeMemory, false, false, "192.168.1.2", false, true, "plaintext"},
		{"no answer", "10.20.0.0/24", "", routeStorage, true, false, "192.168.1.2", false, true, "reported no address"},
		{"answer outside the network", "10.20.0.0/24", "172.16.0.2", routeStorage, true, false, "192.168.1.2", false, true, ""},
		{"loopback answer", "10.20.0.0/24", "127.0.0.1", routeStorage, true, false, "192.168.1.2", false, true, ""},
		{"garbage answer", "10.20.0.0/24", "evil.example", routeStorage, true, false, "192.168.1.2", false, true, ""},
		{"the source has no address in the network", "10.20.0.0/24", "10.20.0.2", routeStorage, true, true, "192.168.1.2", false, true, "has no address in that network"},
		{"the source has none, cold", "10.20.0.0/24", "10.20.0.2", routeCold, true, true, "192.168.1.2", false, true, "has no address in that network"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := testServer(t)
			s.migrationNetwork = c.network
			src := "10.20.0.50"
			if c.noSrcAddr {
				src = "172.31.0.9"
			}
			s.SetLocalIPsForTest(func() ([]net.IP, error) { return []net.IP{net.ParseIP(src)}, nil })
			got := s.chooseMigrationRoute(context.Background(), "vm1", target, c.migAddr, c.kind, c.bothTLS)
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
