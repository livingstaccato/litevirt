package network

import (
	"errors"
	"os"
	"reflect"
	"testing"
)

// TestAddDHCPHost_NoServerIsAnError (re-review I-8): a reservation made where
// no litevirt dnsmasq serves the bridge reserves nothing, so it must not
// report success: the guest would take a dynamic address its exact guard then
// drops.
func TestAddDHCPHost_NoServerIsAnError(t *testing.T) {
	old := dnsmasqLeaseDir
	dnsmasqLeaseDir = t.TempDir()
	defer func() { dnsmasqLeaseDir = old }()
	err := AddDHCPHost("lvbr-none", "52:54:00:00:00:01", "10.9.0.5")
	if !errors.Is(err, ErrNoLocalDHCPServer) {
		t.Fatalf("AddDHCPHost with no hosts file = %v, want ErrNoLocalDHCPServer", err)
	}
}

// TestDHCPHosts_NoRouterLines: the hosts file carries a NIC's lv-norouter tag
// beside its reservation, or alone, in dnsmasq's dhcp-host syntax, and reads
// back what it wrote.
func TestDHCPHosts_NoRouterLines(t *testing.T) {
	old := dnsmasqLeaseDir
	dnsmasqLeaseDir = t.TempDir()
	defer func() { dnsmasqLeaseDir = old }()
	path := DHCPHostsFile("lvbr-nr")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	hosts := map[string]DHCPHost{
		"52:54:00:00:00:01": {IP: "10.9.0.5"},
		"52:54:00:00:00:02": {NoRouter: true},
		"52:54:00:00:00:03": {IP: "10.9.0.6", NoRouter: true},
	}
	if _, err := SyncDHCPHosts("lvbr-nr", hosts); err != nil {
		t.Fatalf("SyncDHCPHosts: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "52:54:00:00:00:01,10.9.0.5\n52:54:00:00:00:02,set:lv-norouter\n52:54:00:00:00:03,set:lv-norouter,10.9.0.6\n"
	if string(got) != want {
		t.Errorf("hosts file =\n%s\nwant\n%s", got, want)
	}
	if back := parseDHCPHosts(got); !reflect.DeepEqual(back, hosts) {
		t.Errorf("parse(render) = %v, want %v", back, hosts)
	}
}

// TestAddDHCPHost_KeepsTheNoRouterTag: a reservation made for a NIC the file
// already tags keeps the tag, and a stale reservation it takes the address
// from keeps its own tag — a reservation never gives a NIC its router back.
func TestAddDHCPHost_KeepsTheNoRouterTag(t *testing.T) {
	old := dnsmasqLeaseDir
	dnsmasqLeaseDir = t.TempDir()
	defer func() { dnsmasqLeaseDir = old }()
	path := DHCPHostsFile("lvbr-nr2")
	if err := os.WriteFile(path, []byte("52:54:00:00:00:01,set:lv-norouter\n52:54:00:00:00:02,set:lv-norouter,10.9.0.7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := AddDHCPHost("lvbr-nr2", "52:54:00:00:00:01", "10.9.0.7"); err != nil {
		t.Fatalf("AddDHCPHost: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "52:54:00:00:00:01,set:lv-norouter,10.9.0.7\n52:54:00:00:00:02,set:lv-norouter\n"; string(got) != want {
		t.Errorf("hosts file =\n%s\nwant\n%s", got, want)
	}
}
