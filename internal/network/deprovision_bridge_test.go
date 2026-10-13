package network

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// `lv network rm` of a bridge network litevirt created (`--type bridge` with no
// --interface, or a compose network) tore down its dnsmasq, gateway address
// and NAT, and left the Linux bridge itself on EVERY host: Deprovision skipped
// the delete for every bridge, because it could not tell its own bridge from an
// operator's infrastructure bridge. The lab removed dozens by hand, on the
// deleting node and on every peer (the peers' network reconciler calls the
// same Deprovision on the tombstone).
//
// EnsureBridge now records the bridges it created, and Deprovision removes a
// bridge only when that record says litevirt made it, nothing is plugged into
// it, it carries no address, and no live network still names it. An operator's
// bridge — one litevirt found already there — is never removed.
func TestDeprovision_RemovesOnlyTheBridgeLitevirtCreated(t *testing.T) {
	type env struct {
		db      *corrosion.Client
		deleted func() []string
		sys     string
	}
	setup := func(t *testing.T, ipLinkAddOut string) env {
		t.Helper()
		sys := t.TempDir()
		origSys, origDir, origAddrs := sysClassNet, createdBridgeDir, interfaceAddrs
		sysClassNet = sys
		createdBridgeDir = filepath.Join(t.TempDir(), "bridges")
		interfaceAddrs = func(string) ([]net.Addr, error) { return nil, nil }
		var dels []string
		execCommand = func(name string, args ...string) ([]byte, error) {
			if name == "ip" && len(args) >= 3 && args[0] == "link" && args[1] == "add" && ipLinkAddOut != "" {
				return []byte(ipLinkAddOut), errors.New("exit status 2")
			}
			if name == "ip" && len(args) == 3 && args[0] == "link" && args[1] == "del" {
				dels = append(dels, args[2])
			}
			return nil, nil
		}
		t.Cleanup(func() {
			sysClassNet, createdBridgeDir, interfaceAddrs = origSys, origDir, origAddrs
			execCommand = defaultExec
		})
		db := corrosion.NewTestClientT(t)
		if err := corrosion.InitSchema(context.Background(), db); err != nil {
			t.Fatalf("InitSchema: %v", err)
		}
		return env{db: db, deleted: func() []string { return dels }, sys: sys}
	}
	// The bridge as sysfs shows it once EnsureBridge made it.
	mkBridge := func(t *testing.T, e env, name string, ports ...string) {
		t.Helper()
		for _, d := range []string{"bridge", "brif"} {
			if err := os.MkdirAll(filepath.Join(e.sys, name, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		for _, p := range ports {
			if err := os.WriteFile(filepath.Join(e.sys, name, "brif", p), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A name no test host carries, so EnsureBridge takes its create path.
	const br = "lvtnetrm0"
	def := compose.NetworkDef{Type: "bridge", Interface: br, Subnet: "10.66.0.0/24"}
	ctx := context.Background()

	t.Run("created by litevirt and unused: removed", func(t *testing.T) {
		e := setup(t, "")
		if err := EnsureBridge(br); err != nil {
			t.Fatal(err)
		}
		mkBridge(t, e, br)
		if err := Deprovision(ctx, e.db, "nr", def, "h"); err != nil {
			t.Fatalf("Deprovision: %v", err)
		}
		if got := strings.Join(e.deleted(), ","); got != br {
			t.Fatalf("ip link del issued for %q, want %q: the bridge litevirt created outlives its network", got, br)
		}
		if _, err := os.Stat(filepath.Join(createdBridgeDir, br)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the created-bridge record for %s survived the bridge's removal (stat err %v)", br, err)
		}
	})

	t.Run("an operator's bridge litevirt found already there: kept", func(t *testing.T) {
		e := setup(t, "RTNETLINK answers: File exists")
		if err := EnsureBridge(br); err != nil {
			t.Fatal(err)
		}
		mkBridge(t, e, br)
		if err := Deprovision(ctx, e.db, "nr", def, "h"); err != nil {
			t.Fatalf("Deprovision: %v", err)
		}
		if got := e.deleted(); len(got) != 0 {
			t.Fatalf("ip link del issued for %v: a bridge litevirt did not create was removed", got)
		}
	})

	t.Run("a port still on it: kept, and still removable later", func(t *testing.T) {
		e := setup(t, "")
		if err := EnsureBridge(br); err != nil {
			t.Fatal(err)
		}
		mkBridge(t, e, br, "vnet0")
		if err := Deprovision(ctx, e.db, "nr", def, "h"); err != nil {
			t.Fatalf("Deprovision: %v", err)
		}
		if got := e.deleted(); len(got) != 0 {
			t.Fatalf("ip link del issued for %v while a port is on the bridge", got)
		}
		if _, err := os.Stat(filepath.Join(createdBridgeDir, br)); err != nil {
			t.Errorf("the created-bridge record was dropped while the bridge stayed: %v", err)
		}
	})

	t.Run("a live network still names it: kept", func(t *testing.T) {
		e := setup(t, "")
		if err := EnsureBridge(br); err != nil {
			t.Fatal(err)
		}
		mkBridge(t, e, br)
		if err := corrosion.UpsertNetwork(ctx, e.db, corrosion.NetworkRecord{
			Name: "sibling", Type: "bridge", Config: `{"interface":"` + br + `"}`,
		}); err != nil {
			t.Fatal(err)
		}
		if err := Deprovision(ctx, e.db, "nr", def, "h"); err != nil {
			t.Fatalf("Deprovision: %v", err)
		}
		if got := e.deleted(); len(got) != 0 {
			t.Fatalf("ip link del issued for %v while live network sibling uses the bridge", got)
		}
	})

	t.Run("the deleted network's own row may still be live: removed", func(t *testing.T) {
		// DeleteNetwork deprovisions BEFORE it soft-deletes the row, so the
		// network being torn down still reads as live; it must not count.
		e := setup(t, "")
		if err := EnsureBridge(br); err != nil {
			t.Fatal(err)
		}
		mkBridge(t, e, br)
		if err := corrosion.UpsertNetwork(ctx, e.db, corrosion.NetworkRecord{
			Name: "nr", Type: "bridge", Config: `{"interface":"` + br + `","subnet":"10.66.0.0/24"}`,
		}); err != nil {
			t.Fatal(err)
		}
		if err := Deprovision(ctx, e.db, "nr", def, "h"); err != nil {
			t.Fatalf("Deprovision: %v", err)
		}
		if got := strings.Join(e.deleted(), ","); got != br {
			t.Fatalf("ip link del issued for %q, want %q", got, br)
		}
	})
}
