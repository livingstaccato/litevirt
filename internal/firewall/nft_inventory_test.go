package firewall

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise NftBinary itself using an exact-argv private executable. It never
// invokes host nft or mutates the host network; unknown commands fail closed.
func inventoryNft(t *testing.T) (NftBinary, func(string, string), func() string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	script := `#!/bin/sh
set -eu
d=${0%/*}
printf '%s\n' "$*" >> "$d/commands"
case "$*" in
 "-f -") cat > "$d/applied"; exit 0;;
 "list table bridge litevirt-nic"|"-j list tables")
  if [ "$(cat "$d/fault")" = inventory ]; then echo 'injected inventory permission failure' >&2; exit 1; fi
  cat "$d/inventory"; exit 0;;
 "delete table bridge litevirt-nic")
  if [ "$(cat "$d/fault")" = delete ]; then echo 'injected delete refusal' >&2; exit 1; fi
  printf '{"nftables":[]}\n' > "$d/inventory"; exit 0;;
 *) echo "unknown command: $*" >&2; exit 97;;
esac
`
	bin := filepath.Join(dir, "nft")
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	set := func(fault, inventory string) { write("fault", fault); write("inventory", inventory) }
	set("", `{"nftables":[{"table":{"family":"bridge","name":"litevirt-nic"}}]}`)
	read := func() string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, "applied"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	return NftBinary{Bin: bin}, set, read
}

func TestNftBinary_UnconfirmedRemovalKeepsGuestVRRPDrop(t *testing.T) {
	for _, state := range []string{"established", "reset", "new-daemon"} {
		for _, failure := range []string{"inventory", "malformed-inventory", "missing-inventory", "null-inventory", "unknown-entry", "malformed-table", "malformed-meta", "delete"} {
			t.Run(state+"/"+failure, func(t *testing.T) {
				n, set, applied := inventoryNft(t)
				a := NewApplier(n)
				if _, err := a.Apply(context.Background(), sgPlan(NICModeEnforce, true)); err != nil {
					t.Fatal(err)
				}
				if state == "reset" {
					a.Reset()
				}
				if state == "new-daemon" {
					a = NewApplier(n)
				}
				inventory := `{"nftables":[{"table":{"family":"bridge","name":"litevirt-nic"}}]}`
				switch failure {
				case "malformed-inventory":
					inventory = "{"
				case "missing-inventory":
					inventory = `{}`
				case "null-inventory":
					inventory = `{"nftables":null}`
				case "unknown-entry":
					inventory = `{"nftables":[{"error":"refused"}]}`
				case "malformed-table":
					inventory = `{"nftables":[{"table":{"family":"bridge"}}]}`
				case "malformed-meta":
					inventory = `{"nftables":[{"metainfo":null}]}`
				}
				set(failure, inventory)
				_, err := a.Apply(context.Background(), Plan{})
				if err == nil {
					t.Error("unconfirmed removal reported success")
				}
				rules := applied()
				drop := fmt.Sprintf("meta mark & %#x == %#x meta l4proto 112 drop", guestVRRPMark, guestVRRPMark)
				if !strings.Contains(rules, drop) {
					t.Error("unconfirmed bridge removal discarded actual inet guest VRRP protection")
				}
				if strings.Contains(rules, fmt.Sprintf("meta mark & %#x == %#x accept", judgedMark, judgedMark)) {
					t.Error("unconfirmed removal trusted stale positive allows")
				}
				set("", `{"nftables":[]}`)
				if _, err := a.Apply(context.Background(), Plan{}); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(applied(), drop) {
					t.Error("confirmed absence retained guest VRRP protection")
				}
			})
		}
	}
}

func TestNftBinary_ConfirmedRemovalClearsGuestVRRPDrop(t *testing.T) {
	for _, inventory := range []string{`{"nftables":[]}`, `{"nftables":[{"table":{"family":"bridge","name":"litevirt-nic"}}]}`, `{"nftables":[{"metainfo":{"json_schema_version":1}},{"table":{"family":"inet","name":"unrelated"}}]}`} {
		t.Run(inventory, func(t *testing.T) {
			n, set, applied := inventoryNft(t)
			a := NewApplier(n)
			if _, err := a.Apply(context.Background(), sgPlan(NICModeEnforce, true)); err != nil {
				t.Fatal(err)
			}
			set("", inventory)
			if _, err := a.Apply(context.Background(), Plan{}); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(applied(), "chain guest_vrrp") {
				t.Fatal("confirmed removal retained guest drop")
			}
			commands, err := os.ReadFile(filepath.Join(filepath.Dir(n.Bin), "commands"))
			if err != nil {
				t.Fatal(err)
			}
			deleted := strings.Count(string(commands), "delete table bridge litevirt-nic\n")
			want := 0
			if strings.Contains(inventory, `"family":"bridge","name":"litevirt-nic"`) {
				want = 1
			}
			if deleted != want {
				t.Fatalf("exact confirmed-table delete count=%d want=%d", deleted, want)
			}
		})
	}
}
