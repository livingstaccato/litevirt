//go:build linux

package firewall

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestKernelChild_TagGroupsHoldOnTheWire loads what the production loader
// renders for tag groups into a real nf_tables and pushes real traffic
// through it: a group's set with an IPv6 companion, a rule rewritten from
// tag:<name> to the set, an accept against the empty set of a missing group,
// a drop on a missing group without its address, and a NIC held at drop for
// a shared firewall identity. Then the member's tags are removed and the
// next pass lets it through.
//
// It uses only kernelTestModules, so it must pass wherever the kernel tests
// run.
func TestKernelChild_TagGroupsHoldOnTheWire(t *testing.T) {
	inNetns(t)
	l := newGuestLab(t, map[string]string{
		"ga": "10.20.0.1", // a member of web
		"gb": "10.20.0.2", // drops anything from web
		"gc": "10.20.0.3", // no member
		"ge": "10.20.0.5", // shares its firewall identity: held at drop
	})
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	row := func(sql string, args ...any) {
		t.Helper()
		if err := db.Execute(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	row(`INSERT INTO networks (name, type, config, created_at, updated_at) VALUES ('lan', 'bridge', '{"Subnet":"10.20.0.0/24"}', 't', 't')`)
	row(`INSERT INTO networks (name, type, config, created_at, updated_at) VALUES ('lan6', 'bridge', '{"Subnet":"fd00:20::/64"}', 't', 't')`)
	running := map[string]map[string]string{}
	vm := func(name, fwID, mac, ip string, sgs string) {
		spec := `{"name":"` + name + `"`
		if fwID != "" {
			spec += `,"firewall_id":"` + fwID + `"`
		}
		row(`INSERT INTO vms (name, host_name, spec, state, created_at, updated_at) VALUES (?, 'host-a', ?, 'running', 't', 't')`, name, spec+"}")
		row(`INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, ip, tap_device, security_groups, updated_at)
			VALUES (?, 'lan', 0, ?, ?, ?, ?, 't')`, name, mac, ip, "p"+name, sgs)
		row(`INSERT INTO ip_allocations (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
			VALUES ('lan', ?, ?, ?, 'vm', '', 't', 't')`, ip, mac, name)
		running[name] = map[string]string{mac: "p" + name}
	}
	idWeb, idShared := "0000000000000000000000000000000a", "0000000000000000000000000000000b"
	vm("ga", idWeb, "52:54:00:20:00:01", "10.20.0.1", `[]`)
	vm("gb", "", "52:54:00:20:00:02", "10.20.0.2", `["no-web"]`)
	vm("gc", "", "52:54:00:20:00:03", "10.20.0.3", `[]`)
	vm("ge", idShared, "52:54:00:20:00:05", "10.20.0.5", `[]`)
	// ga's second NIC holds an IPv6 lease: the set gets its _v6 companion.
	row(`INSERT INTO vm_nics (vm_name, id, network_name, mac, ordinal, ip, updated_at) VALUES ('ga', 'n6', 'lan6', '52:54:00:20:00:61', 1, '', 't')`)
	row(`INSERT INTO ip_allocations (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
		VALUES ('lan6', 'fd00:20::1', '52:54:00:20:00:61', 'ga', 'vm', '', 't', 't')`)
	// ge's identity is held by another live VM too (a copy).
	row(`INSERT INTO vms (name, host_name, spec, state, created_at, updated_at) VALUES ('gz', 'host-b', ?, 'running', 't', 't')`,
		`{"name":"gz","firewall_id":"`+idShared+`"}`)
	policy := func(key, value string) {
		row(`INSERT INTO cluster_policies (key, value, set_by, updated_at) VALUES (?, ?, 'test', ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`, key, value, time.Now().UTC().Format(time.RFC3339Nano))
	}
	policy(corrosion.FirewallTagGroupKeyPrefix+"web", `{"match":{"role":"web"},"networks":[],"security_groups":[]}`)
	policy(corrosion.FirewallTagsKeyPrefix+"vm/"+idWeb, `{"tags":{"role":"web"},"name":"ga"}`)
	row(`INSERT INTO security_groups (id, name, created_at, updated_at) VALUES ('sg-1', 'no-web', 't', 't')`)
	row(`INSERT INTO sg_rules (id, sg_id, direction, proto, port_range, cidr, action, created_at, updated_at)
		VALUES ('r1', 'sg-1', 'ingress', 'all', '', 'tag:web', 'drop', 't', 't')`)
	cluster := func(id, proto, port, cidr, action string) {
		row(`INSERT INTO cluster_firewall_rules (id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
			VALUES (?, 'ingress', ?, ?, ?, ?, 100, '', '', 't', 't')`, id, proto, port, cidr, action)
	}
	cluster("c-gone-drop", "udp", "9", "tag:gone", "drop")
	cluster("c-gone-acc", "tcp", "9", "tag:gone2", "accept")

	loader := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{
		RunningTaps: func() (map[string]map[string]string, error) { return running, nil },
		TapBridge:   func(string) string { return "gwbr0" },
	})
	apply := func() Plan {
		t.Helper()
		plan, err := loader(ctx)
		if err != nil {
			t.Fatalf("loader: %v", err)
		}
		plan.NICMode = NICModeEnforce
		a := NewApplier(NftBinary{})
		if _, err := a.Apply(ctx, plan); err != nil {
			t.Fatalf("a real nft refused the tag-group ruleset: %v", err)
		}
		return plan
	}
	plan := apply()
	if len(plan.TagGroups.SharedIdentity) != 1 || len(plan.InvalidRows) != 0 {
		t.Fatalf("premise: report %+v, invalid rows %+v", plan.TagGroups, plan.InvalidRows)
	}
	listed := sh(t, "nft", "list", "table", "bridge", NICTableName)
	for _, want := range []string{"set lv_tg_web ", "set lv_tg_web_v6 ", "set lv_tg_gone2 ", "10.20.0.1", "fd00:20::1"} {
		if !strings.Contains(listed, want) {
			t.Errorf("the loaded bridge table lacks %q:\n%s", want, listed)
		}
	}
	for _, c := range []struct {
		name     string
		from, to string
		want     bool
	}{
		{"a member, into a NIC that drops the group", "ga", "10.20.0.2", false},
		{"no member, into that NIC", "gc", "10.20.0.2", true},
		{"into a NIC held for a shared identity", "gc", "10.20.0.5", false},
		{"a member, elsewhere", "ga", "10.20.0.3", true},
	} {
		if got := l.ping(c.from, c.to); got != c.want {
			t.Errorf("%s (%s -> %s): reached=%v, want %v", c.name, c.from, c.to, got, c.want)
		}
	}

	// The member's tags are removed: the next pass drops it from the set.
	policy(corrosion.FirewallTagsKeyPrefix+"vm/"+idWeb, "")
	apply()
	if !l.ping("ga", "10.20.0.2") {
		t.Error("a former member is still dropped after its tags were removed")
	}
	if t.Failed() {
		t.Logf("ruleset:\n%s", sh(t, "nft", "list", "ruleset"))
	}
}
