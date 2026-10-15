package corrosion

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/firewall/rulefield"
)

// TestFirewallWriters_RefuseUngrammaticalFields (finding F-1): the four
// writers every path reaches (gRPC, stack deploy, anything later) refuse a
// row whose fields would add nft syntax to every host's ruleset, and store
// nothing.
func TestFirewallWriters_RefuseUngrammaticalFields(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	isField := func(err error) bool {
		var fe *rulefield.FieldError
		return errors.As(err, &fe)
	}
	if err := InsertClusterFirewallRule(ctx, c, FirewallRule{ID: "c", Direction: "ingress", Proto: "tcp", PortRange: "22\nx"}); !isField(err) {
		t.Errorf("cluster rule: %v", err)
	}
	if err := InsertHostFirewallRule(ctx, c, FirewallRule{ID: "h", HostName: "a", Direction: "ingress", CIDR: "10.0.0.0/8;"}); !isField(err) {
		t.Errorf("host rule: %v", err)
	}
	if err := InsertSGRule(ctx, c, SGRule{ID: "s", SGID: "g", Direction: "ingress", Proto: "esp }"}); !isField(err) {
		t.Errorf("sg rule: %v", err)
	}
	if err := InsertIPSet(ctx, c, IPSet{ID: "i", Name: "a b", CIDRs: []string{"10.0.0.0/8"}}); !isField(err) {
		t.Errorf("ip set: %v", err)
	}
	if rows, _ := ListClusterFirewallRules(ctx, c); len(rows) != 0 {
		t.Errorf("cluster rule stored")
	}
	if rows, _ := ListHostFirewallRules(ctx, c, "a"); len(rows) != 0 {
		t.Errorf("host rule stored")
	}
	if rows, _ := ListSGRules(ctx, c, "g"); len(rows) != 0 {
		t.Errorf("sg rule stored")
	}
	if rows, _ := ListIPSets(ctx, c); len(rows) != 0 {
		t.Errorf("ip set stored")
	}
}

// TestInsertIPSet_RefusesCompanionClash (fw-grammar re-review 3 N-2): a set
// named <x>_v6 beside a set x with IPv6 elements, written in either order, or
// as a second row of x, makes every host refuse its ruleset; the writer
// refuses it and stores nothing. A set named y_v6 beside a y with no IPv6
// element is an ordinary name, as it always was.
//
// Mutation: drop the IPSetCompanionClash call from InsertIPSetWithGrant — red.
func TestInsertIPSet_RefusesCompanionClash(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	g := capabilities.GrantForTest(t, capabilities.FeatureFirewallIPv6)
	isField := func(err error) bool {
		var fe *rulefield.FieldError
		return errors.As(err, &fe)
	}
	write := func(id, name string, cidrs ...string) error {
		return InsertIPSetWithGrant(ctx, c, g, IPSet{ID: id, Name: name, CIDRs: cidrs})
	}
	if err := write("x", "x", "10.0.0.0/8", "fd00::/8"); err != nil {
		t.Fatal(err)
	}
	if err := write("xv6", "x_v6", "10.9.0.0/16"); !isField(err) {
		t.Errorf("x_v6 beside x with IPv6 elements: %v", err)
	}
	if err := write("zv6", "z_v6", "10.1.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if err := write("z", "z", "fd00::/8"); !isField(err) {
		t.Errorf("z with IPv6 elements beside z_v6: %v", err)
	}
	if err := write("z4", "z", "10.2.0.0/16"); err != nil {
		t.Errorf("z with IPv4 elements beside z_v6: %v", err)
	}
	if err := write("z6", "z", "2001:db8::/32"); !isField(err) {
		t.Errorf("a second row of z adding IPv6 elements beside z_v6: %v", err)
	}
	rows, _ := ListIPSets(ctx, c)
	if len(rows) != 3 {
		t.Errorf("stored %+v, want x, z_v6 and z (IPv4)", rows)
	}
}
