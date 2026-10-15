package corrosion

import (
	"context"
	"errors"
	"testing"

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
