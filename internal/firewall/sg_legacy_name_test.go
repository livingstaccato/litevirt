package firewall

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A rule an older client stored with the group's NAME in sg_id is rendered as
// the group's own when the name is unambiguous, and not at all when two live
// groups hold it.
func TestCorrosionPlanLoader_LegacyNameRule(t *testing.T) {
	for _, tc := range []struct {
		name      string
		second    bool
		wantRules int
	}{
		{"unambiguous", false, 1},
		{"ambiguous", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := corrosion.NewTestClientT(t)
			if err := corrosion.InitSchema(ctx, db); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "sg-1", Name: "web"}); err != nil {
				t.Fatal(err)
			}
			if tc.second {
				if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "sg-2", Name: "web", StackName: "shop"}); err != nil {
					t.Fatal(err)
				}
			}
			if err := corrosion.InsertSGRule(ctx, db, corrosion.SGRule{ID: "r1", SGID: "web",
				Direction: "ingress", Proto: "tcp", PortRange: "22", Action: "accept"}); err != nil {
				t.Fatal(err)
			}
			plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, liveTaps(nil))(ctx)
			if err != nil {
				t.Fatal(err)
			}
			got := 0
			for _, g := range plan.SecurityGroups {
				got += len(g.Rules)
			}
			if got != tc.wantRules {
				t.Errorf("rendered %d rules, want %d (%+v)", got, tc.wantRules, plan.SecurityGroups)
			}
		})
	}
}
