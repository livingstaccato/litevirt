package firewall

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A NIC is rendered with the global groups and its own project's, never
// another project's — even when its binding names one, as a binding made
// before another project created a group of that name does
// (docs/design/security-group-projects.md). The VM and the container are in
// acme; "b-web" belongs to other.
func TestCorrosionPlanLoader_SkipsAnotherProjectsGroup(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	for _, g := range []corrosion.SecurityGroup{
		{ID: "sg-base", Name: "base"},
		{ID: "sg-a", Name: "a-web", Project: "acme"},
		{ID: "sg-b", Name: "b-web", Project: "other"},
	} {
		insert := func() error { return corrosion.InsertSecurityGroup(ctx, db, g) }
		if g.Project != "" {
			insert = func() error {
				return corrosion.InsertProjectSecurityGroup(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureSGProjects), g)
			}
		}
		if err := insert(); err != nil {
			t.Fatalf("insert %s: %v", g.Name, err)
		}
		if err := corrosion.InsertSGRule(ctx, db, corrosion.SGRule{ID: "r-" + g.ID, SGID: g.ID,
			Direction: "ingress", Proto: "tcp", PortRange: "80", Action: "accept"}); err != nil {
			t.Fatalf("InsertSGRule: %v", err)
		}
	}
	bound := []string{"base", "a-web", "b-web"}
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm-a", HostName: "host-a", State: "running", Project: "acme"},
		[]corrosion.InterfaceRecord{{VMName: "vm-a", NetworkName: "prod", MAC: "aa:bb:cc:dd:ee:01",
			TapDevice: "tap-a", SecurityGroups: bound}}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct-a", State: "running", Project: "acme",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	if err := corrosion.UpsertContainerInterface(ctx, db, corrosion.ContainerInterfaceRecord{
		HostName: "host-a", CtName: "ct-a", NetworkName: "prod", MAC: "52:00:00:00:00:10",
		VethDevice: "lvca", SecurityGroups: bound,
	}); err != nil {
		t.Fatalf("UpsertContainerInterface: %v", err)
	}

	plan, err := CorrosionPlanLoader(db, "host-a", Plan{},
		liveTaps(map[string]map[string]string{"vm-a": {"aa:bb:cc:dd:ee:01": "tap-a"}}))(ctx)
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	seen := 0
	for _, nb := range plan.NICs {
		if nb.NICDev != "tap-a" && nb.NICDev != "lvca" {
			continue
		}
		seen++
		if !equalStringSlice(nb.SecurityGroups, []string{"base", "a-web"}) {
			t.Errorf("%s binds %v, want [base a-web]: another project's group must not apply", nb.NICDev, nb.SecurityGroups)
		}
		if len(nb.ExtraRules) != 0 {
			t.Errorf("%s is held at drop (%v); a foreign group is skipped like an unknown name", nb.NICDev, nb.ExtraRules)
		}
	}
	if seen != 2 {
		t.Fatalf("rendered %d of the two NICs: %+v", seen, plan.NICs)
	}
}
