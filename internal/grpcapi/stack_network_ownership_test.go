package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Stack names may contain "_", so "<stack>_" is not a unique prefix: stack
// "app_v2"'s network "app_v2_lan" also starts with "app_". Deleting stack
// "app" removes only app's own networks — including one whose row lost its
// stack_name — and never app_v2's.
func TestDeleteStack_UnderscorePrefixKeepsLongerStacksNetworks(t *testing.T) {
	s := testServerCov(t)
	ctx := adminCtx()
	for _, st := range []string{"app", "app_v2"} {
		if err := corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{Name: st, ComposeYAML: "vms: {}\n", State: "running"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, nr := range []corrosion.NetworkRecord{
		{Name: "app_lan", StackName: "app", Type: "bridge", Config: "{}"},
		{Name: "app_db", StackName: "", Type: "bridge", Config: "{}"}, // app's, stack_name lost in a migration
		{Name: "app_v2_lan", StackName: "app_v2", Type: "bridge", Config: "{}"},
		{Name: "app_v2_db", StackName: "", Type: "bridge", Config: "{}"}, // app_v2's, stack_name lost
	} {
		if err := corrosion.UpsertNetwork(ctx, s.db, nr); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteStack(&pb.DeleteStackRequest{Name: "app"}, &mockDeleteStream{ctx: ctx}); err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	for _, name := range []string{"app_lan", "app_db"} {
		if nr, _ := corrosion.GetNetwork(ctx, s.db, name); nr != nil {
			t.Errorf("stack app's network %s survived its stack's delete", name)
		}
	}
	for _, name := range []string{"app_v2_lan", "app_v2_db"} {
		if nr, _ := corrosion.GetNetwork(ctx, s.db, name); nr == nil {
			t.Errorf("deleting stack app deleted stack app_v2's network %s", name)
		}
	}
}

func TestStackOwningName_LongestKnownPrefix(t *testing.T) {
	stacks := []string{"app", "app_v2", "web"}
	cases := map[string]string{
		"app_lan":    "app",
		"app_v2_lan": "app_v2",
		"app_v2":     "app",
		"app_":       "",
		"web_x":      "web",
		"other_x":    "",
		"app":        "",
	}
	for name, want := range cases {
		if got := stackOwningName(name, stacks); got != want {
			t.Errorf("stackOwningName(%q) = %q, want %q", name, got, want)
		}
	}
}
