package corrosion

import (
	"context"
	"errors"
	"testing"
)

func TestFailbackPolicy_DefaultsOffAndRoundTrips(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if p, err := GetFailbackPolicy(ctx, c); err != nil || p.Enabled {
		t.Fatalf("no row must read as off: %+v err=%v", p, err)
	}
	if err := SetFailbackPolicy(ctx, c, true, "alice"); !errors.Is(err, ErrClusterPolicyGateClosed) {
		t.Fatalf("set with the gate unwired: %v, want ErrClusterPolicyGateClosed", err)
	}
	openClusterPolicyGate(c)
	if err := SetFailbackPolicy(ctx, c, true, "alice"); err != nil {
		t.Fatal(err)
	}
	p, err := GetFailbackPolicy(ctx, c)
	if err != nil || !p.Enabled || p.SetBy != "alice" || p.UpdatedAt == "" {
		t.Fatalf("after on: %+v err=%v", p, err)
	}
	if err := SetFailbackPolicy(ctx, c, false, "bob"); err != nil {
		t.Fatal(err)
	}
	if p, _ := GetFailbackPolicy(ctx, c); p.Enabled || p.SetBy != "bob" {
		t.Fatalf("after off: %+v", p)
	}
}

// A value this build does not know is off, never on.
func TestFailbackPolicy_UnknownValueIsOff(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	openClusterPolicyGate(c)
	if err := c.Execute(ctx, clusterPolicyUpsertSQL, clusterPolicyFailback, "sometimes", "x", c.NowTS()); err != nil {
		t.Fatal(err)
	}
	if p, _ := GetFailbackPolicy(ctx, c); p.Enabled {
		t.Fatalf("an unknown value read as on: %+v", p)
	}
}

func TestDrainOrigins_PutListCollect(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	o := DrainOrigin{VM: "web", From: "h1", To: "h2", Epoch: 4, CreatedAt: "2026-01-01T00:00:00Z"}
	if err := PutDrainOrigin(ctx, c, o, "drain"); !errors.Is(err, ErrClusterPolicyGateClosed) {
		t.Fatalf("put with the gate unwired: %v", err)
	}
	openClusterPolicyGate(c)
	for _, x := range []DrainOrigin{o,
		{VM: "db", From: "h1", To: "h3", Epoch: 2, CreatedAt: "t"},
		{VM: "other", From: "h9", To: "h2", Epoch: 1, CreatedAt: "t"}} {
		if err := PutDrainOrigin(ctx, c, x, "drain"); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ListDrainOrigins(ctx, c, "h1")
	if err != nil || len(got) != 2 || got[0].VM != "db" || got[1] != o {
		t.Fatalf("ListDrainOrigins(h1) = %+v err=%v; want db and web, sorted, only host h1's", got, err)
	}
	if err := CollectDrainOrigin(ctx, c, "web", "failback"); err != nil {
		t.Fatal(err)
	}
	if got, _ := ListDrainOrigins(ctx, c, "h1"); len(got) != 1 || got[0].VM != "db" {
		t.Fatalf("after collecting web: %+v", got)
	}
	// A later drain of the same VM replaces the record.
	o2 := DrainOrigin{VM: "web", From: "h1", To: "h4", Epoch: 9, CreatedAt: o.CreatedAt}
	if err := PutDrainOrigin(ctx, c, o2, "drain"); err != nil {
		t.Fatal(err)
	}
	if got, _ := ListDrainOrigins(ctx, c, "h1"); len(got) != 2 || got[1] != o2 {
		t.Fatalf("a second drain did not replace the record: %+v", got)
	}
	if err := PutDrainOrigin(ctx, c, DrainOrigin{VM: "a/b", From: "h1", To: "h2"}, "x"); err == nil {
		t.Fatal("a VM name with a slash was accepted into the key")
	}
}
