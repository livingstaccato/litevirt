package corrosion

import (
	"context"
	"testing"
)

func newCtTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return c
}

// ListContainersByStack returns only containers tagged with the stack label.
func TestListContainersByStack(t *testing.T) {
	c := newCtTestClient(t)
	ctx := context.Background()
	mk := func(name, stack string) {
		r := ContainerRecord{HostName: "h1", Name: name, State: "running"}
		if stack != "" {
			r.Labels = map[string]string{LabelStack: stack}
		}
		if err := UpsertContainer(ctx, c, r); err != nil {
			t.Fatal(err)
		}
	}
	mk("a", "s1")
	mk("b", "s2")
	mk("c", "") // no stack label → belongs to no stack

	got, err := ListContainersByStack(ctx, c, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "a" {
		t.Fatalf("ListContainersByStack(s1) = %+v, want just [a]", got)
	}
	// A stack with no tagged containers is empty (and non-nil so callers can range).
	if got, _ := ListContainersByStack(ctx, c, "nope"); len(got) != 0 {
		t.Errorf("unknown stack returned %d containers", len(got))
	}
}

// SetHostLabel merges into hosts.labels and preserves other labels; re-setting
// the same value is a no-op.
func TestSetHostLabel(t *testing.T) {
	c := newCtTestClient(t)
	ctx := context.Background()
	if err := InsertHost(ctx, c, HostRecord{
		Name: "h1", Address: "10.0.0.1", SSHUser: "root", CertSerial: "x", State: "active",
	}); err != nil {
		t.Fatal(err)
	}

	if err := SetHostLabel(ctx, c, "h1", LabelLXCCapable, "true"); err != nil {
		t.Fatal(err)
	}
	h, _ := GetHost(ctx, c, "h1")
	if h == nil || h.Labels[LabelLXCCapable] != "true" {
		t.Fatalf("LXC label not set: %+v", h)
	}

	// Merging a second label preserves the first.
	if err := SetHostLabel(ctx, c, "h1", "rack", "r1"); err != nil {
		t.Fatal(err)
	}
	h, _ = GetHost(ctx, c, "h1")
	if h.Labels[LabelLXCCapable] != "true" || h.Labels["rack"] != "r1" {
		t.Fatalf("merge lost a label: %+v", h.Labels)
	}

	// Re-setting the same value is a no-op (returns nil without churn).
	if err := SetHostLabel(ctx, c, "h1", LabelLXCCapable, "true"); err != nil {
		t.Fatalf("no-op set returned error: %v", err)
	}
}
