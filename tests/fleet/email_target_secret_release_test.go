package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_EmailTargetSecret_GatedOnReleaseToken drives CreateNotificationTarget
// over real gRPC against real checkers: an email target carrying an SMTP
// password is refused with the release refusal until release_2026_11_v1 has
// latched, leaves no row and no used record; once latched it succeeds, and the
// feature's used record is on every replica by the time the call returns (the
// gate records and waits for acknowledgement before the data is written).
// A passwordless email target and a webhook are never gated.
func TestFleet_EmailTargetSecret_GatedOnReleaseToken(t *testing.T) {
	ctx := context.Background()
	c, gates := latchedFleet(t, 3, 2207)
	a, old := c.Nodes[0], c.Nodes[2]
	const feature = string(capabilities.FeatureEmailTargetSecret)

	withPw := `{"host":"smtp.example.com","from":"lv@example.com","to":["ops@example.com"],"username":"u","password":"sm7pPassw0rd"}`
	noPw := `{"host":"smtp.example.com","from":"lv@example.com","to":["ops@example.com"]}`
	create := func(name, typ, cfg string) error {
		_, err := c.SelfClient(a).CreateNotificationTarget(ctx, &pb.CreateNotificationTargetRequest{Name: name, Type: typ, Config: cfg, Enabled: true})
		return err
	}

	// A host still on the previous build: the token cannot latch.
	old.Server.SetWALQuarantined(func() bool { return true })
	err := create("mail", "email", withPw)
	if status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "the cluster upgrade must finish first ("+feature+" needs "+capabilities.ReleaseToken+")") {
		t.Fatalf("create with a password before the latch: %v", err)
	}
	if rows, _ := corrosion.ListNotificationTargets(ctx, a.DB); len(rows) != 0 {
		t.Fatalf("a refused create left %d rows", len(rows))
	}
	for _, n := range c.Nodes {
		if featureUsedOn(t, n, capabilities.ReleaseToken, feature) {
			t.Fatalf("%s holds a used record for a refused create", n.Name)
		}
	}
	// Nothing main allowed is refused: passwordless email and a webhook.
	if err := create("mail-nopw", "email", noPw); err != nil {
		t.Fatalf("passwordless email target refused mid-roll: %v", err)
	}
	if err := create("hook", "webhook", `{"url":"http://example.invalid/x"}`); err != nil {
		t.Fatalf("webhook target refused mid-roll: %v", err)
	}
	for _, n := range c.Nodes {
		if featureUsedOn(t, n, capabilities.ReleaseToken, feature) {
			t.Fatalf("%s marked the feature used for an ungated create", n.Name)
		}
	}

	// Uniform fleet: the token latches and the create goes through.
	old.Server.SetWALQuarantined(old.DB.WALQuarantined)
	eventually(t, 15*time.Second, "an email target with a password to be created after the latch", func() bool {
		err = create("mail", "email", withPw)
		return err == nil
	})
	if !gates[a.Name].DurablyLatched(capabilities.ReleaseToken) {
		t.Fatalf("created before the release token durably latched on %s", a.Name)
	}
	for _, n := range c.Nodes {
		if !featureUsedOn(t, n, capabilities.ReleaseToken, feature) {
			t.Fatalf("%s lacks the used record although the create returned", n.Name)
		}
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		resp, err := c.SelfClient(n).ListNotificationTargets(ctx, &pb.ListNotificationTargetsRequest{})
		if err != nil {
			t.Fatalf("list on %s: %v", n.Name, err)
		}
		found := false
		for _, tg := range resp.Targets {
			if tg.Name == "mail" {
				found = true
				if strings.Contains(tg.Config, "sm7pPassw0rd") {
					t.Fatalf("%s lists the password: %s", n.Name, tg.Config)
				}
			}
		}
		if !found {
			t.Fatalf("%s does not hold the email target", n.Name)
		}
	}
}
