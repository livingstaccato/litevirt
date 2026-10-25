package corrosion

import (
	"context"
	"testing"
)

// The automation origin is written once, by the founder, behind the
// cluster_policies gate, and never replaced; a row that does not decode is an
// error, never "absent" and never overwritten.
func TestAutomationOriginSeededOnceBehindTheGate(t *testing.T) {
	ctx := context.Background()
	closed := nicGuardDB(t, false)
	if wrote, err := SeedAutomationOrigin(ctx, closed, "h1"); err != nil || wrote {
		t.Fatalf("seeded through a closed gate: %v %v", wrote, err)
	}
	if _, have, err := GetAutomationOrigin(ctx, closed); err != nil || have {
		t.Fatalf("closed gate: origin present %v, %v", have, err)
	}

	c := nicGuardDB(t, true)
	if wrote, err := SeedAutomationOrigin(ctx, c, "h1"); err != nil || !wrote {
		t.Fatalf("founder could not seed the origin: %v %v", wrote, err)
	}
	o, have, err := GetAutomationOrigin(ctx, c)
	if err != nil || !have || o.Version != 1 || o.Founder != "h1" || o.FoundedAt == "" {
		t.Fatalf("origin %+v present %v: %v", o, have, err)
	}
	if wrote, err := SeedAutomationOrigin(ctx, c, "h2"); err != nil || wrote {
		t.Fatalf("a second seed replaced the origin: %v %v", wrote, err)
	}
	if o2, _, _ := GetAutomationOrigin(ctx, c); o2 != o {
		t.Fatalf("origin changed to %+v", o2)
	}

	bad := nicGuardDB(t, true)
	if err := SetClusterPolicy(ctx, bad, clusterPolicyAutomationOrigin, `{"version":2,"founder":"x","founded_at":"t"}`, "test"); err != nil {
		t.Fatal(err)
	}
	if _, have, err := GetAutomationOrigin(ctx, bad); err == nil || have {
		t.Fatalf("an undecodable origin read as present %v / absent without error (%v)", have, err)
	}
	if wrote, err := SeedAutomationOrigin(ctx, bad, "h1"); err != nil || wrote {
		t.Fatalf("an undecodable origin was overwritten: %v %v", wrote, err)
	}
}

// Authority moves to the new generation only through the carrying import of
// an ordinary transition that keeps this voter, under its own incarnation, in
// an automation-eligible electorate. Every other adoption leaves this voter
// not automation-ready.
func TestAutomationVoterCarryGuardRules(t *testing.T) {
	ctx := context.Background()
	ca := newClaimTestCA(t)
	for _, tc := range []struct {
		name     string
		next     func(a, b, c, d *claimTestVoter) VoterConfigValue
		carrying bool
		want     bool
	}{
		{"ordinary member", func(a, b, c, d *claimTestVoter) VoterConfigValue {
			return VoterConfigValue{Members: membersOf(a, b, c, d), Change: VoterChangeAdd("d")}
		}, true, true},
		{"non-carrying import", func(a, b, c, d *claimTestVoter) VoterConfigValue {
			return VoterConfigValue{Members: membersOf(a, b, c, d), Change: VoterChangeAdd("d")}
		}, false, false},
		{"forced", func(a, b, c, d *claimTestVoter) VoterConfigValue {
			return VoterConfigValue{Members: membersOf(a, b, c), Change: "force:x"}
		}, true, false},
		{"other incarnation", func(a, b, c, d *claimTestVoter) VoterConfigValue {
			ms := membersOf(a, b, c, d)
			for i := range ms {
				if ms[i].Name == c.name {
					ms[i].Incarnation = "someone-else"
				}
			}
			return VoterConfigValue{Members: ms, Change: VoterChangeAdd("d")}
		}, true, false},
		{"two voters", func(a, b, c, d *claimTestVoter) VoterConfigValue {
			return VoterConfigValue{Members: membersOf(b, c), Change: "rm:a"}
		}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b, c, d := newClaimTestVoter(t, ca, "a"), newClaimTestVoter(t, ca, "b"), newClaimTestVoter(t, ca, "c"), newClaimTestVoter(t, ca, "d")
			adoptHandBuilt(t, 1, membersOf(a, b, c), c)
			key, err := AutomationClaimKey(1)
			if err != nil {
				t.Fatal(err)
			}
			installAutomationEvidence(t, c.c, key, "", 1)
			if st, err := c.c.AutomationMembershipStanding(ctx); err != nil || !st.Imported || st.Generation != 1 {
				t.Fatalf("fixture standing %+v: %v", st, err)
			}
			next := tc.next(a, b, c, d)
			next.Generation, next.CreatedBy, next.CreatedAt = 2, "t", "t"
			if err := WriteVoterConfig(ctx, c.c, next, ClaimCertificate{}); err != nil {
				t.Fatal(err)
			}
			if tc.carrying {
				_, err = c.c.ImportClaimsAndAdoptAutomation(ctx, 2, []string{"a", "b"}, nil)
			} else {
				_, err = c.c.ImportClaimsAndAdopt(ctx, 2, []string{"a", "b"}, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			st, err := c.c.AutomationMembershipStanding(ctx)
			if err != nil || st.Generation != 2 {
				t.Fatalf("standing %+v: %v", st, err)
			}
			if st.Imported != tc.want {
				t.Fatalf("authority carried = %v, want %v (%s)", st.Imported, tc.want, st.Detail)
			}
			if _, err := c.c.AutomationMembership(ctx); (err == nil) != tc.want {
				t.Fatalf("automation membership after adoption: %v, want authority %v", err, tc.want)
			}
			// Not carried means the row never moved, not merely that it is
			// rejected when read.
			var gen int64
			if err := c.c.db.QueryRowContext(ctx, `SELECT generation FROM local_automation_authority WHERE id = 1`).Scan(&gen); err != nil {
				t.Fatal(err)
			}
			if want := map[bool]int64{true: 2, false: 1}[tc.want]; gen != want {
				t.Fatalf("authority row at generation %d, want %d", gen, want)
			}
		})
	}
}
