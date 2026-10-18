package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func synFloodLoaderDB(t *testing.T) *corrosion.Client {
	t.Helper()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	return db
}

func setSynFloodPolicy(t *testing.T, db *corrosion.Client, host string, p corrosion.FirewallSynflood) {
	t.Helper()
	g := capabilities.GrantForTest(t, capabilities.FeatureFirewallSynflood)
	if err := corrosion.SetFirewallSynflood(context.Background(), db, g, host, p, "alice"); err != nil {
		t.Fatalf("SetFirewallSynflood(%q): %v", host, err)
	}
}

// putSynFloodRaw stores a value as a replica might receive it from another
// build, bypassing the writer.
func putSynFloodRaw(t *testing.T, db *corrosion.Client, key, value string) {
	t.Helper()
	if err := db.Execute(context.Background(),
		`INSERT INTO cluster_policies (key, value, set_by, updated_at, deleted_at) VALUES (?, ?, 'peer', ?, NULL)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, deleted_at = NULL`,
		key, value, db.NowTS()); err != nil {
		t.Fatal(err)
	}
}

func loadSynFloodPlan(t *testing.T, db *corrosion.Client, host string, probe func() error) Plan {
	t.Helper()
	plan, err := CorrosionPlanLoader(db, host, Plan{}, LoaderOptions{SynFloodProbe: probe})(context.Background())
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	return plan
}

// The loader fills Plan.SynFlood from the policy resolved for its host: the
// host's row over the cluster's, with neither off.
func TestLoader_SynFloodFillsPlan(t *testing.T) {
	db := synFloodLoaderDB(t)
	if got := loadSynFloodPlan(t, db, "host-a", nil).SynFlood; got.On {
		t.Errorf("no policy: SynFlood = %+v, want off", got)
	}
	setSynFloodPolicy(t, db, "", corrosion.FirewallSynflood{Mode: corrosion.SynfloodOn, Rate: 300, Burst: 1500})
	if got := loadSynFloodPlan(t, db, "host-a", nil).SynFlood; got != (SynFlood{On: true, Rate: 300, Burst: 1500}) {
		t.Errorf("cluster on: SynFlood = %+v, want on 300/1500", got)
	}
	setSynFloodPolicy(t, db, "host-a", corrosion.FirewallSynflood{Mode: corrosion.SynfloodOff})
	if got := loadSynFloodPlan(t, db, "host-a", nil).SynFlood; got.On {
		t.Errorf("host off over cluster on: SynFlood = %+v, want off", got)
	}
	if got := loadSynFloodPlan(t, db, "host-b", nil).SynFlood; got != (SynFlood{On: true, Rate: 300, Burst: 1500}) {
		t.Errorf("another host: SynFlood = %+v, want the cluster's on 300/1500", got)
	}
}

// A kernel that refused the probe renders nothing SYN-flood and reports why,
// while the policy asks for protection; with the policy off there is nothing
// to report.
func TestLoader_SynFloodProbeRefused(t *testing.T) {
	db := synFloodLoaderDB(t)
	refused := func() error { return errors.New("nft refused probe table: no nft_limit") }
	setSynFloodPolicy(t, db, "", corrosion.FirewallSynflood{Mode: corrosion.SynfloodOn, Rate: 200, Burst: 1000})
	plan := loadSynFloodPlan(t, db, "host-a", refused)
	if plan.SynFlood.On {
		t.Errorf("refused probe: SynFlood = %+v, want off", plan.SynFlood)
	}
	if !strings.Contains(plan.SynFloodUnavailable, "no nft_limit") {
		t.Errorf("refused probe: SynFloodUnavailable = %q, want the refusal", plan.SynFloodUnavailable)
	}
	plan.NICs = []NICBinding{{NICDev: "tap0", VMName: "vm1"}}
	out, err := Render(plan)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(out, setSyn4) || strings.Contains(out, SynFloodComment) {
		t.Error("refused probe: the ruleset still carries SYN-flood lines")
	}

	setSynFloodPolicy(t, db, "", corrosion.FirewallSynflood{Mode: corrosion.SynfloodOff})
	if plan := loadSynFloodPlan(t, db, "host-a", refused); plan.SynFloodUnavailable != "" || plan.SynFlood.On {
		t.Errorf("policy off: SynFlood = %+v, unavailable %q; want off and nothing to report", plan.SynFlood, plan.SynFloodUnavailable)
	}
	setSynFloodPolicy(t, db, "", corrosion.FirewallSynflood{Mode: corrosion.SynfloodOn, Rate: 200, Burst: 1000})
	if plan := loadSynFloodPlan(t, db, "host-a", func() error { return nil }); !plan.SynFlood.On || plan.SynFloodUnavailable != "" {
		t.Errorf("accepted probe: SynFlood = %+v, unavailable %q", plan.SynFlood, plan.SynFloodUnavailable)
	}
}

// A row this build cannot read protects at the defaults, does not fail the
// pass, and is reported naming its key.
func TestLoader_SynFloodUnreadable(t *testing.T) {
	db := synFloodLoaderDB(t)
	putSynFloodRaw(t, db, corrosion.FirewallSynfloodKey(""), "on please")
	plan := loadSynFloodPlan(t, db, "host-a", nil)
	if plan.SynFlood != (SynFlood{On: true, Rate: corrosion.SynfloodDefaultRate, Burst: corrosion.SynfloodDefaultBurst}) {
		t.Errorf("unreadable row: SynFlood = %+v, want on at the defaults", plan.SynFlood)
	}
	if len(plan.UnreadablePolicies) != 1 || !strings.Contains(plan.UnreadablePolicies[0], corrosion.FirewallSynfloodKey("")) {
		t.Errorf("unreadable row: UnreadablePolicies = %q, want one naming %s", plan.UnreadablePolicies, corrosion.FirewallSynfloodKey(""))
	}
	putSynFloodRaw(t, db, corrosion.FirewallSynfloodKey(""), `{"mode":"off"}`)
	if plan := loadSynFloodPlan(t, db, "host-a", nil); len(plan.UnreadablePolicies) != 0 {
		t.Errorf("readable again: UnreadablePolicies = %q", plan.UnreadablePolicies)
	}
}

// B2 review m2 carry: validate refuses the whole plan on an out-of-range
// SYN-flood value, so every path through the loader must hand it one that
// passes: no row, on, off, off with numbers, inherit, every unreadable shape
// and a refused probe. None may arrive as on with a zero rate or burst.
func TestLoader_SynFloodEveryPathValidates(t *testing.T) {
	refused := func() error { return errors.New("refused") }
	cases := []struct {
		name  string
		setup func(t *testing.T, db *corrosion.Client)
		probe func() error
	}{
		{"no row", func(*testing.T, *corrosion.Client) {}, nil},
		{"cluster on", func(t *testing.T, db *corrosion.Client) {
			setSynFloodPolicy(t, db, "", corrosion.FirewallSynflood{Mode: corrosion.SynfloodOn, Rate: 1, Burst: 100000})
		}, nil},
		{"cluster off with numbers", func(t *testing.T, db *corrosion.Client) {
			setSynFloodPolicy(t, db, "", corrosion.FirewallSynflood{Mode: corrosion.SynfloodOff, Rate: 5, Burst: 6})
		}, nil},
		{"host inherit", func(t *testing.T, db *corrosion.Client) {
			setSynFloodPolicy(t, db, "", corrosion.FirewallSynflood{Mode: corrosion.SynfloodOn, Rate: 100000, Burst: 1})
			setSynFloodPolicy(t, db, "host-a", corrosion.FirewallSynflood{})
		}, nil},
		{"refused probe", func(t *testing.T, db *corrosion.Client) {
			setSynFloodPolicy(t, db, "", corrosion.FirewallSynflood{Mode: corrosion.SynfloodOn, Rate: 200, Burst: 1000})
		}, refused},
	}
	for _, raw := range []string{"{}", "null", "x", `{"mode":"on"}`, `{"mode":"on","rate":0,"burst":1000}`,
		`{"mode":"on","rate":200,"burst":100001}`, `{"mode":"on","rate":-1,"burst":5}`, `{"mode":"off","rate":0,"burst":7}`,
		`{"mode":"strict","rate":200,"burst":1000}`, `[]`, `{"mode":"on","rate":"200","burst":1000}`} {
		for _, key := range []string{corrosion.FirewallSynfloodKey(""), corrosion.FirewallSynfloodKey("host-a")} {
			cases = append(cases, struct {
				name  string
				setup func(t *testing.T, db *corrosion.Client)
				probe func() error
			}{"raw " + key + " " + raw, func(t *testing.T, db *corrosion.Client) { putSynFloodRaw(t, db, key, raw) }, nil})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := synFloodLoaderDB(t)
			tc.setup(t, db)
			plan := loadSynFloodPlan(t, db, "host-a", tc.probe)
			if err := validateSynFlood(plan.SynFlood); err != nil {
				t.Fatalf("SynFlood %+v fails validate: %v", plan.SynFlood, err)
			}
			if plan.SynFlood.On && (plan.SynFlood.Rate == 0 || plan.SynFlood.Burst == 0) {
				t.Fatalf("SynFlood %+v is on with a zero rate or burst", plan.SynFlood)
			}
			plan.NICs = []NICBinding{{NICDev: "tap0", VMName: "vm1"}}
			if _, err := Render(plan); err != nil {
				t.Fatalf("Render: %v", err)
			}
		})
	}
}

// The start probe checks the renderer's own SYN-flood sets and line, so a
// kernel that accepts the probe accepts what is rendered (B2 review m1).
func TestProbeSynFlood_ChecksTheRenderedShape(t *testing.T) {
	prev := probeRunner
	t.Cleanup(func() { probeRunner = prev })
	var got string
	var args []string
	probeRunner = func(_ context.Context, stdin string, a ...string) (string, error) {
		got, args = stdin, a
		return "", nil
	}
	if err := ProbeSynFlood(context.Background()); err != nil {
		t.Fatalf("ProbeSynFlood: %v", err)
	}
	if strings.Join(args, " ") != "-c -f -" {
		t.Errorf("nft args = %q, want check only", args)
	}
	p := Plan{SynFlood: SynFlood{On: true, Rate: corrosion.SynfloodDefaultRate, Burst: corrosion.SynfloodDefaultBurst}}
	var sets, lines strings.Builder
	renderSynFloodSets(&sets, p)
	renderSynFloodLines(&lines, p)
	for _, want := range []string{sets.String(), lines.String(), "set " + setNICDevs} {
		if !strings.Contains(got, want) {
			t.Errorf("probe ruleset lacks %q:\n%s", want, got)
		}
	}
	probeRunner = func(context.Context, string, ...string) (string, error) {
		return "Error: Could not process rule: No such file or directory", errors.New("exit status 1")
	}
	if err := ProbeSynFlood(context.Background()); err == nil || !strings.Contains(err.Error(), "No such file") {
		t.Errorf("refused probe: err = %v, want nft's refusal", err)
	}
}

// Plan.UnreadablePolicies is shared with the other policy blocks of the pass
// (the log policy's): it is reset once at the top of the pass and each block
// APPENDS, so the SYN-flood block keeps what came before it, and a stale
// entry in the defaults plan never survives.
//
// Mutations: assign instead of append — the earlier entry is lost: red; drop
// the reset at the top of the pass — the stale entry survives: red.
func TestLoader_SynFloodAppendsUnreadable(t *testing.T) {
	ctx := context.Background()
	db := synFloodLoaderDB(t)
	putSynFloodRaw(t, db, corrosion.FirewallSynfloodKey(""), "x")
	_, _, got, err := loadSynFlood(ctx, db, "host-a", nil, []string{"earlier"})
	if err != nil || len(got) != 2 || got[0] != "earlier" || !strings.Contains(got[1], corrosion.FirewallSynfloodKey("")) {
		t.Fatalf("loadSynFlood unreadable = %q, %v; want the earlier entry kept and the SYN-flood key appended", got, err)
	}
	plan, err := CorrosionPlanLoader(db, "host-a", Plan{UnreadablePolicies: []string{"stale"}}, LoaderOptions{})(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.UnreadablePolicies) != 1 || plan.UnreadablePolicies[0] == "stale" {
		t.Errorf("UnreadablePolicies = %q, want only this pass's SYN-flood entry", plan.UnreadablePolicies)
	}
}
