package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

type adoptionFixture struct {
	db      *corrosion.Client
	gated   int
	enabled bool
	latched bool
	now     time.Time
	dir     string
}

func newAdoptionFixture(t *testing.T) *adoptionFixture {
	t.Helper()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return &adoptionFixture{db: db, enabled: true, latched: true, now: time.Now(), dir: t.TempDir()}
}

func (f *adoptionFixture) pass(t *testing.T, host string) ProjectAdoptionPass {
	return ProjectAdoptionPass{
		DB: f.db, Host: host,
		Enabled:   func() bool { return f.enabled },
		Available: func() bool { return f.latched },
		Gate: func(ctx context.Context, feat capabilities.Feature, write func(context.Context, capabilities.FeatureGrant) error) error {
			f.gated++
			return write(ctx, capabilities.GrantForTest(t, feat))
		},
		DataDir: f.dir,
		Now:     func() time.Time { return f.now },
	}
}

func (f *adoptionFixture) project(t *testing.T, name string, legacy bool) {
	t.Helper()
	f.db.SetProjectIncarnationGate(func() bool { return !legacy })
	if err := corrosion.InsertProject(context.Background(), f.db, corrosion.ProjectRecord{Name: name}); err != nil {
		t.Fatal(err)
	}
	f.db.SetProjectIncarnationGate(func() bool { return true })
}

func incarnationOf(t *testing.T, db *corrosion.Client, name string) string {
	t.Helper()
	p, err := corrosion.GetProject(context.Background(), db, name)
	if err != nil || p == nil {
		t.Fatalf("GetProject %s: %+v %v", name, p, err)
	}
	return p.Incarnation
}

// Re-review I-2: the pass asks the release gate (which records the feature's
// use) only once it has a project to adopt, the flag is on and the token has
// latched. A cluster with nothing to adopt, or with the flag off, records no
// use.
//
// Mutations: the gate asked before the scan — red; the flag read inside the
// gate's write — red; the latch check dropped — red.
func TestProjectAdoptionPass_RecordsNoUseWithoutWork(t *testing.T) {
	ctx := context.Background()
	f := newAdoptionFixture(t)
	f.project(t, "/born", false)
	if _, err := corrosion.ClaimInitialProjectAuthority(ctx, f.db, "/legacy", "node-1"); err != nil {
		t.Fatal(err)
	}
	if n, err := f.pass(t, "node-1").Run(ctx); err != nil || n != 0 || f.gated != 0 {
		t.Fatalf("nothing to adopt: adopted %d, gate asked %d times, err %v", n, f.gated, err)
	}
	f.project(t, "/legacy", true)
	f.enabled = false
	if n, err := f.pass(t, "node-1").Run(ctx); err != nil || n != 0 || f.gated != 0 {
		t.Fatalf("flag off: adopted %d, gate asked %d times, err %v", n, f.gated, err)
	}
	f.enabled, f.latched = true, false
	if n, err := f.pass(t, "node-1").Run(ctx); err != nil || n != 0 || f.gated != 0 {
		t.Fatalf("not latched: adopted %d, gate asked %d times, err %v", n, f.gated, err)
	}
	if _, err := os.Stat(filepath.Join(f.dir, projectAdoptionFirstLatchedFile)); !os.IsNotExist(err) {
		t.Fatalf("first-latched time recorded before the latch: %v", err)
	}
	f.latched = true
	if n, err := f.pass(t, "node-1").Run(ctx); err != nil || n != 1 || f.gated != 1 {
		t.Fatalf("with work: adopted %d, gate asked %d times, err %v", n, f.gated, err)
	}
	if inc := incarnationOf(t, f.db, "/legacy"); inc == "" {
		t.Fatal("the legacy project was not adopted")
	}
	if n, err := f.pass(t, "node-1").Run(ctx); err != nil || n != 0 || f.gated != 1 {
		t.Fatalf("after adoption: adopted %d, gate asked %d times, err %v", n, f.gated, err)
	}
}

// The preferred adopter (the authority holder) adopts at once; another host
// waits until both the row's last write and its own first sight of the
// latch are ProjectAdoptionFallback old. The first sight is written once and
// survives a restart (a new pass); a rewrite is never made.
//
// Mutations: the first-latched file rewritten on every pass — red; the
// fallback measured from the row alone — red (a pre-latch row is months old,
// so a non-holder adopts at once).
func TestProjectAdoptionPass_FallbackClockSurvivesRestarts(t *testing.T) {
	ctx := context.Background()
	f := newAdoptionFixture(t)
	f.project(t, "/legacy", true)
	if _, err := corrosion.ClaimInitialProjectAuthority(ctx, f.db, "/legacy", "holder"); err != nil {
		t.Fatal(err)
	}
	f.now = time.Now().Add(365 * 24 * time.Hour) // the row is a year old
	start := f.now
	if n, err := f.pass(t, "other").Run(ctx); err != nil || n != 0 || f.gated != 0 {
		t.Fatalf("a non-holder adopted at once: %d %v (gate %d)", n, err, f.gated)
	}
	b, err := os.ReadFile(filepath.Join(f.dir, projectAdoptionFirstLatchedFile))
	if err != nil {
		t.Fatal(err)
	}
	f.now = start.Add(ProjectAdoptionFallback - time.Minute)
	if n, _ := f.pass(t, "other").Run(ctx); n != 0 { // a "restart": a new pass
		t.Fatal("a non-holder adopted before the fallback delay")
	}
	if b2, _ := os.ReadFile(filepath.Join(f.dir, projectAdoptionFirstLatchedFile)); string(b2) != string(b) {
		t.Fatalf("the first-latched time was rewritten: %q -> %q", b, b2)
	}
	f.now = start.Add(ProjectAdoptionFallback)
	if n, err := f.pass(t, "other").Run(ctx); err != nil || n != 1 {
		t.Fatalf("a non-holder past the fallback delay: %d %v", n, err)
	}
}

func TestProjectAdoptionPass_TheHolderAdoptsAtOnce(t *testing.T) {
	ctx := context.Background()
	f := newAdoptionFixture(t)
	f.project(t, "/legacy", true)
	if _, err := corrosion.ClaimInitialProjectAuthority(ctx, f.db, "/legacy", "holder"); err != nil {
		t.Fatal(err)
	}
	if n, err := f.pass(t, "holder").Run(ctx); err != nil || n != 1 {
		t.Fatalf("the holder: adopted %d, err %v", n, err)
	}
}
