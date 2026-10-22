package corrosion

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
)

func adoptionClient(t *testing.T) *Client {
	t.Helper()
	c := NewTestClientT(t)
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

func adoptGrant(t *testing.T) capabilities.FeatureGrant {
	return capabilities.GrantForTest(t, capabilities.FeatureProjectAdoption)
}

// legacyProject makes, with project_incarnation_v1 not latched, the project
// name ("") with an untagged grant, a none-tagged pre-grant, a pre-tagged
// grant, a NoAccess sentinel and a bare-key quota, as a v1.9 cluster holds
// it once the latch arrives. It leaves the gate on.
func legacyProject(t *testing.T, c *Client, name string) {
	t.Helper()
	ctx := context.Background()
	c.SetProjectIncarnationGate(func() bool { return false })
	if err := InsertProject(ctx, c, ProjectRecord{Name: name}); err != nil {
		t.Fatal(err)
	}
	if err := UpsertProjectQuota(ctx, c, ProjectQuotaRecord{ProjectName: name, VCPULimit: 8, MemMiBLimit: 4096}); err != nil {
		t.Fatal(err)
	}
	root := "/projects" + strings.TrimSuffix("/"+strings.TrimPrefix(name, "/"), "/")
	sfx := strings.ReplaceAll(name, "/", "_")
	for _, b := range []struct{ id, path, role string }{
		{"untagged" + sfx, root, "Operator"},
		{"pregrant" + sfx + "~p:none", root + "/vms/x", "Viewer"},
		{"latched" + sfx + "~p:pre", root, "Admin"},
		{"sentinel" + sfx, root, SentinelRole},
		// Granted for another incarnation of the name: held before and
		// after (the settle may retire it to NoAccess, which grants the
		// same nothing).
		{"older" + sfx + "~p:r0123456789abcdef0123456789abcdef", root, "Operator"},
	} {
		if err := c.Execute(ctx, roleBindingInsertSQL, b.id, b.path, b.role, "user:bob@local", 1, c.NowTS()); err != nil {
			t.Fatal(err)
		}
	}
	c.SetProjectIncarnationGate(func() bool { return true })
}

// adoptionView is what a receiver grants and bounds for project name: every
// live binding's effective role (NoAccess when held, as the auth engine reads
// it) and the quota read.
func adoptionView(t *testing.T, c *Client, name string) string {
	t.Helper()
	ctx := context.Background()
	bs, err := ListRoleBindings(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, b := range bs {
		role := b.Role
		if b.Held {
			role = SentinelRole
		}
		out = append(out, b.ID+"="+role)
	}
	sort.Strings(out)
	q, err := GetProjectQuota(ctx, c, name)
	if err != nil {
		t.Fatal(err)
	}
	if q == nil {
		out = append(out, "quota=none (unbounded)")
	} else {
		out = append(out, fmt.Sprintf("quota=%d/%d", q.VCPULimit, q.MemMiBLimit))
	}
	return strings.Join(out, "\n")
}

func projectRow(t *testing.T, c *Client, name string) string {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT name, display, parent_name, created_at, updated_at, deleted_at, incarnation FROM projects WHERE name = ?`, name)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		return "<no row>"
	}
	r := rows[0]
	return strings.Join([]string{r.String("name"), r.String("display"), r.String("parent_name"), r.String("created_at"),
		r.String("updated_at"), r.String("deleted_at"), r.String("incarnation")}, "|")
}

func walTo(t *testing.T, from *Client, origin string, to *Client) {
	t.Helper()
	applyWALEntries(t, to, walEntries(t, from, origin))
}

func applyWALEntries(t *testing.T, to *Client, es []*pb.MutationEntry) {
	t.Helper()
	if _, err := NewReplicator(to, "", RelayConfig{}).ApplyRemoteMutations(context.Background(), es); err != nil {
		t.Fatalf("ApplyRemoteMutations: %v", err)
	}
}

// The adopted incarnation is a wire value: "a" and 128 bits of SHA-256 of the
// canonical name, the same for every spelling, distinct per name, never the
// default project's constant.
//
// Mutation: created_at (or anything but the canonical name) in the hash —
// red (pinned bytes).
func TestAdoptedProjectIncarnation_IsPinned(t *testing.T) {
	if got := adoptedProjectIncarnation("/acme"); got != "aaf7986a22959ac3f46c6116c8dfa1ab8" {
		t.Fatalf("adoptedProjectIncarnation(/acme) = %q: the value is on the wire and in dependent records", got)
	}
	if got := adoptedProjectIncarnation("/acme/team"); got != "a2aefc8150d1616a3b07c014738bfb135" {
		t.Fatalf("adoptedProjectIncarnation(/acme/team) = %q", got)
	}
	if !regexp.MustCompile(`^a[0-9a-f]{32}$`).MatchString(adoptedProjectIncarnation("/x")) {
		t.Fatal("not a and 32 hex digits")
	}
	if adoptedProjectIncarnation("/a") == adoptedProjectIncarnation("/b") {
		t.Fatal("two names share an adopted incarnation")
	}
	if defaultProjectIncarnation != "default" {
		t.Fatalf("defaultProjectIncarnation = %q: dependent records store it", defaultProjectIncarnation)
	}
	if !projectPreIncarnationOfName("acme", adoptedProjectIncarnation("/acme")) {
		t.Fatal("a legacy spelling does not alias its canonical name's adopted incarnation")
	}
}

// Every reader takes a row holding the name's adopted incarnation exactly as
// one holding "": untagged, none- and pre-tagged bindings grant, the quota is
// the bare key. Another name's adopted value, or an operator-written "a…",
// is a foreign incarnation (equality, never the prefix).
//
// Mutations: the alias dropped from projectBindingHeld — red; from
// projectQuotaKey — red; the alias by "a" prefix — red.
func TestProjectAdoption_ReadersTakeTheAdoptedIncarnationAsPreLatch(t *testing.T) {
	adopted := adoptedProjectIncarnation("/acme")
	foreign := adoptedProjectIncarnation("/other")
	born := newProjectIncarnation(true)
	for _, tc := range []struct {
		live      string
		preGrants bool
	}{
		{"", true}, {adopted, true}, {foreign, false}, {"a" + strings.Repeat("0", 32), false}, {born, false},
	} {
		states := projectStates([][4]string{{"/acme", "", tc.live, "t"}}, []bool{false})
		for _, id := range []string{"untagged", "g~p:none", "g~p:pre"} {
			held := projectBindingHeld(RoleBindingRecord{ID: id, Path: "/projects/acme"}, states)
			if held == tc.preGrants {
				t.Errorf("live %q: %s held=%v, want held=%v", tc.live, id, held, !tc.preGrants)
			}
		}
		if projectBindingHeld(RoleBindingRecord{ID: "g~p:" + tc.live, Path: "/projects/acme"}, states) && tc.live != "" {
			t.Errorf("live %q: a binding tagged with it is held", tc.live)
		}
		wantBare := tc.preGrants
		if got := projectQuotaKey("/acme", tc.live) == "/acme"; got != wantBare {
			t.Errorf("live %q: quota key %q, want bare=%v", tc.live, projectQuotaKey("/acme", tc.live), wantBare)
		}
	}
	// A binding tagged with the adopted value grants only once the row holds
	// it: before, it is a foreign incarnation to a "" row.
	pre := projectStates([][4]string{{"/acme", "", "", "t"}}, []bool{false})
	if !projectBindingHeld(RoleBindingRecord{ID: "g~p:" + adopted, Path: "/projects/acme"}, pre) {
		t.Error("an adopted-tagged binding grants under a row still holding ''")
	}
}

// Adoption changes nothing a receiver grants or bounds: the adopter, a WAL
// receiver and an anti-entropy receiver each see the same bindings (role,
// held, clock) and the same quota before and after, and nothing is retired.
// The row then holds the adopted incarnation at justAfterTS(U).
//
// Mutations: the alias dropped from projectBindingHeld, from the keep set
// (pre retired), or from projectQuotaKey (unbounded) — each red; a NowTS
// stamp — red (the clock).
func TestProjectAdoption_ChangesNothingAReceiverSees(t *testing.T) {
	ctx := context.Background()
	src := adoptionClient(t)
	legacyProject(t, src, "/acme")
	wal, ae := adoptionClient(t), adoptionClient(t)
	for _, r := range []*Client{wal, ae} {
		r.SetProjectIncarnationGate(func() bool { return true })
		walTo(t, src, "src", r)
	}
	before := map[*Client]string{src: adoptionView(t, src, "/acme"), wal: adoptionView(t, wal, "/acme"), ae: adoptionView(t, ae, "/acme")}
	if !strings.Contains(before[src], "quota=8/4096") || !strings.Contains(before[src], "latched_acme~p:pre=Admin") ||
		!strings.Contains(before[src], "~p:r0123456789abcdef0123456789abcdef="+SentinelRole) {
		t.Fatalf("fixture:\n%s", before[src])
	}
	u := strings.Split(projectRow(t, src, "/acme"), "|")[4]
	applied, err := AdoptProjectIncarnation(ctx, src, adoptGrant(t), "/acme")
	if err != nil || !applied {
		t.Fatalf("adopt: applied=%v err=%v", applied, err)
	}
	walTo(t, src, "src", wal)
	aeBoth(t, src, ae)
	want, _ := justAfterTS(u)
	for name, c := range map[string]*Client{"adopter": src, "wal receiver": wal, "ae receiver": ae} {
		row := strings.Split(projectRow(t, c, "/acme"), "|")
		if row[6] != adoptedProjectIncarnation("/acme") || row[4] != want || row[5] != "" {
			t.Errorf("%s: row %v, want live, adopted, at %s", name, row, want)
		}
		if got := adoptionView(t, c, "/acme"); got != before[c] {
			t.Errorf("%s: what it grants and bounds moved:\nbefore\n%s\nafter\n%s", name, before[c], got)
		}
	}
}

// A late write of the "" lifetime from a node that has not seen the adoption
// still counts on a node that has: its pre-tagged and untagged grants grant
// and are not retired, and its bare-key quota is the one read (review I4).
//
// Mutations: the alias dropped from projectBindingHeld, the keep set or
// projectQuotaKey — each red.
func TestProjectAdoption_ALateWriteOfThePreLatchLifetimeCounts(t *testing.T) {
	ctx := context.Background()
	lag := adoptionClient(t)
	legacyProject(t, lag, "/acme")
	adopter := adoptionClient(t)
	adopter.SetProjectIncarnationGate(func() bool { return true })
	walTo(t, lag, "lag", adopter)
	if ok, err := AdoptProjectIncarnation(ctx, adopter, adoptGrant(t), "/acme"); err != nil || !ok {
		t.Fatalf("adopt: %v %v", ok, err)
	}
	// The lagging node, latched but still at "", grants and tightens.
	id, err := ProjectBindingID(ctx, lag, "/projects/acme", "late")
	if err != nil || id != "late~p:pre" {
		t.Fatalf("lagging node's tag: %q %v", id, err)
	}
	if err := insertProjectBinding(ctx, lag, "/acme", projectTagPre, []interface{}{id, "/projects/acme", "Operator", "user:carol@local", 1, lag.NowTS()}); err != nil {
		t.Fatal(err)
	}
	if err := lag.Execute(ctx, roleBindingInsertSQL, "late-untagged", "/projects/acme", "Viewer", "user:dave@local", 1, lag.NowTS()); err != nil {
		t.Fatal(err)
	}
	if err := UpsertProjectQuota(ctx, lag, ProjectQuotaRecord{ProjectName: "/acme", VCPULimit: 2, MemMiBLimit: 512}); err != nil {
		t.Fatal(err)
	}
	walTo(t, lag, "lag", adopter)
	for _, id := range []string{"late~p:pre", "late-untagged"} {
		b, err := GetRoleBinding(ctx, adopter, id)
		if err != nil || b == nil || b.Held || b.Role == SentinelRole {
			t.Errorf("late grant %s on the adopter: %+v (err %v), want it granting", id, b, err)
		}
	}
	if q, _ := GetProjectQuota(ctx, adopter, "/acme"); q == nil || q.VCPULimit != 2 {
		t.Errorf("late quota on the adopter: %+v, want the tightened 2 vCPU", q)
	}
	// And the lagging node, once it takes the adoption, retires nothing.
	walTo(t, adopter, "adopter", lag)
	if b, _ := GetRoleBinding(ctx, lag, "late~p:pre"); b == nil || b.Held || b.Role != "Operator" {
		t.Errorf("late grant on the lagging node after the adoption: %+v", b)
	}
}

// The adoption writes only a live row that is the only live spelling of its
// name, still holds "", and has the updated_at it read; anything else writes
// nothing. It needs the feature's grant.
//
// Mutations: the single-spelling check dropped — red; the updated_at check
// dropped — red (hook case); the grant check dropped — red.
func TestProjectAdoption_GuardWritesOnlyTheStateItRead(t *testing.T) {
	ctx := context.Background()
	t.Cleanup(func() { projectAdoptionHook = nil })
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, c *Client)
		hook  func(c *Client)
	}{
		{"two live spellings", func(t *testing.T, c *Client) {
			c.SetProjectIncarnationGate(func() bool { return false })
			if err := InsertProject(ctx, c, ProjectRecord{Name: "acme"}); err != nil {
				t.Fatal(err)
			}
			c.SetProjectIncarnationGate(func() bool { return true })
		}, nil},
		{"deleted", func(t *testing.T, c *Client) {
			if _, err := c.db.Exec(`UPDATE projects SET deleted_at = '2026-01-01T00:00:00Z' WHERE name = '/acme'`); err != nil {
				t.Fatal(err)
			}
		}, nil},
		{"born after the latch", func(t *testing.T, c *Client) {
			if _, err := c.db.Exec(`UPDATE projects SET incarnation = ? WHERE name = '/acme'`, newProjectIncarnation(false)); err != nil {
				t.Fatal(err)
			}
		}, nil},
		{"written between the read and the write", nil, func(c *Client) {
			if _, err := c.db.Exec(`UPDATE projects SET updated_at = ? WHERE name = '/acme'`, c.NowTS()); err != nil {
				panic(err)
			}
		}},
		{"a spelling made live between the read and the write", nil, func(c *Client) {
			if _, err := c.db.Exec(`INSERT INTO projects (name, display, created_at, updated_at) VALUES ('acme', '', 'x', 'y')`); err != nil {
				panic(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := adoptionClient(t)
			legacyProject(t, c, "/acme")
			if tc.setup != nil {
				tc.setup(t, c)
			}
			projectAdoptionHook = nil
			if tc.hook != nil {
				projectAdoptionHook = func() { tc.hook(c) }
			}
			was := projectRow(t, c, "/acme")
			applied, err := AdoptProjectIncarnation(ctx, c, adoptGrant(t), "/acme")
			projectAdoptionHook = nil
			if err != nil || applied {
				t.Fatalf("applied=%v err=%v, want nothing written", applied, err)
			}
			if got := projectRow(t, c, "/acme"); strings.HasSuffix(got, "|"+adoptedProjectIncarnation("/acme")) {
				t.Fatalf("row adopted: %s (was %s)", got, was)
			}
		})
	}
	c := adoptionClient(t)
	legacyProject(t, c, "/acme")
	if _, err := AdoptProjectIncarnation(ctx, c, capabilities.GrantForTest(t, capabilities.FeatureFenceSSH), "/acme"); err == nil {
		t.Fatal("adopted with another feature's grant")
	}
	if ok, err := AdoptProjectIncarnation(ctx, c, adoptGrant(t), "/acme"); err != nil || !ok {
		t.Fatalf("adopt: %v %v", ok, err)
	}
	if ok, err := AdoptProjectIncarnation(ctx, c, adoptGrant(t), "/acme"); err != nil || ok {
		t.Fatalf("adopting again: applied=%v err=%v, want done", ok, err)
	}
	if _, err := AdoptProjectIncarnation(ctx, c, adoptGrant(t), DefaultProject); err == nil {
		t.Fatal("adopted the default project")
	}
}

// Two adopters of one name that read the same row write byte-identical
// statements, and converge to one row.
//
// Mutations: a NowTS stamp — red; created_at in the hash — green here (same
// row), red in TestAdoptedProjectIncarnation_IsPinned.
func TestProjectAdoption_ConcurrentAdoptersWriteOneStatement(t *testing.T) {
	ctx := context.Background()
	src := adoptionClient(t)
	legacyProject(t, src, "/acme")
	a, b := adoptionClient(t), adoptionClient(t)
	for _, c := range []*Client{a, b} {
		c.SetProjectIncarnationGate(func() bool { return true })
		walTo(t, src, "src", c)
	}
	last := func(c *Client) string {
		rows, err := c.Query(ctx, `SELECT stmts FROM mutation_log ORDER BY seq DESC LIMIT 1`)
		if err != nil || len(rows) != 1 {
			t.Fatalf("mutation_log: %v", err)
		}
		return rows[0].String("stmts")
	}
	for _, c := range []*Client{a, b} {
		if ok, err := AdoptProjectIncarnation(ctx, c, adoptGrant(t), "/acme"); err != nil || !ok {
			t.Fatalf("adopt: %v %v", ok, err)
		}
	}
	if la, lb := last(a), last(b); la != lb {
		t.Fatalf("two adopters wrote different entries:\n%s\n%s", la, lb)
	}
	walTo(t, a, "a", b)
	walTo(t, b, "b", a)
	if ra, rb := projectRow(t, a, "/acme"), projectRow(t, b, "/acme"); ra != rb {
		t.Fatalf("rows differ: %s vs %s", ra, rb)
	}
}

// Re-review I-1: a delete made after the adoption overtakes it on a receiver
// (which then skips the adoption as older), leaving "" on some replicas and
// the adopted value on others at one updated_at. Anti-entropy converges every
// replica to one row, the adopted one, deleted, with no unresolved tie.
//
// Mutation: the alias tie rule dropped — red (rows differ, an unresolved tie).
func TestProjectAdoption_ADeleteThatOvertakesTheAdoptionConverges(t *testing.T) {
	ctx := context.Background()
	src := adoptionClient(t)
	legacyProject(t, src, "/acme")
	r, n, l := adoptionClient(t), adoptionClient(t), adoptionClient(t)
	for _, c := range []*Client{r, n, l} {
		c.SetProjectIncarnationGate(func() bool { return true })
		walTo(t, src, "src", c)
	}
	if ok, err := AdoptProjectIncarnation(ctx, r, adoptGrant(t), "/acme"); err != nil || !ok {
		t.Fatalf("adopt: %v %v", ok, err)
	}
	walTo(t, r, "r", n)
	if _, err := n.db.Exec(`DELETE FROM role_bindings`); err != nil { // DeleteProject refuses nothing here; keep its retire simple
		t.Fatal(err)
	}
	if err := DeleteProject(ctx, n, "/acme"); err != nil {
		t.Fatal(err)
	}
	walTo(t, n, "n", l) // the delete first
	walTo(t, r, "r", l) // the adoption, now older: skipped
	if got := strings.Split(projectRow(t, l, "/acme"), "|"); got[6] != "" || got[5] == "" {
		t.Fatalf("fixture: the overtaken receiver holds %v, want a '' tombstone", got)
	}
	// A pre-tagged grant of the pre-latch lifetime that only l holds (one the
	// delete never saw). When the tie rule turns l's '' tombstone into the
	// adopted one, l settles; the adopted tombstone keeps pre out of
	// retirement exactly as a '' tombstone does (review m-R1).
	if err := l.Execute(ctx, roleBindingInsertSQL, "only-l~p:pre", "/projects/acme", "Operator", "user:carol@local", 1, l.NowTS()); err != nil {
		t.Fatal(err)
	}
	walTo(t, n, "n", r)
	for i := 0; i < 2; i++ {
		for _, from := range []*Client{r, n, l} {
			for _, to := range []*Client{r, n, l} {
				if from != to {
					aeBoth(t, from, to)
				}
			}
		}
	}
	want := projectRow(t, r, "/acme")
	if f := strings.Split(want, "|"); f[6] != adoptedProjectIncarnation("/acme") || f[5] == "" {
		t.Fatalf("converged row %s, want deleted and adopted", want)
	}
	for name, c := range map[string]*Client{"n": n, "l": l} {
		if got := projectRow(t, c, "/acme"); got != want {
			t.Errorf("%s holds %s, want %s", name, got, want)
		}
	}
	if b, err := GetRoleBinding(ctx, l, "only-l~p:pre"); err != nil || b == nil || b.Role != "Operator" {
		t.Errorf("l's pre-tagged grant after the adopted tombstone settled: %+v (err %v), want it untouched", b, err)
	}
	for name, c := range map[string]*Client{"r": r, "n": n, "l": l} {
		if got := c.UnresolvedTieCount(); got != 0 {
			t.Errorf("%s tracks %d unresolved ties: %v", name, got, c.UnresolvedTieTables())
		}
	}
}

// Review C3: a project deleted, revived before the latch (still "", same
// created_at) and then adopted stays live on a receiver that only ever saw
// the tombstone and takes the adoption by anti-entropy.
func TestProjectAdoption_ARevivedProjectStaysLive(t *testing.T) {
	ctx := context.Background()
	src := adoptionClient(t)
	legacyProject(t, src, "/acme")
	rcv := adoptionClient(t)
	rcv.SetProjectIncarnationGate(func() bool { return true })
	src.SetProjectIncarnationGate(func() bool { return false })
	if _, err := src.db.Exec(`DELETE FROM role_bindings`); err != nil {
		t.Fatal(err)
	}
	if err := DeleteProject(ctx, src, "/acme"); err != nil {
		t.Fatal(err)
	}
	walTo(t, src, "src", rcv) // the receiver holds the tombstone only
	if err := InsertProject(ctx, src, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	src.SetProjectIncarnationGate(func() bool { return true })
	if ok, err := AdoptProjectIncarnation(ctx, src, adoptGrant(t), "/acme"); err != nil || !ok {
		t.Fatalf("adopt: %v %v", ok, err)
	}
	aeBoth(t, src, rcv)
	if got := strings.Split(projectRow(t, rcv, "/acme"), "|"); got[5] != "" || got[6] != adoptedProjectIncarnation("/acme") {
		t.Fatalf("receiver row %v, want the revived project live and adopted", got)
	}
}

// A tie of two rows that differ only in incarnation, "" and the name's
// adopted value, resolves to the adopted one in both directions. Any other
// difference, or another value, is the policy chain's.
func TestProjectAdoption_TieRule(t *testing.T) {
	c := adoptionClient(t)
	cols := []string{"name", "display", "parent_name", "created_at", "updated_at", "deleted_at", "incarnation"}
	row := func(inc, display string) []interface{} {
		return []interface{}{"/acme", display, nil, "c", "u", "d", inc}
	}
	adopted := adoptedProjectIncarnation("/acme")
	for _, tc := range []struct {
		name                string
		local, incoming     []interface{}
		keepLocal, resolved bool
	}{
		{"local adopted", row(adopted, ""), row("", ""), true, true},
		{"incoming adopted", row("", ""), row(adopted, ""), false, true},
		{"another name's value", row("", ""), row(adoptedProjectIncarnation("/b"), ""), true, false},
		{"another difference too", row("", "x"), row(adopted, "y"), true, false},
		{"a born incarnation", row("", ""), row(newProjectIncarnation(true), ""), true, false},
	} {
		keep, unresolved, _ := c.resolveTie("projects", cols, tc.local, tc.incoming, []int{0}, pathAE)
		if keep != tc.keepLocal || unresolved == tc.resolved {
			t.Errorf("%s: keepLocal=%v unresolved=%v, want keepLocal=%v resolved=%v", tc.name, keep, unresolved, tc.keepLocal, tc.resolved)
		}
	}
}

// The orphan reaper's guard takes "" and the adopted value for one lifetime;
// a re-created name is still protected.
//
// Mutation: the guard by equality only — red.
func TestProjectAdoption_ReaperGuardTakesOneLifetime(t *testing.T) {
	ctx := context.Background()
	adopted := adoptedProjectIncarnation("/acme")
	for _, tc := range []struct {
		tomb, guard string
		want        bool
	}{
		{"", adopted, true}, {adopted, "", true}, {adopted, adopted, true}, {"", "", true},
		{newProjectIncarnation(false), "", false}, {newProjectIncarnation(false), adopted, false},
		{"", adoptedProjectIncarnation("/b"), false},
	} {
		c := adoptionClient(t)
		projectRowForVerdict(t, c, "/acme", tc.tomb, "2026-01-01T00:00:00Z")
		tx, err := c.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.projectIncarnationGuardMatches(ctx, tx, &MutationGuard{Protocol: projectIncarnationGuardV1,
			ResourceKind: projectGuardDeleted, ResourceID: "/acme", Incarnation: tc.guard})
		tx.Rollback()
		if err != nil || got != tc.want {
			t.Errorf("tombstone %q, guard %q: %v (err %v), want %v", tc.tomb, tc.guard, got, err, tc.want)
		}
	}
}

// Re-review M-1: a columnless dump (every row of its sender still "") is the
// same lifetime as a local adopted row, so its newer tombstone is taken by
// LWW; over a born incarnation it is still kept out.
//
// Mutation: projectsDumpDecision keeping any non-empty local — red.
func TestProjectAdoption_AColumnlessDumpMergesOverAnAdoptedRow(t *testing.T) {
	ctx := context.Background()
	old := adoptionClient(t)
	legacyProject(t, old, "/acme")
	cur := adoptionClient(t)
	cur.SetProjectIncarnationGate(func() bool { return true })
	walTo(t, old, "old", cur)
	if ok, err := AdoptProjectIncarnation(ctx, cur, adoptGrant(t), "/acme"); err != nil || !ok {
		t.Fatalf("adopt: %v %v", ok, err)
	}
	if _, err := old.db.Exec(`DELETE FROM role_bindings`); err != nil {
		t.Fatal(err)
	}
	old.SetProjectIncarnationGate(func() bool { return false })
	if err := DeleteProject(ctx, old, "/acme"); err != nil {
		t.Fatal(err)
	}
	dump := old.DumpStateBytes()
	if strings.Contains(string(dump), "incarnation") {
		t.Fatal("fixture: the dump carries the incarnation column")
	}
	if err := cur.MergeStateBytesLWW(dump); err != nil {
		t.Fatal(err)
	}
	if got := strings.Split(projectRow(t, cur, "/acme"), "|"); got[5] == "" {
		t.Fatalf("the newer tombstone of the same lifetime was kept out: %v", got)
	}
}

// The scan finds the live "" projects with one spelling, and names those with
// two live spellings as blocked; it skips born, adopted and default rows.
func TestScanProjectAdoption(t *testing.T) {
	ctx := context.Background()
	c := adoptionClient(t)
	for _, r := range []struct{ name, inc, del string }{
		{"/acme", "", ""}, {"/two", "", ""}, {"two", "r1", ""}, {"/born", "f1", ""},
		{"/adopted", adoptedProjectIncarnation("/adopted"), ""}, {"/gone", "", "2026-01-01T00:00:00Z"},
		{DefaultProject, "", ""},
	} {
		projectRowForVerdict(t, c, r.name, r.inc, r.del)
	}
	s, err := ScanProjectAdoption(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Candidates) != 1 || s.Candidates[0].Name != "/acme" || s.Candidates[0].UpdatedAt == "" {
		t.Errorf("candidates %+v, want /acme alone", s.Candidates)
	}
	if strings.Join(s.BlockedSpellings, ",") != "/two" {
		t.Errorf("blocked %v, want /two", s.BlockedSpellings)
	}
}

// Delete after adoption, then re-create: the new birth is r…, every grant of
// the pre-latch lifetime is held, and the adopted tombstone keeps pre-tagged
// grants out of retirement exactly as a "" tombstone does.
func TestProjectAdoption_ARecreateAfterAdoptionIsANewLifetime(t *testing.T) {
	ctx := context.Background()
	c := adoptionClient(t)
	legacyProject(t, c, "/acme")
	if ok, err := AdoptProjectIncarnation(ctx, c, adoptGrant(t), "/acme"); err != nil || !ok {
		t.Fatalf("adopt: %v %v", ok, err)
	}
	if err := DeleteProject(ctx, c, "/acme"); err != nil {
		t.Fatal(err)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	if inc := projectIncarnationOf(t, c, "/acme"); !strings.HasPrefix(inc, projectRebirth) {
		t.Fatalf("re-create incarnation %q, want a rebirth", inc)
	}
	tx, _ := c.db.Begin()
	v, err := projectParentVerdictTx(ctx, tx, "/acme", adoptedProjectIncarnation("/acme"))
	tx.Rollback()
	if err != nil || v != projectParentConflict {
		t.Fatalf("adopted parent after re-create: %v %v, want conflict", v, err)
	}
	bs, _ := ListRoleBindings(ctx, c)
	for _, b := range bs {
		if strings.HasPrefix(b.Path, "/projects/acme") && b.Role != SentinelRole && !b.Held {
			t.Errorf("%s grants on the re-created project", b.ID)
		}
	}
}

// The merge order (a paged-pull wire contract) is 4b13deaf1's: role_bindings,
// projects and project_quotas share one rank (re-review I1).
func TestProjectAdoption_MergeRankIsUnchanged(t *testing.T) {
	for _, tbl := range []string{"role_bindings", "projects", "project_quotas"} {
		if r := mergeDependencyRank(tbl); r != 2 {
			t.Errorf("mergeDependencyRank(%s) = %d, want 2", tbl, r)
		}
	}
}
