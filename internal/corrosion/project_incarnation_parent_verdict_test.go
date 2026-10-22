package corrosion

import (
	"context"
	"testing"
)

// projectRowForVerdict writes one projects row directly: a live row when
// deletedAt is "", else a tombstone.
func projectRowForVerdict(t *testing.T, c *Client, name, inc, deletedAt string) {
	t.Helper()
	var del interface{}
	if deletedAt != "" {
		del = deletedAt
	}
	if _, err := c.db.Exec(`INSERT INTO projects (name, display, parent_name, created_at, updated_at, deleted_at, incarnation)
		VALUES (?, '', NULL, '2026-01-01T00:00:00Z', ?, ?, ?)`, name, c.NowTS(), del, inc); err != nil {
		t.Fatalf("insert project row %q: %v", name, err)
	}
}

// A parent is judged by equality only. Current needs exactly one live
// spelling of the canonical name, spelled as asked, holding the incarnation
// asked; any other live state is Conflict, never "newer". No live row is
// Absent, a tombstone exactly as no row at all. The default project has no
// row by design and is Current only for its constant. A live row still
// holding "" is Unadopted whatever is asked.
//
// Mutations (each red here): tombstones counted as spellings ("tombstone
// beside the live spelling"); tombstones counted as live ("tombstone only
// ..."); the >1 live spelling check dropped ("two spellings ..."); any live
// spelling's incarnation accepted ("two spellings ...", "other spelling
// ..."); the spelling check dropped ("other spelling ..."); the incarnation
// compared by prefix or ignored ("another incarnation" and the "asked of"
// cases); the default shortcut dropped ("_default ...", "root"); an error
// returned with Current ("invalid name"); Current made the zero verdict.
func TestProjectParentVerdict_EqualityOnly(t *testing.T) {
	const (
		incA = "f0123456789abcdef0123456789abcdef"
		incB = "r0123456789abcdef0123456789abcdef"
	)
	var zero projectParentVerdict
	if zero == projectParentCurrent {
		t.Fatal("the zero verdict is Current: a caller that drops an error would read a parent as current")
	}
	type row struct{ name, inc, deletedAt string }
	const dead = "2026-02-01T00:00:00Z"
	cases := []struct {
		name    string
		rows    []row
		ask     string
		inc     string
		want    projectParentVerdict
		wantErr bool
	}{
		{"live and equal", []row{{"/acme", incA, ""}}, "/acme", incA, projectParentCurrent, false},
		{"legacy spelling live and equal", []row{{"acme", incA, ""}}, "acme", incA, projectParentCurrent, false},
		{"another incarnation", []row{{"/acme", incB, ""}}, "/acme", incA, projectParentConflict, false},
		{"pre-latch '' asked of ''", []row{{"/acme", "", ""}}, "/acme", "", projectParentUnadopted, false},
		{"marker asked of a '' row", []row{{"/acme", "", ""}}, "/acme", incA, projectParentUnadopted, false},
		{"adopted asked of a '' row", []row{{"/acme", "", ""}}, "/acme", adoptedProjectIncarnation("/acme"), projectParentUnadopted, false},
		{"adopted row and its incarnation", []row{{"/acme", adoptedProjectIncarnation("/acme"), ""}}, "/acme", adoptedProjectIncarnation("/acme"), projectParentCurrent, false},
		{"'' asked of an adopted row", []row{{"/acme", adoptedProjectIncarnation("/acme"), ""}}, "/acme", "", projectParentConflict, false},
		{"another name's adopted incarnation", []row{{"/acme", adoptedProjectIncarnation("/acme"), ""}}, "/acme", adoptedProjectIncarnation("/other"), projectParentConflict, false},
		{"'' asked of a marker row", []row{{"/acme", incA, ""}}, "/acme", "", projectParentConflict, false},
		{"prefix of the incarnation", []row{{"/acme", incA, ""}}, "/acme", incA[:1], projectParentConflict, false},
		{"two spellings holding the same marker", []row{{"/acme", incA, ""}, {"acme", incA, ""}}, "/acme", incA, projectParentConflict, false},
		{"two spellings holding '', asked by the legacy one", []row{{"/acme", "", ""}, {"acme", "", ""}}, "acme", "", projectParentConflict, false},
		{"other spelling live with the incarnation", []row{{"/acme", incA, ""}}, "acme", incA, projectParentConflict, false},
		{"tombstone beside the live spelling", []row{{"acme", incB, dead}, {"/acme", incA, ""}}, "/acme", incA, projectParentCurrent, false},
		{"tombstone only, holding the incarnation", []row{{"/acme", incA, dead}}, "/acme", incA, projectParentAbsent, false},
		{"tombstone only, holding ''", []row{{"/acme", "", dead}}, "/acme", "", projectParentAbsent, false},
		{"no row", []row{{"/other", incA, ""}}, "/acme", incA, projectParentAbsent, false},
		{"no row, '' asked", nil, "/acme", "", projectParentAbsent, false},
		{"child is its own name", []row{{"/acme", incA, ""}}, "/acme/team", incA, projectParentAbsent, false},
		{"_default and its constant", nil, DefaultProject, defaultProjectIncarnation, projectParentCurrent, false},
		{"_default asked with ''", nil, DefaultProject, "", projectParentConflict, false},
		{"_default even with a row", []row{{DefaultProject, incB, ""}}, DefaultProject, incB, projectParentConflict, false},
		{"/_default", nil, "/" + DefaultProject, defaultProjectIncarnation, projectParentCurrent, false},
		{"/_default asked with another", nil, "/" + DefaultProject, incA, projectParentConflict, false},
		// "/" is accepted only as the canonical form of "", the default
		// project in stored rows; the root itself is not a project.
		{"root, as the canonical form of ''", nil, "/", defaultProjectIncarnation, projectParentCurrent, false},
		{"empty name", nil, "", defaultProjectIncarnation, projectParentCurrent, false},
		{"empty name asked with ''", nil, "", "", projectParentConflict, false},
		{"invalid name", []row{{"/acme", incA, ""}}, "/acme/../x", incA, projectParentUnknown, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := NewTestClientT(t)
			if err := InitSchema(ctx, c); err != nil {
				t.Fatalf("InitSchema: %v", err)
			}
			for _, r := range tc.rows {
				projectRowForVerdict(t, c, r.name, r.inc, r.deletedAt)
			}
			tx, err := c.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			got, err := projectParentVerdictTx(ctx, tx, tc.ask, tc.inc)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("verdict(%q, %q) = %v, want %v", tc.ask, tc.inc, got, tc.want)
			}
		})
	}
}

// The verdict follows the owner's own writes: a latched first birth is
// Current under its incarnation, a delete makes it Absent, and a re-create is
// a new incarnation, so the old one is a Conflict and never "older".
func TestProjectParentVerdict_FollowsTheLifecycle(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	c.SetProjectIncarnationGate(func() bool { return true })
	verdict := func(name, inc string) projectParentVerdict {
		t.Helper()
		tx, err := c.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		v, err := projectParentVerdictTx(ctx, tx, name, inc)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	first := projectIncarnationOf(t, c, "/acme")
	if got := verdict("/acme", first); got != projectParentCurrent {
		t.Fatalf("after create: %v, want current", got)
	}
	if err := DeleteProject(ctx, c, "/acme"); err != nil {
		t.Fatal(err)
	}
	if got := verdict("/acme", first); got != projectParentAbsent {
		t.Fatalf("after delete: %v, want absent", got)
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatal(err)
	}
	second := projectIncarnationOf(t, c, "/acme")
	if got := verdict("/acme", first); got != projectParentConflict {
		t.Fatalf("old incarnation after re-create: %v, want conflict", got)
	}
	if got := verdict("/acme", second); got != projectParentCurrent {
		t.Fatalf("new incarnation after re-create: %v, want current", got)
	}
}
