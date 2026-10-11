package corrosion

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
)

func groupSession(id, realm string, created, exp time.Time) SessionRecord {
	return SessionRecord{ID: id, Username: "olga", Realm: realm, CreatedAt: created.Format(time.RFC3339),
		LastUsedAt: created.Format(time.RFC3339), ExpiresAt: exp.Format(time.RFC3339)}
}

// TestSessionGroups_RecordedWithTheSessionOnlyWithTheGrant: the groups go in
// the session's own batch with the login_policy grant; without it the session
// is written alone. A read for another realm finds none.
func TestSessionGroups_RecordedWithTheSessionOnlyWithTheGrant(t *testing.T) {
	ctx := context.Background()
	c := lifecycleDB(t)
	now := time.Now().UTC()
	if err := InsertSessionWithLoginData(ctx, c, lpGrant(t), groupSession("s1", "oidc:corp", now, now.Add(time.Hour)), "", []string{"ops", " ops ", "", "dev"}); err != nil {
		t.Fatal(err)
	}
	g, err := SessionGroups(ctx, c, "s1", "oidc:corp")
	if err != nil || strings.Join(g, ",") != "dev,ops" {
		t.Fatalf("groups %v %v, want the normalized set dev,ops", g, err)
	}
	if g, _ := SessionGroups(ctx, c, "s1", "oidc:other"); g != nil {
		t.Fatalf("groups read for another realm: %v", g)
	}
	if err := InsertSessionWithLoginData(ctx, c, capabilities.FeatureGrant{}, groupSession("s2", "oidc:corp", now, now.Add(time.Hour)), "", []string{"ops"}); err != nil {
		t.Fatal(err)
	}
	if s, _ := GetSession(ctx, c, "s2"); s == nil {
		t.Fatal("the session was not written without the grant")
	}
	if g, _ := SessionGroups(ctx, c, "s2", "oidc:corp"); g != nil {
		t.Fatalf("groups %v recorded without the grant", g)
	}
}

func TestNormalizeSessionGroups_Bounds(t *testing.T) {
	var many []string
	for i := 0; i < MaxSessionGroups+10; i++ {
		many = append(many, strings.Repeat("g", 3)+string(rune('a'+i%26))+strings.Repeat("x", i/26))
	}
	many = append(many, strings.Repeat("y", MaxSessionGroupBytes+1), "bad\nname")
	out, dropped := NormalizeSessionGroups(many)
	if len(out) != MaxSessionGroups || dropped != 12 {
		t.Fatalf("kept %d dropped %d, want %d and 12", len(out), dropped, MaxSessionGroups)
	}
}

// TestGC_PrunesSessionGroupsWithTheirSessions: like session_factors.
func TestGC_PrunesSessionGroupsWithTheirSessions(t *testing.T) {
	ctx := context.Background()
	c := lifecycleDB(t)
	old := time.Now().Add(-48 * time.Hour).UTC()
	now := time.Now().UTC()
	if err := InsertSessionWithLoginData(ctx, c, lpGrant(t), groupSession("dead", "oidc:corp", old, old.Add(time.Hour)), "", []string{"ops"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertSessionWithLoginData(ctx, c, lpGrant(t), groupSession("live", "oidc:corp", now, now.Add(time.Hour)), "", []string{"ops"}); err != nil {
		t.Fatal(err)
	}
	if _, err := GCSupersededRows(ctx, c, time.Hour, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	rows, err := c.Query(ctx, `SELECT session_id AS k FROM session_groups`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].String("k") != "live" {
		t.Fatalf("session_groups after GC: %v, want only live", rows)
	}
}
