package corrosion

import (
	"context"
	"testing"
)

// If the legacy-rule write fails, the group must still be live: a retry of the
// delete finds it, and the rules are not stranded for a later group to adopt.
func TestDeleteSecurityGroupWithLegacyRules_AtomicOnSecondWriteFailure(t *testing.T) {
	ctx := context.Background()
	db := NewTestClientT(t)
	if err := InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	sg := SecurityGroup{ID: "sg-1", Name: "web"}
	if err := InsertSecurityGroup(ctx, db, sg); err != nil {
		t.Fatal(err)
	}
	if err := InsertSGRule(ctx, db, SGRule{ID: "legacy", SGID: "web", Direction: "ingress"}); err != nil {
		t.Fatal(err)
	}
	// Inject the failure: the name-keyed rule tombstone aborts.
	if err := db.Execute(ctx, `CREATE TRIGGER fail_legacy BEFORE UPDATE ON sg_rules
		WHEN NEW.sg_id = 'web' BEGIN SELECT RAISE(ABORT, 'injected'); END`); err != nil {
		t.Fatal(err)
	}
	if err := DeleteSecurityGroupWithLegacyRules(ctx, db, sg); err == nil {
		t.Fatal("expected the injected failure")
	}
	if got, _ := GetSecurityGroup(ctx, db, "sg-1"); got == nil {
		t.Fatal("group was tombstoned although the legacy-rule write failed; a retry would get NotFound and strand the rules")
	}
	if err := db.Execute(ctx, `DROP TRIGGER fail_legacy`); err != nil {
		t.Fatal(err)
	}
	if err := DeleteSecurityGroupWithLegacyRules(ctx, db, sg); err != nil {
		t.Fatal(err)
	}
	if got, _ := GetSecurityGroup(ctx, db, "sg-1"); got != nil {
		t.Error("group still live after the retry")
	}
	if rules, _ := ListSGRules(ctx, db, "web"); len(rules) != 0 {
		t.Errorf("legacy rules survived: %v", rules)
	}
}
