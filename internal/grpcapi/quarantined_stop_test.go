package grpcapi

import (
	"strings"
	"testing"
)

// A forced stop refused under release probation says it lifts by itself; one
// refused under a rollback quarantine says to upgrade or reseed. Probation
// needs neither, so the rollback remedy would send an operator to rebuild a
// host that is about to recover on its own.
//
// Mutation: return the upgrade/reseed remedy unconditionally — the
// probation case goes red.
func TestQuarantinedForceStopRefusal_RemedyBySource(t *testing.T) {
	s := testServer(t)
	if err := s.quarantinedForceStopRefusal("web", true); err != nil {
		t.Fatalf("unquarantined: %v", err)
	}

	s.db.EnterReleaseProbation([]string{"release_2099_01_v1"})
	err := s.quarantinedForceStopRefusal("web", true)
	if err == nil || !strings.Contains(err.Error(), "lifts by itself") || strings.Contains(err.Error(), "reseed") {
		t.Errorf("probation refusal: %v, want the remedy that it lifts by itself", err)
	}
	if err := s.quarantinedForceStopRefusal("web", false); err != nil {
		t.Errorf("a graceful stop is refused under probation: %v", err)
	}

	s.db.SetWriteQuarantine(func() string { return "rolled back below latched token(s): x" })
	err = s.quarantinedForceStopRefusal("web", true)
	if err == nil || !strings.Contains(err.Error(), "reseed the host") || strings.Contains(err.Error(), "lifts by itself") {
		t.Errorf("rollback refusal: %v, want the upgrade/reseed remedy", err)
	}
}
