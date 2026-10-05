package health

import "testing"

// A VM a host drain stopped for a cold move carries the move's own detail,
// and every decision treats it as an operator stop: a crash-like stop under it
// (the drain's own shutdown) is never restarted. Anything else that merely
// resembles it is not.
//
// Mutation: IsOperatorStop recognises only "operator-stop" — the drain's stop
// is restarted under policy "always" and goes red.
func TestDrainStopDetailIsAnOperatorStop(t *testing.T) {
	d := DrainStopDetail("0123abcd")
	if !IsOperatorStop(d) || !IsOperatorStop(operatorStopDetail) {
		t.Fatalf("IsOperatorStop(%q)=%t, IsOperatorStop(operator-stop)=%t; want both true", d, IsOperatorStop(d), IsOperatorStop(operatorStopDetail))
	}
	for _, other := range []string{"", "crashed", "drain-cold-move", "operator-stopped"} {
		if IsOperatorStop(other) {
			t.Errorf("IsOperatorStop(%q) = true, want false", other)
		}
	}
	if restart, reason := restartDecision("destroyed", d, false, "always"); restart {
		t.Fatalf("a VM stopped by a drain's cold move would be restarted (%s)", reason)
	}
}
