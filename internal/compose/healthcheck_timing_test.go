package compose

import "testing"

const hcTCP = hcVM + "      type: tcp\n      target: \"22\"\n"

// interval and timeout must be durations greater than zero, a timeout must
// not outlast the interval, and retries must be at least 1. Each problem
// names its field, in the same format as every other.
func TestHealthcheck_TimingIsValidated(t *testing.T) {
	for _, c := range []struct{ extra, path, msg, hint string }{
		{"      interval: \"10\"\n", "vms.web.healthcheck.interval", `interval "10" is not a duration`, `add a unit, e.g. "10s"`},
		{"      interval: soon\n", "vms.web.healthcheck.interval", `interval "soon" is not a duration`, `e.g. "10s" or "1m"`},
		{"      interval: 0s\n", "vms.web.healthcheck.interval", "interval must be greater than 0", ""},
		{"      timeout: -1s\n", "vms.web.healthcheck.timeout", "timeout must be greater than 0", ""},
		{"      timeout: 5\n", "vms.web.healthcheck.timeout", `timeout "5" is not a duration`, `add a unit, e.g. "5s"`},
		{"      interval: 10s\n      timeout: 30s\n", "vms.web.healthcheck.timeout", "timeout 30s exceeds interval 10s", "lower timeout or raise interval"},
		{"      timeout: 30s\n", "vms.web.healthcheck.timeout", "timeout 30s exceeds interval 10s (the default)", "lower timeout or raise interval"},
		{"      retries: 0\n", "vms.web.healthcheck.retries", "retries must be at least 1", "omit it for the default, 3"},
		{"      retries: -2\n", "vms.web.healthcheck.retries", "retries must be at least 1", "omit it for the default, 3"},
	} {
		ps := problemsOf(t, hcTCP+c.extra)
		p, ok := findProblem(ps, c.path, c.msg)
		if !ok {
			t.Errorf("%s: no problem %q at %s; got:\n%s", c.extra, c.msg, c.path, dumpProblems(ps))
			continue
		}
		if p.Message != c.msg || p.Hint != c.hint {
			t.Errorf("%s: got %q — %q, want %q — %q", c.extra, p.Message, p.Hint, c.msg, c.hint)
		}
	}
}

func TestHealthcheck_TimingThatIsFine(t *testing.T) {
	for _, extra := range []string{
		"",                     // every default
		"      interval: 2s\n", // the default timeout is not held against a short interval
		"      interval: 1ms\n      retries: 1\n",
		"      interval: 1m\n      timeout: 1m\n      retries: 5\n",
	} {
		if _, err := ParseBytes([]byte(hcTCP + extra)); err != nil {
			t.Errorf("%q refused: %v", extra, err)
		}
	}
}

// Stored stacks are not re-judged by checks added after they were deployed.
func TestParseStored_SkipsTimingChecks(t *testing.T) {
	if _, err := ParseStored([]byte(hcTCP + "      retries: 0\n      interval: \"10\"\n")); err != nil {
		t.Errorf("ParseStored refused stored timing: %v", err)
	}
}
