package daemon

import (
	"testing"
	"time"
)

func TestParseSMARTInterval(t *testing.T) {
	for in, want := range map[string]time.Duration{"": time.Hour, "0": 0, "off": 0, "15m": 15 * time.Minute, "bogus": time.Hour, "-5m": time.Hour, "1s": 10 * time.Minute, "9m59s": 10 * time.Minute, "10m": 10 * time.Minute} {
		if got := parseSMARTInterval(in); got != want {
			t.Errorf("%q = %v want %v", in, got, want)
		}
	}
}
