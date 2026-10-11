package main

import (
	"strings"
	"testing"
)

// The request is checked before any connection is made: a call that names no
// limit and no --clear would otherwise silently clear every limit, and one that
// names both is contradictory.
func TestDiskIO_RefusesAnEmptyOrContradictoryRequest(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"nothing named":  {[]string{"vm1"}, "name at least one limit"},
		"clear + limit":  {[]string{"vm1", "--clear", "--read-iops", "5"}, "--clear cannot be combined"},
		"bad byte rate":  {[]string{"vm1", "--read-bps", "fast"}, "--read-bps"},
		"too many words": {[]string{"vm1", "vm2"}, "accepts 1 arg"},
	} {
		cmd := newDiskIOCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs(tc.args)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want one containing %q", name, err, tc.want)
		}
	}
}
