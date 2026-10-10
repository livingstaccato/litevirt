package main

import (
	"strings"
	"testing"
)

// I8: the CLI never sends a container's bare name as a schedule's vm_name. A
// daemon that predates container schedules reads an unknown scope's vm_name as
// a VM name; a key ("@ct:...") is a name no VM can have, so such a daemon can
// never act on the VM schedule of the same name.
func TestContainerScheduleRef_NeverABareName(t *testing.T) {
	for _, tc := range []struct{ project, name, want string }{
		{"", "web", "@ct:web"},
		{"prod", "web", "@ct:prod/web"},
	} {
		got := containerScheduleRef(tc.project, tc.name)
		if got != tc.want || !strings.HasPrefix(got, "@ct:") {
			t.Errorf("containerScheduleRef(%q, %q) = %q, want %q", tc.project, tc.name, got, tc.want)
		}
	}
}
