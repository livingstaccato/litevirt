package daemon

import "testing"

// enforcement.project_adoption defaults on; only an explicit false turns it
// off.
func TestLoadConfig_ProjectAdoptionDefaultsOn(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"no enforcement block", "", true},
		{"empty enforcement block", "enforcement:\n", true},
		{"enforcement block without the key", "enforcement:\n  partition_pause: true\n", true},
		{"explicitly on", "enforcement:\n  project_adoption: true\n", true},
		{"explicitly off", "enforcement:\n  project_adoption: false\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustLoadConfigText(t, tc.text).Enforcement.ProjectAdoption; got != tc.want {
				t.Fatalf("Enforcement.ProjectAdoption = %v, want %v", got, tc.want)
			}
		})
	}
}
