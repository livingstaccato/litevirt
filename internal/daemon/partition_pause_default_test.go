package daemon

import "testing"

// Partition pause is ON unless a host's config says otherwise
// (docs/design/partition-pause.md §5): the second exception to the
// default-false rule, beside audit_signature. An explicit false is the kill
// switch and must survive.
//
// Mutation: drop PartitionPause from LoadConfig's preset — every default case
// goes red; preset it in a way an explicit false cannot override — the last
// case goes red.
func TestLoadConfig_PartitionPauseDefaultsOn(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"no enforcement block", "", true},
		{"empty enforcement block", "enforcement:\n", true},
		{"enforcement block without the key", "enforcement:\n  recovery_claim: true\n", true},
		{"explicitly on", "enforcement:\n  partition_pause: true\n", true},
		{"explicitly off", "enforcement:\n  partition_pause: false\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustLoadConfigText(t, tc.text).Enforcement.PartitionPause; got != tc.want {
				t.Fatalf("Enforcement.PartitionPause = %v, want %v", got, tc.want)
			}
		})
	}
}

// enforcement.partition_pause_record_failure: empty is the default (pause),
// the three named values load, and a typo fails the load rather than
// silently picking a behaviour for a full disk.
//
// Mutation: drop the validation — the typo case loads and goes red.
func TestLoadConfig_PartitionPauseRecordFailure(t *testing.T) {
	for _, tc := range []struct {
		name, text, want string
		bad              bool
	}{
		{"unset", "", "", false},
		{"pause", "enforcement:\n  partition_pause_record_failure: pause\n", "pause", false},
		{"reserve", "enforcement:\n  partition_pause_record_failure: reserve\n", "reserve", false},
		{"self_fence", "enforcement:\n  partition_pause_record_failure: self_fence\n", "self_fence", false},
		{"typo", "enforcement:\n  partition_pause_record_failure: self-fence\n", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadConfigText(t, tc.text)
			if tc.bad {
				if err == nil {
					t.Fatalf("LoadConfig accepted %q", tc.text)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			if got := cfg.Enforcement.PartitionPauseRecordFailure; got != tc.want {
				t.Fatalf("PartitionPauseRecordFailure = %q, want %q", got, tc.want)
			}
		})
	}
}
