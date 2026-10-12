package compose

import (
	"strconv"
	"strings"
	"testing"
)

// migrate.priority is an int32 in the stored spec; a value outside that range
// is refused at parse instead of wrapping (2147483648 would have become the
// LOWEST priority). Mutation: drop the range check — the out-of-range cases
// parse and the test goes red.
func TestParseBytes_MigratePriorityRange(t *testing.T) {
	doc := func(p string) []byte {
		return []byte("name: s\nvms:\n  web:\n    image: nginx\n    cpu: 1\n    memory: 512\n    migrate:\n      priority: " + p + "\n")
	}
	for _, ok := range []string{"0", "100", "-5", "2147483647", "-2147483648"} {
		f, err := ParseBytes(doc(ok))
		if err != nil {
			t.Errorf("priority %s: %v", ok, err)
			continue
		}
		if got := f.VMs["web"].Migrate.Priority; strconv.Itoa(got) != ok {
			t.Errorf("priority %s parsed as %d", ok, got)
		}
	}
	for _, bad := range []string{"2147483648", "-2147483649"} {
		_, err := ParseBytes(doc(bad))
		if err == nil || !strings.Contains(err.Error(), "migrate.priority") {
			t.Errorf("priority %s: want a migrate.priority range error, got %v", bad, err)
		}
	}
}
