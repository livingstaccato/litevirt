package corrosion

import (
	"strings"
	"testing"
)

// The pending-admin message reads right for one name and for several, and
// points a directory admin at mark-external (int-followups review m-4).
func TestAdminCredentialPendingError_Wording(t *testing.T) {
	one := (&AdminCredentialPendingError{Usernames: []string{"bob"}}).Error()
	if !strings.Contains(one, `whether admin "bob" can log in: its credential has`) || !strings.Contains(one, "lv user mark-external bob") {
		t.Errorf("one name: %q", one)
	}
	two := (&AdminCredentialPendingError{Usernames: []string{"a", "b"}}).Error()
	if !strings.Contains(two, `whether admins "a", "b" can log in: their credentials have`) {
		t.Errorf("two names: %q", two)
	}
}
