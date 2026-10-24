package custody_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/custody"
)

func provisionRef() custody.CustodyProvisionRef {
	return custody.CustodyProvisionRef{Attempt: "attempt", Voter: consumerRef(), Equality: custody.CustodyKeyRef{Epoch: "equality", KeyID: "eq", Generation: 8, ConfigDigest: "config"}}
}

// Replacing an immutable continuation or trusting an in-memory response would
// break the restart identity asserted by this actual child-process reopen.
func TestCustodyProvisionImmutableProcessReopen(t *testing.T) {
	if path := os.Getenv("LITEVIRT_CUSTODY_PROVISION_TEST"); path != "" {
		s, err := custody.OpenLocalCustody(path, consumerScope("target"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		for _, phase := range []string{"plan", "recipient", "completion"} {
			got, err := s.ReadProvisionRecord(provisionRef(), phase)
			if err != nil || !bytes.Equal(got, []byte(`{"phase":"`+phase+`"}`)) {
				t.Fatal("child did not reopen exact continuation")
			}
		}
		return
	}
	path := filepath.Join(consumerDir(t), "stored")
	s, _ := consumerStore(t, path, "target")
	for _, phase := range []string{"plan", "recipient", "completion"} {
		body := []byte(`{"phase":"` + phase + `"}`)
		if err := s.SaveProvisionRecord(provisionRef(), phase, body); err != nil {
			t.Fatal(err)
		}
		if err := s.SaveProvisionRecord(provisionRef(), phase, body); err != nil {
			t.Fatal("identical retry refused")
		}
		if err := s.SaveProvisionRecord(provisionRef(), phase, []byte(`{"different":true}`)); err == nil {
			t.Fatal("immutable continuation replaced")
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCustodyProvisionImmutableProcessReopen$")
	cmd.Env = append(os.Environ(), "LITEVIRT_CUSTODY_PROVISION_TEST="+path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child reopen failed: %v %s", err, out)
	}
}

func TestCustodyProvisionRejectsWrongPurposeAndOversize(t *testing.T) {
	s, _ := consumerStore(t, filepath.Join(consumerDir(t), "stored"), "target")
	for _, phase := range []string{"../material", "material", "", "plan/recipient"} {
		if err := s.SaveProvisionRecord(provisionRef(), phase, []byte(`{}`)); err == nil {
			t.Fatal("unallocated phase admitted")
		}
	}
	if err := s.SaveProvisionRecord(provisionRef(), "completion", bytes.Repeat([]byte{'x'}, 1<<20)); err == nil {
		t.Fatal("overbound aggregate metadata admitted")
	}
	if _, err := s.ReadProvisionRecord(provisionRef(), "completion"); err == nil {
		t.Fatal("missing continuation manufactured")
	}
}
