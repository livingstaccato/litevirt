package automation

import "testing"

func TestAutomationIdentitySubmissionRequiresActualProvider(t *testing.T) {
	c := Command{Kind: "ensure_owner", ClusterUID: "cluster", ProjectUID: "project", PrincipalID: "principal", OwnerID: "owner", RequestID: "request", Body: []byte(`{"version":1}`)}
	if err := validateCommand(c); Code(err) != CodeUnavailable {
		t.Fatalf("business Submit must remain closed before recovery/lookup/assignment without actual admission provider: %v", err)
	}
}
