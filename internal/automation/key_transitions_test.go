package automation

import (
	"context"
	"encoding/json"
	"testing"
)

func TestAutomationKeyTransitionEngineRefusesWithoutProvider(t *testing.T) {
	engine := NewEngine("a", nil, nil, nil)
	for _, kind := range []string{"rewrap_payload", "activate_key_epoch"} {
		_, err := engine.Submit(context.Background(), Command{Kind: kind, ClusterUID: "cluster", PrincipalID: "a", RequestID: "request", Body: []byte(`{"version":1}`)})
		if Code(err) != CodeUnsupported {
			t.Fatalf("historical recognition opened fresh proposer: %v", err)
		}
	}
}

func TestAutomationKeyTransitionPreservesSecretBindingEncoding(t *testing.T) {
	raw, err := json.Marshal(SecretBinding{ClusterUID: "c", ProjectUID: "p", ResourceUID: "r", OperationID: "o", PayloadID: "payload", AdmittedGeneration: 7})
	if err != nil || string(raw) != `{"ClusterUID":"c","ProjectUID":"p","ResourceUID":"r","OperationID":"o","PayloadID":"payload","AdmittedGeneration":7}` {
		t.Fatal("shared binding changed existing JSON encoding")
	}
}
