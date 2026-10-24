package custody_test

import (
	"bytes"
	"encoding/json"
	"filippo.io/age"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/custody"
)

func transferFixture(t *testing.T) (*custody.LocalCustody, *custody.LocalCustody, custody.EqualityImportBinding, []byte) {
	t.Helper()
	dir := consumerDir(t)
	donor, _ := consumerStore(t, filepath.Join(dir, "donor"), "donor")
	target, key := consumerStore(t, filepath.Join(dir, "target"), "target")
	ref := custody.CustodyKeyRef{Epoch: "equality", KeyID: "eq-donor", Generation: 8, ConfigDigest: "config"}
	material := []byte("secret-equality-material-canary!")
	if _, err := donor.ImportEqualityKey(ref, material); err != nil {
		t.Fatal(err)
	}
	b := custody.EqualityImportBinding{Source: consumerScope("donor"), Target: consumerScope("target"), SourceVoter: "db-donor", TargetVoter: "db-target", VoterRef: consumerRef(), SourceEquality: ref, TargetEquality: custody.CustodyKeyRef{Epoch: "equality", KeyID: "eq-target", Generation: 8, ConfigDigest: "config"}, Recipient: key.Recipient(), Attempt: "attempt", ExpiresAt: "2026-10-24T01:00:00Z"}
	return donor, target, b, material
}

// A transfer must import the donor's exact material, never regenerate a key.
func TestCustodyEqualityTransferReopensExactMaterial(t *testing.T) {
	donor, target, b, material := transferFixture(t)
	capsule, err := donor.SealEqualityImport(b.SourceEquality, b, b.Recipient)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(capsule, material) {
		t.Fatal("plaintext equality material escaped")
	}
	for i := 0; i < 2; i++ {
		if err := target.ImportSealedEquality(b.VoterRef, b.Recipient, b.TargetEquality, b, capsule); err != nil {
			t.Fatal(err)
		}
	}
	got, err := target.OpenEqualityKey(b.TargetEquality)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := custody.NewBootstrapEqualityKey("equality", material)
	if err != nil {
		t.Fatal(err)
	}
	scope := custody.IntentScope{ClusterUID: "cluster", Namespace: "request", Method: "create"}
	raw := custody.RawBootstrapIntent{Present: true, UserData: []byte("private-intent")}
	tag, err := expected.IntentTag("equality", scope, raw)
	if err != nil {
		t.Fatal(err)
	}
	if match, err := got.CompareIntent("equality", scope, raw, tag); err != nil || !match {
		t.Fatal("import did not preserve exact equality material")
	}
}

// These inputs must fail without leaving usable material. The separate binding
// mutant establishes causality; malformed ciphertext is also refused by age.
func TestCustodyEqualityTransferRefusesChangedBindingOrCiphertext(t *testing.T) {
	for _, name := range []string{"admission", "target", "voter", "attempt", "expiry", "epoch", "truncated", "suffix", "corrupt"} {
		t.Run(name, func(t *testing.T) {
			donor, target, b, _ := transferFixture(t)
			capsule, err := donor.SealEqualityImport(b.SourceEquality, b, b.Recipient)
			if err != nil {
				t.Fatal(err)
			}
			changed := b
			switch name {
			case "admission":
				changed.Target.AdmittedAt = "2026-10-19T00:00:00.000Z"
			case "target":
				changed.Target.HostID = "different"
			case "voter":
				changed.TargetVoter = "different"
			case "attempt":
				changed.Attempt = "different"
			case "expiry":
				changed.ExpiresAt = "2026-10-24T01:00:01Z"
			case "epoch":
				changed.TargetEquality.Epoch = "different"
			case "truncated":
				capsule = capsule[:len(capsule)-1]
			case "suffix":
				capsule = append(capsule, 0)
			case "corrupt":
				capsule[len(capsule)-1] ^= 1
			}
			err = target.ImportSealedEquality(b.VoterRef, b.Recipient, b.TargetEquality, changed, capsule)
			if err == nil {
				t.Fatal("changed transfer imported")
			}
			if strings.Contains(err.Error(), "private-intent") {
				t.Fatal("secret error")
			}
			if _, err := target.OpenEqualityKey(b.TargetEquality); err == nil {
				t.Fatal("failed transfer left usable key")
			}
		})
	}
}

// The sender can authenticate arbitrary plaintext with the public recipient.
// Authentication alone therefore cannot substitute for the complete canonical
// import record. The exact fixture body first proves that this reaches import.
func TestCustodyEqualityTransferCompleteCanonicalPlaintext(t *testing.T) {
	for _, suffix := range []string{"", " ", "{}"} {
		t.Run("suffix="+suffix, func(t *testing.T) {
			_, target, b, material := transferFixture(t)
			body, err := json.Marshal(struct {
				Version  int
				Purpose  string
				Binding  custody.EqualityImportBinding
				Material []byte
			}{1, "automation-equality-import", b, material})
			if err != nil {
				t.Fatal(err)
			}
			recipient, err := age.ParseX25519Recipient(b.Recipient)
			if err != nil {
				t.Fatal(err)
			}
			var ciphertext bytes.Buffer
			writer, err := age.Encrypt(&ciphertext, recipient)
			if err != nil {
				t.Fatal(err)
			}
			plaintext := append([]byte("litevirt/automation/equality-import/v1\x00"), body...)
			plaintext = append(plaintext, suffix...)
			if _, err = writer.Write(plaintext); err != nil {
				t.Fatal(err)
			}
			if err = writer.Close(); err != nil {
				t.Fatal(err)
			}
			err = target.ImportSealedEquality(b.VoterRef, b.Recipient, b.TargetEquality, b, ciphertext.Bytes())
			if suffix == "" {
				if err != nil {
					t.Fatal("canonical authenticated fixture refused", err)
				}
			} else {
				if err == nil {
					t.Fatal("authenticated trailing plaintext imported")
				}
				if _, err = target.OpenEqualityKey(b.TargetEquality); err == nil {
					t.Fatal("noncanonical import left usable material")
				}
			}
		})
	}
}
