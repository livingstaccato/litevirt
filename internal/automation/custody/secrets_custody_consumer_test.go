package custody_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/litevirt/litevirt/internal/automation/custody"
)

func consumerBinding() custody.SecretBinding {
	return custody.SecretBinding{ClusterUID: "cluster", ProjectUID: "project", ResourceUID: "resource", OperationID: "operation", PayloadID: "payload", AdmittedGeneration: 7}
}

func consumerScope(host string) custody.CustodyScope {
	return custody.CustodyScope{ClusterUID: "cluster", HostID: host, HostIncarnation: 17, AdmittedAt: "2026-10-19T00:00:00Z"}
}

func consumerRef() custody.CustodyKeyRef {
	return custody.CustodyKeyRef{Epoch: "original", KeyID: "voter", Generation: 8, ConfigDigest: "config"}
}

func consumerStore(t *testing.T, path, host string) (*custody.LocalCustody, *custody.LocalVoterKey) {
	t.Helper()
	store, err := custody.CreateLocalCustody(path, consumerScope(host))
	if err != nil {
		t.Fatal("consumer store creation failed")
	}
	t.Cleanup(func() { store.Close() })
	key, err := store.CreateVoterIdentity(consumerRef())
	if err != nil {
		t.Fatal("consumer identity creation failed")
	}
	return store, key
}

func consumerDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("consumer private directory failed")
	}
	return dir
}

func consumerRecipient(t *testing.T, key *custody.LocalVoterKey) *age.X25519Recipient {
	t.Helper()
	recipient, err := age.ParseX25519Recipient(key.Recipient())
	if err != nil {
		t.Fatal("consumer public recipient failed")
	}
	return recipient
}

func consumerNoFiles(t *testing.T, files custody.EffectiveBootstrap, err error) {
	t.Helper()
	if !reflect.DeepEqual(files, custody.EffectiveBootstrap{}) || err == nil || err.Error() != "invalid bootstrap secret" {
		t.Fatal("consumer refusal returned files or nonfixed error")
	}
}

func consumerNoCiphertext(t *testing.T, ciphertext []byte, err error) {
	t.Helper()
	if ciphertext != nil || err == nil || err.Error() != "invalid bootstrap secret" {
		t.Fatal("consumer refusal returned ciphertext or nonfixed error")
	}
}

func TestAutomationCustodyConsumerExactFilesAfterReopen(t *testing.T) {
	dir := consumerDir(t)
	path := filepath.Join(dir, "stored")
	store, key := consumerStore(t, path, "survivor")
	recipient := consumerRecipient(t, key)
	if store.Close() != nil {
		t.Fatal("consumer store close failed")
	}
	reopened, err := custody.OpenLocalCustody(path, consumerScope("survivor"))
	if err != nil {
		t.Fatal("consumer store reopen failed")
	}
	defer reopened.Close()
	key, err = reopened.OpenVoterIdentity(consumerRef(), recipient.String())
	if err != nil {
		t.Fatal("consumer stored identity reopen failed")
	}
	for _, files := range []custody.EffectiveBootstrap{
		{},
		{UserData: []byte{}, Metadata: []byte{}, NetworkConfig: []byte{}, VendorData: []byte{}},
		{UserData: []byte{}, Metadata: nil, NetworkConfig: []byte{}, VendorData: nil},
		{UserData: nil, Metadata: []byte{}, NetworkConfig: nil, VendorData: []byte{}},
		{UserData: []byte("USER-SEED-MARKER\x00\xff\r\n"), Metadata: []byte("META-SEED-MARKER\r\n"), NetworkConfig: []byte("NETWORK-SEED-MARKER\x00\xfe"), VendorData: []byte("VENDOR-SEED-MARKER\r\n")},
	} {
		ciphertext, err := custody.EncryptBootstrap(consumerBinding(), files, []*age.X25519Recipient{recipient})
		if err != nil {
			t.Fatal("consumer envelope creation failed")
		}
		got, err := key.DecryptBootstrap(consumerBinding(), ciphertext)
		if err != nil || !reflect.DeepEqual(got, files) {
			t.Fatal("consumer changed exact files or presence")
		}
	}
}

func TestAutomationCustodyConsumerSurvivingProcessRewrap(t *testing.T) {
	// Follow the existing custody subprocess-reopen pattern. The child receives
	// only surviving B/C stores and public metadata, never A's opaque handle.
	if dir := os.Getenv("LITEVIRT_CUSTODY_CONSUMER_DIR"); dir != "" {
		store, err := custody.OpenLocalCustody(filepath.Join(dir, "b"), consumerScope("b"))
		if err != nil {
			t.Fatal("survivor store reopen failed")
		}
		defer store.Close()
		key, err := store.OpenVoterIdentity(consumerRef(), os.Getenv("LITEVIRT_CUSTODY_CONSUMER_B"))
		if err != nil {
			t.Fatal("survivor stored identity reopen failed")
		}
		// A's directory has been removed before this process starts.
		if _, err := os.Stat(filepath.Join(dir, "a")); !os.IsNotExist(err) {
			t.Fatal("entry custody remained available to survivor")
		}
		ciphertext, err := os.ReadFile(filepath.Join(dir, "original.age"))
		if err != nil {
			t.Fatal("survivor envelope read failed")
		}
		files, err := key.DecryptBootstrap(consumerBinding(), ciphertext)
		if err != nil || !reflect.DeepEqual(files, consumerSurvivorFiles()) {
			t.Fatal("survivor did not recover original files")
		}
		replacement, err := age.ParseX25519Recipient(os.Getenv("LITEVIRT_CUSTODY_CONSUMER_C"))
		if err != nil {
			t.Fatal("replacement public recipient failed")
		}
		original := bytes.Clone(ciphertext)
		rewrapped, err := key.RewrapBootstrap(consumerBinding(), ciphertext, []*age.X25519Recipient{replacement})
		if err != nil || !bytes.Equal(ciphertext, original) || os.WriteFile(filepath.Join(dir, "replacement.age"), rewrapped, 0600) != nil {
			t.Fatal("survivor rewrap failed")
		}
		return
	}
	dir := consumerDir(t)
	aStore, a := consumerStore(t, filepath.Join(dir, "a"), "a")
	bStore, b := consumerStore(t, filepath.Join(dir, "b"), "b")
	_, c := consumerStore(t, filepath.Join(dir, "c"), "c")
	ciphertext, err := custody.EncryptBootstrap(consumerBinding(), consumerSurvivorFiles(), []*age.X25519Recipient{consumerRecipient(t, a), consumerRecipient(t, b)})
	if err != nil || os.WriteFile(filepath.Join(dir, "original.age"), ciphertext, 0600) != nil {
		t.Fatal("original envelope creation failed")
	}
	original := bytes.Clone(ciphertext)
	if aStore.Close() != nil || bStore.Close() != nil || os.RemoveAll(filepath.Join(dir, "a")) != nil {
		t.Fatal("entry custody removal failed")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal("consumer executable unavailable")
	}
	cmd := exec.Command(exe, "-test.run=^TestAutomationCustodyConsumerSurvivingProcessRewrap$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), "LITEVIRT_CUSTODY_CONSUMER_DIR="+dir, "LITEVIRT_CUSTODY_CONSUMER_B="+b.Recipient(), "LITEVIRT_CUSTODY_CONSUMER_C="+c.Recipient())
	if err = cmd.Run(); err != nil {
		t.Fatal("surviving consumer process failed")
	}
	rewrapped, err := os.ReadFile(filepath.Join(dir, "replacement.age"))
	if err != nil || bytes.Equal(rewrapped, original) {
		t.Fatal("replacement envelope missing or unchanged")
	}
	got, err := c.DecryptBootstrap(consumerBinding(), rewrapped)
	if err != nil || !reflect.DeepEqual(got, consumerSurvivorFiles()) {
		t.Fatal("replacement recipient lost original files")
	}
	for _, removed := range []*custody.LocalVoterKey{a, b} {
		files, err := removed.DecryptBootstrap(consumerBinding(), rewrapped)
		consumerNoFiles(t, files, err)
		// Old copies remain decryptable; rewrapping does not revoke them.
		files, err = removed.DecryptBootstrap(consumerBinding(), original)
		if err != nil || !reflect.DeepEqual(files, consumerSurvivorFiles()) {
			t.Fatal("rewrap changed access to original envelope")
		}
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, "original.age"))
	if err != nil || !bytes.Equal(onDisk, original) || !bytes.Equal(ciphertext, original) {
		t.Fatal("rewrap mutated original envelope")
	}
}

func consumerSurvivorFiles() custody.EffectiveBootstrap {
	return custody.EffectiveBootstrap{UserData: []byte("USER-SEED-MARKER\r\n"), Metadata: []byte{}, NetworkConfig: nil, VendorData: []byte("VENDOR-SEED-MARKER\x00\xff")}
}

func TestAutomationCustodyConsumerRefusesWithoutPartialFiles(t *testing.T) {
	dir := consumerDir(t)
	_, key := consumerStore(t, filepath.Join(dir, "owner"), "owner")
	_, wrong := consumerStore(t, filepath.Join(dir, "other"), "other")
	files := custody.EffectiveBootstrap{UserData: bytes.Repeat([]byte("PRIVATE-SEED-MARKER"), 8192), Metadata: []byte{}, NetworkConfig: nil, VendorData: []byte("VENDOR-SEED-MARKER")}
	ciphertext, err := custody.EncryptBootstrap(consumerBinding(), files, []*age.X25519Recipient{consumerRecipient(t, key)})
	if err != nil {
		t.Fatal("consumer refusal envelope creation failed")
	}
	tampered := bytes.Clone(ciphertext)
	tampered[len(tampered)-1] ^= 1
	wrongBinding := consumerBinding()
	wrongBinding.PayloadID = "other-payload"
	for _, tc := range []struct {
		name       string
		key        *custody.LocalVoterKey
		binding    custody.SecretBinding
		ciphertext []byte
	}{
		{"wrong-key", wrong, consumerBinding(), ciphertext},
		{"wrong-original-binding", key, wrongBinding, ciphertext},
		{"tampered-final-chunk", key, consumerBinding(), tampered},
		{"truncated-final-chunk", key, consumerBinding(), ciphertext[:len(ciphertext)-1]},
		{"nil-handle", nil, consumerBinding(), ciphertext},
		{"empty-handle", &custody.LocalVoterKey{}, consumerBinding(), ciphertext},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.key.DecryptBootstrap(tc.binding, tc.ciphertext)
			consumerNoFiles(t, got, err)
			rewrapped, err := tc.key.RewrapBootstrap(tc.binding, tc.ciphertext, []*age.X25519Recipient{consumerRecipient(t, wrong)})
			consumerNoCiphertext(t, rewrapped, err)
		})
	}
	for _, recipients := range [][]*age.X25519Recipient{nil, {nil}, {consumerRecipient(t, wrong), consumerRecipient(t, wrong)}} {
		rewrapped, err := key.RewrapBootstrap(consumerBinding(), ciphertext, recipients)
		consumerNoCiphertext(t, rewrapped, err)
	}
	for _, value := range []any{key, (*custody.LocalVoterKey)(nil), &custody.LocalVoterKey{}} {
		shown := fmt.Sprintf("%v %+v %#v", value, value, value)
		if strings.Contains(shown, "AGE-SECRET") || strings.Contains(shown, "SEED-MARKER") {
			t.Fatal("consumer presentation disclosed private material")
		}
	}
}
