package automation

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestAutomationSecretVendorSeedDelivery(t *testing.T) {
	if _, err := exec.LookPath("genisoimage"); err != nil {
		t.Fatal("required genisoimage unavailable")
	}
	inspector, err := exec.LookPath("isoinfo")
	if err != nil {
		t.Fatal("required isoinfo unavailable")
	}
	binding := SecretBinding{ClusterUID: "cluster", ProjectUID: "project", ResourceUID: "resource", OperationID: "operation", PayloadID: "payload", AdmittedGeneration: 7}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("native identity generation failed")
	}
	for _, vendor := range [][]byte{nil, {}, []byte("vendor-delivery\r\n\x00\xff")} {
		files := EffectiveBootstrap{UserData: []byte{}, Metadata: []byte("instance-id: resource\r\nlocal-hostname: admitted\r\n"), NetworkConfig: []byte{}, VendorData: vendor}
		cipher, err := EncryptBootstrap(binding, files, []*age.X25519Recipient{id.Recipient()})
		if err != nil {
			t.Fatal("delivery encryption failed")
		}
		opened, err := DecryptBootstrap(binding, cipher, []*age.X25519Identity{id})
		if err != nil {
			t.Fatal("delivery decryption failed")
		}
		out := filepath.Join(t.TempDir(), "seed.iso")
		if err := WriteBootstrapISO(opened, out); err != nil {
			t.Fatal("exact delivery failed")
		}
		listing, err := exec.Command(inspector, "-R", "-i", out, "-f").Output()
		if err != nil {
			t.Fatal("ISO listing failed")
		}
		names := map[string]bool{}
		for _, n := range strings.Fields(string(listing)) {
			names[n] = true
		}
		for name, want := range map[string][]byte{"user-data": files.UserData, "meta-data": files.Metadata, "network-config": files.NetworkConfig, "vendor-data": files.VendorData} {
			if names["/"+name] != (want != nil) {
				t.Errorf("encrypted delivery changed presence: %s", name)
				continue
			}
			if want == nil {
				continue
			}
			got, err := exec.Command(inspector, "-R", "-i", out, "-x", "/"+name).Output()
			if err != nil || !bytes.Equal(got, want) {
				t.Errorf("encrypted delivery changed bytes: %s", name)
			}
		}
	}
}
