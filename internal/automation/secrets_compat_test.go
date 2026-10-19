package automation_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"filippo.io/age"
	"github.com/litevirt/litevirt/internal/automation"
	"github.com/litevirt/litevirt/internal/automation/custody"
)

// A facade that changes a binding, file presence or argument order must break
// these real cross-package round trips.
func TestAutomationSecretCompatibility(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("native identity generation failed")
	}
	binding := automation.SecretBinding{ClusterUID: "cluster", ProjectUID: "project", ResourceUID: "resource", OperationID: "operation", PayloadID: "payload", AdmittedGeneration: 7}
	var leafBinding custody.SecretBinding = binding
	var parentBinding automation.SecretBinding = leafBinding
	for _, files := range []automation.EffectiveBootstrap{
		{},
		{UserData: []byte{}, Metadata: []byte{}, NetworkConfig: []byte{}, VendorData: []byte{}},
		{UserData: []byte("user\x00\xff\r\n"), Metadata: []byte("meta\r\n"), NetworkConfig: []byte("network\x00"), VendorData: []byte("vendor\xff\r\n")},
		{UserData: []byte{}, Metadata: []byte("meta"), NetworkConfig: nil, VendorData: []byte{}},
	} {
		var leafFiles custody.EffectiveBootstrap = files
		ciphertext, err := automation.EncryptBootstrap(parentBinding, files, []*age.X25519Recipient{id.Recipient()})
		if err != nil {
			t.Fatal("parent encryption failed")
		}
		opened, err := custody.DecryptBootstrap(leafBinding, ciphertext, []*age.X25519Identity{id})
		if err != nil || !reflect.DeepEqual(opened, leafFiles) {
			t.Fatal("parent to leaf changed exact files or presence")
		}
		ciphertext, err = custody.EncryptBootstrap(leafBinding, leafFiles, []*age.X25519Recipient{id.Recipient()})
		if err != nil {
			t.Fatal("leaf encryption failed")
		}
		var parentFiles automation.EffectiveBootstrap
		parentFiles, err = automation.DecryptBootstrap(parentBinding, ciphertext, []*age.X25519Identity{id})
		if err != nil || !reflect.DeepEqual(parentFiles, files) {
			t.Fatal("leaf to parent changed exact files or presence")
		}
		wrong := leafBinding
		wrong.AdmittedGeneration++
		if opened, err := custody.DecryptBootstrap(wrong, ciphertext, []*age.X25519Identity{id}); err == nil || !reflect.DeepEqual(opened, custody.EffectiveBootstrap{}) {
			t.Fatal("cross-package decryption released files for the wrong binding")
		}
		if opened, err := automation.DecryptBootstrap(parentBinding, ciphertext[:len(ciphertext)-1], []*age.X25519Identity{id}); err == nil || !reflect.DeepEqual(opened, automation.EffectiveBootstrap{}) {
			t.Fatal("parent facade released unauthenticated partial files")
		}
	}

	material := bytes.Repeat([]byte{42}, 32)
	parentKey, err := automation.NewBootstrapEqualityKey("epoch", material)
	if err != nil {
		t.Fatal("parent equality import failed")
	}
	leafKey, err := custody.NewBootstrapEqualityKey("epoch", material)
	if err != nil {
		t.Fatal("leaf equality import failed")
	}
	var aliasedLeafKey custody.BootstrapEqualityKey = parentKey
	var aliasedParentKey automation.BootstrapEqualityKey = leafKey
	scope := automation.IntentScope{ClusterUID: "cluster", Namespace: "namespace", Method: "create"}
	raw := automation.RawBootstrapIntent{Present: true, UserData: []byte{}, Metadata: []byte("raw\r\n"), NetworkConfig: nil}
	var leafScope custody.IntentScope = scope
	var leafRaw custody.RawBootstrapIntent = raw
	tag, err := aliasedParentKey.IntentTag("epoch", scope, raw)
	if err != nil {
		t.Fatal("parent equality tag failed")
	}
	if equal, err := aliasedLeafKey.CompareIntent("epoch", leafScope, leafRaw, tag); err != nil || !equal {
		t.Fatal("cross-package equality receipt changed")
	}
	leafRaw.UserData = nil
	if equal, err := leafKey.CompareIntent("epoch", leafScope, leafRaw, tag); err != nil || equal {
		t.Fatal("cross-package equality lost raw file presence")
	}
}

// Reopening through the other public package must retain the original native
// recipient and equality material, including immutable import retry semantics.
func TestAutomationCustodyCompatibility(t *testing.T) {
	for _, parentCreates := range []bool{true, false} {
		name := "leaf-create-parent-reopen"
		if parentCreates {
			name = "parent-create-leaf-reopen"
		}
		t.Run(name, func(t *testing.T) {
			parent, err := os.MkdirTemp("/var/tmp", "litevirt-custody-compat-")
			if err != nil {
				t.Fatal("private custody parent unavailable")
			}
			t.Cleanup(func() { os.RemoveAll(parent) })
			path := filepath.Join(parent, "custody")
			scope := automation.CustodyScope{ClusterUID: "cluster", HostID: "host", HostIncarnation: 17, AdmittedAt: "2026-10-19T00:00:00Z"}
			var leafScope custody.CustodyScope = scope
			var store *automation.LocalCustody
			if parentCreates {
				store, err = automation.CreateLocalCustody(path, scope)
			} else {
				store, err = custody.CreateLocalCustody(path, leafScope)
			}
			if err != nil {
				t.Fatal("custody create failed")
			}
			defer store.Close()
			var leafStore *custody.LocalCustody = store
			ref := automation.CustodyKeyRef{Epoch: "epoch", KeyID: "key", Generation: 8, ConfigDigest: "config"}
			var leafRef custody.CustodyKeyRef = ref
			key, err := leafStore.CreateVoterIdentity(leafRef)
			if err != nil {
				t.Fatal("native voter identity create failed")
			}
			var parentKey *automation.LocalVoterKey = key
			var leafKey *custody.LocalVoterKey = parentKey
			recipient := leafKey.Recipient()
			if _, err := age.ParseX25519Recipient(recipient); err != nil || parentKey.String() != "local voter custody" || leafKey.GoString() != "local voter custody" {
				t.Fatal("native recipient or redacted methods changed")
			}
			material := bytes.Repeat([]byte{42}, 32)
			equality, err := store.ImportEqualityKey(ref, material)
			if err != nil {
				t.Fatal("file-backed equality import failed")
			}
			intentScope := automation.IntentScope{ClusterUID: "cluster", Namespace: "namespace", Method: "create"}
			raw := automation.RawBootstrapIntent{Present: true, UserData: []byte{}}
			tag, err := equality.IntentTag("epoch", intentScope, raw)
			if err != nil {
				t.Fatal("file-backed equality tag failed")
			}
			generatedRef := ref
			generatedRef.KeyID = "generated"
			generated, err := store.GenerateEqualityKey(generatedRef)
			if err != nil {
				t.Fatal("file-backed equality generation failed")
			}
			generatedTag, err := generated.IntentTag("epoch", intentScope, raw)
			if err != nil {
				t.Fatal("generated equality tag failed")
			}
			if err := store.Close(); err != nil {
				t.Fatal("custody close failed")
			}
			if parentCreates {
				store, err = custody.OpenLocalCustody(path, leafScope)
			} else {
				store, err = automation.OpenLocalCustody(path, scope)
			}
			if err != nil {
				t.Fatal("cross-package reopen failed")
			}
			defer store.Close()
			restored, err := store.OpenVoterIdentity(ref, recipient)
			if err != nil || restored.Recipient() != recipient {
				t.Fatal("reopen changed native voter identity")
			}
			for _, candidate := range []struct {
				ref automation.CustodyKeyRef
				tag []byte
			}{{ref, tag}, {generatedRef, generatedTag}} {
				opened, err := store.OpenEqualityKey(candidate.ref)
				if err != nil {
					t.Fatal("reopen lost equality material")
				}
				if equal, err := opened.CompareIntent("epoch", intentScope, raw, candidate.tag); err != nil || !equal {
					t.Fatal("reopen changed equality receipt")
				}
			}
			if _, err := store.ImportEqualityKey(ref, material); err != nil {
				t.Fatal("exact immutable equality retry failed")
			}
			if _, err := store.ImportEqualityKey(ref, bytes.Repeat([]byte{43}, 32)); err != automation.ErrCustodyConflict || err != custody.ErrCustodyConflict {
				t.Fatal("different equality material did not preserve conflict identity")
			}
		})
	}

	for _, pair := range [][2]error{
		{automation.ErrCustodyUnavailable, custody.ErrCustodyUnavailable},
		{automation.ErrCustodyCorrupt, custody.ErrCustodyCorrupt},
		{automation.ErrCustodyConflict, custody.ErrCustodyConflict},
		{automation.ErrCustodyRecoveryRequired, custody.ErrCustodyRecoveryRequired},
	} {
		if pair[0] != pair[1] || !errors.Is(pair[0], pair[1]) {
			t.Fatal("facade changed exported error identity")
		}
	}
	parent, err := os.MkdirTemp("/var/tmp", "litevirt-custody-errors-")
	if err != nil {
		t.Fatal("private custody parent unavailable")
	}
	defer os.RemoveAll(parent)
	scope := automation.CustodyScope{ClusterUID: "cluster", HostID: "host", HostIncarnation: 17, AdmittedAt: "2026-10-19T00:00:00Z"}
	if _, err := automation.OpenLocalCustody(filepath.Join(parent, "missing"), scope); err != custody.ErrCustodyUnavailable {
		t.Fatal("missing root changed unavailable identity")
	}
	if _, err := automation.CreateLocalCustody(filepath.Join(parent, "invalid"), automation.CustodyScope{}); err != custody.ErrCustodyCorrupt {
		t.Fatal("invalid scope changed corrupt identity")
	}
	incomplete := filepath.Join(parent, "incomplete")
	if err := os.Mkdir(incomplete, 0700); err != nil {
		t.Fatal("incomplete root setup failed")
	}
	if _, err := automation.OpenLocalCustody(incomplete, scope); err != custody.ErrCustodyRecoveryRequired {
		t.Fatal("incomplete root changed recovery identity")
	}
	if _, err := automation.CreateLocalCustody(incomplete, scope); err != custody.ErrCustodyConflict {
		t.Fatal("occupied root changed conflict identity")
	}
}

func TestAutomationSecretWrappingDoesNotEnterRetryIdentity(t *testing.T) {
	key, err := automation.NewBootstrapEqualityKey("epoch", bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal("valid equality key refused")
	}
	scope := automation.IntentScope{ClusterUID: "cluster", Namespace: "namespace", Method: "CreateVM"}
	raw := automation.RawBootstrapIntent{Present: true, UserData: []byte("raw")}
	tag, err := key.IntentTag("epoch", scope, raw)
	if err != nil {
		t.Fatal("tag failed")
	}
	a, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("identity generation failed")
	}
	b, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("identity generation failed")
	}
	binding := automation.SecretBinding{ClusterUID: "cluster", ProjectUID: "project", ResourceUID: "resource", OperationID: "operation", PayloadID: "payload", AdmittedGeneration: 7}
	files := automation.EffectiveBootstrap{UserData: []byte("effective"), Metadata: []byte("generated")}
	first, err := automation.EncryptBootstrap(binding, files, []*age.X25519Recipient{a.Recipient()})
	if err != nil {
		t.Fatal("encrypt failed")
	}
	second, err := automation.EncryptBootstrap(binding, files, []*age.X25519Recipient{b.Recipient()})
	if err != nil {
		t.Fatal("rewrap failed")
	}
	c := automation.Command{Kind: "admit_create", ClusterUID: "cluster", ProjectUID: "project", PrincipalID: "principal", OwnerID: "owner", ManagementKey: "key", RequestID: "request", ResourceUID: "resource", Body: []byte(`{"version":1}`), Ciphertext: first, SecretIntentTag: tag, SecretKeyEpoch: "epoch"}
	original, err := automation.CanonicalCommand(c)
	if err != nil {
		t.Fatal("canonical intent failed")
	}
	c.Ciphertext = second
	c.Session++
	changed, err := automation.CanonicalCommand(c)
	if err != nil || !bytes.Equal(original, changed) {
		t.Fatal("wrapping or session changed immutable retry identity")
	}
}
