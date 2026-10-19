package custody_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/litevirt/litevirt/internal/automation/custody"
)

func TestAutomationCustodyLifetimeN0CurrentAPI(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal("SETUP_N0_PRIVATE_PARENT")
	}
	scope := custody.CustodyScope{ClusterUID: "cluster", HostID: "host", HostIncarnation: 0, AdmittedAt: "2026-10-19T00:00:00Z"}
	store, err := custody.CreateLocalCustody(filepath.Join(parent, "custody"), scope)
	if store != nil {
		defer store.Close()
	}
	if errors.Is(err, custody.ErrCustodyCorrupt) {
		t.Fatal("RED_N0_CREATE_REJECTED_VALID_ZERO")
	}
	if err != nil || store == nil {
		t.Fatal("SETUP_N0_UNEXPECTED_CREATE_RESULT")
	}
	if err := store.Close(); err != nil {
		t.Fatal("SETUP_N0_CLOSE_FAILED")
	}
}

// Frozen original local-custody-v1 bytes: no current writer or private codec
// constructs this fixture. This is unrelated to bootstrap-payload-v1 support.
const frozenCustodyV1Scope = `{"Version":1,"Purpose":"scope","Scope":{"ClusterUID":"cluster","HostID":"host","HostIncarnation":17},"Ref":{"Epoch":"","KeyID":"","Generation":0,"ConfigDigest":""},"Material":null}`
const frozenCustodyV1KeyName = "key-a688c329dacafbda55a732b2d07850c5aee768a7fe24a55dd658331875f753b4"
const frozenCustodyV1Material = `{"Version":1,"Purpose":"equality","Scope":{"ClusterUID":"cluster","HostID":"host","HostIncarnation":17},"Ref":{"Epoch":"epoch-old","KeyID":"key","Generation":8,"ConfigDigest":"config"},"Material":"RlJPWkVOLVYxLU1BVEVSSUFMLVNFTlRJTkVMLTAwMDA="}`
const frozenCustodyV1Sentinel = "FROZEN-V1-MATERIAL-SENTINEL-0000"

func assertFrozenCustodyV1Unchanged(t *testing.T, path string) {
	t.Helper()
	for _, dir := range []struct {
		path string
		name string
	}{{path, "scope"}, {filepath.Join(path, frozenCustodyV1KeyName), "material"}} {
		info, err := os.Lstat(dir.path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatal("SETUP_LEGACY_DIRECTORY_MODE_CHANGED")
		}
		entries, err := os.ReadDir(dir.path)
		if err != nil {
			t.Fatal("SETUP_LEGACY_DIRECTORY_UNREADABLE")
		}
		if dir.path == path {
			if len(entries) != 2 || entries[0].Name() != frozenCustodyV1KeyName || entries[1].Name() != "scope" {
				t.Fatal("SETUP_LEGACY_ROOT_NAMES_CHANGED")
			}
		} else if len(entries) != 1 || entries[0].Name() != dir.name {
			t.Fatal("SETUP_LEGACY_MATERIAL_NAMES_CHANGED")
		}
	}
	for _, file := range []struct {
		path string
		body string
	}{{filepath.Join(path, "scope"), frozenCustodyV1Scope}, {filepath.Join(path, frozenCustodyV1KeyName, "material"), frozenCustodyV1Material}} {
		info, err := os.Lstat(file.path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("SETUP_LEGACY_FILE_MODE_CHANGED")
		}
		body, err := os.ReadFile(file.path)
		if err != nil || !bytes.Equal(body, []byte(file.body)) {
			t.Fatal("SETUP_LEGACY_FILE_BYTES_CHANGED")
		}
	}
}

func TestAutomationCustodyLegacyRecordRefusal(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal("SETUP_LEGACY_PRIVATE_PARENT")
	}
	path := filepath.Join(parent, "custody")
	keyPath := filepath.Join(path, frozenCustodyV1KeyName)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal("SETUP_LEGACY_ROOT_CREATE")
	}
	if err := os.Mkdir(keyPath, 0700); err != nil {
		t.Fatal("SETUP_LEGACY_KEY_DIRECTORY_CREATE")
	}
	if err := os.WriteFile(filepath.Join(path, "scope"), []byte(frozenCustodyV1Scope), 0600); err != nil {
		t.Fatal("SETUP_LEGACY_SCOPE_WRITE")
	}
	if err := os.WriteFile(filepath.Join(keyPath, "material"), []byte(frozenCustodyV1Material), 0600); err != nil {
		t.Fatal("SETUP_LEGACY_MATERIAL_WRITE")
	}
	assertFrozenCustodyV1Unchanged(t, path)
	t.Cleanup(func() { assertFrozenCustodyV1Unchanged(t, path) })
	scope := custody.CustodyScope{ClusterUID: "cluster", HostID: "host", HostIncarnation: 17, AdmittedAt: "2026-10-19T00:00:00Z"}
	if occupied, err := custody.CreateLocalCustody(path, scope); occupied != nil || !errors.Is(err, custody.ErrCustodyConflict) {
		if occupied != nil {
			occupied.Close()
		}
		t.Fatal("occupied legacy root was treated as fresh custody")
	}
	store, err := custody.OpenLocalCustody(path, scope)
	if store != nil {
		defer store.Close()
	}
	if err == nil {
		if store == nil {
			t.Fatal("SETUP_LEGACY_NIL_STORE")
		}
		// On the old implementation, prove this is genuine usable v1 material
		// before reporting the intended refusal failure.
		ref := custody.CustodyKeyRef{Epoch: "epoch-old", KeyID: "key", Generation: 8, ConfigDigest: "config"}
		opened, err := store.OpenEqualityKey(ref)
		if err != nil {
			t.Fatal("SETUP_LEGACY_MATERIAL_NOT_USABLE")
		}
		expected, err := custody.NewBootstrapEqualityKey("epoch-old", []byte(frozenCustodyV1Sentinel))
		if err != nil {
			t.Fatal("SETUP_LEGACY_SENTINEL_INVALID")
		}
		intentScope := custody.IntentScope{ClusterUID: "cluster", Namespace: "namespace", Method: "CreateVM"}
		raw := custody.RawBootstrapIntent{Present: true, UserData: []byte("raw")}
		tag, err := expected.IntentTag("epoch-old", intentScope, raw)
		if err != nil {
			t.Fatal("SETUP_LEGACY_SENTINEL_TAG")
		}
		if equal, err := opened.CompareIntent("epoch-old", intentScope, raw, tag); err != nil || !equal {
			t.Fatal("SETUP_LEGACY_SENTINEL_MISMATCH")
		}
		t.Fatal("RED_LEGACY_V1_OPENED_INSTEAD_OF_RECOVERY")
	}
	if store != nil || !errors.Is(err, custody.ErrCustodyRecoveryRequired) {
		t.Fatal("SETUP_LEGACY_UNEXPECTED_OPEN_RESULT")
	}
}

func TestAutomationCustodyLifetimeRejectsInvalidScope(t *testing.T) {
	valid := custody.CustodyScope{ClusterUID: "cluster", HostID: "host", HostIncarnation: 17, AdmittedAt: "2026-10-19T00:00:00Z"}
	for _, candidate := range []struct {
		name   string
		mutate func(*custody.CustodyScope)
	}{
		{"missing-at", func(s *custody.CustodyScope) { s.AdmittedAt = "" }},
		{"oversized-at", func(s *custody.CustodyScope) { s.AdmittedAt = "2026-10-19T00:00:00." + strings.Repeat("0", 4096) + "Z" }},
		{"malformed-at", func(s *custody.CustodyScope) { s.AdmittedAt = "not-a-timestamp" }},
		{"whitespace-at", func(s *custody.CustodyScope) { s.AdmittedAt += " " }},
		{"invalid-utf8-at", func(s *custody.CustodyScope) { s.AdmittedAt = "\xff" }},
		{"host-number-overflow", func(s *custody.CustodyScope) { s.HostIncarnation = uint64(math.MaxInt64) + 1 }},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			parent := t.TempDir()
			if err := os.Chmod(parent, 0700); err != nil {
				t.Fatal("SETUP_SCOPE_PRIVATE_PARENT")
			}
			scope := valid
			candidate.mutate(&scope)
			path := filepath.Join(parent, "custody")
			store, err := custody.CreateLocalCustody(path, scope)
			if store != nil {
				defer store.Close()
			}
			if err == nil && store != nil {
				t.Fatal("RED_INVALID_SCOPE_WAS_ACCEPTED")
			}
			if candidate.name == "invalid-utf8-at" && store == nil && errors.Is(err, custody.ErrCustodyConflict) {
				t.Fatal("RED_INVALID_UTF8_REACHED_RECORD_CONFLICT")
			}
			if store != nil || !errors.Is(err, custody.ErrCustodyCorrupt) {
				t.Fatal("SETUP_SCOPE_UNEXPECTED_CREATE_RESULT")
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("SETUP_SCOPE_INVALID_CREATED_FILES")
			}
		})
	}
}

type lifetimeFile struct {
	mode os.FileMode
	body string
}

func lifetimeSnapshot(t *testing.T, path string) map[string]lifetimeFile {
	t.Helper()
	files := make(map[string]lifetimeFile)
	err := filepath.WalkDir(path, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(path, name)
		if err != nil {
			return err
		}
		file := lifetimeFile{mode: info.Mode()}
		if !entry.IsDir() {
			if !info.Mode().IsRegular() {
				t.Fatal("unexpected nonregular lifetime fixture")
			}
			body, err := os.ReadFile(name)
			if err != nil {
				return err
			}
			file.body = string(body)
		}
		files[relative] = file
		return nil
	})
	if err != nil {
		t.Fatal("lifetime fixture snapshot failed")
	}
	return files
}

func TestAutomationCustodyLifetimeExactAtAndReopen(t *testing.T) {
	for numberName, number := range map[string]uint64{"zero": 0, "max": math.MaxInt64} {
		seenNames := make(map[string]bool)
		for _, spelling := range []struct {
			name string
			at   string
		}{
			{"whole-seconds", "2026-10-19T00:00:00Z"},
			{"fractional-zero", "2026-10-19T00:00:00.000000000Z"},
			{"zero-offset", "2026-10-19T00:00:00+00:00"},
		} {
			t.Run(numberName+"-"+spelling.name, func(t *testing.T) {
				parent := t.TempDir()
				if err := os.Chmod(parent, 0700); err != nil {
					t.Fatal("private lifetime parent unavailable")
				}
				path := filepath.Join(parent, "custody")
				scope := custody.CustodyScope{ClusterUID: "cluster", HostID: "host", HostIncarnation: number, AdmittedAt: spelling.at}
				store, err := custody.CreateLocalCustody(path, scope)
				if err != nil {
					t.Fatal("valid exact lifetime was rejected")
				}
				defer store.Close()
				ref := custody.CustodyKeyRef{Epoch: "epoch", KeyID: "key", Generation: 8, ConfigDigest: "config"}
				key, err := store.ImportEqualityKey(ref, bytes.Repeat([]byte{42}, 32))
				if err != nil {
					t.Fatal("exact lifetime equality import failed")
				}
				voter, err := store.CreateVoterIdentity(ref)
				if err != nil {
					t.Fatal("exact lifetime voter generation failed")
				}
				recipient := voter.Recipient()
				intentScope := custody.IntentScope{ClusterUID: "cluster", Namespace: "namespace", Method: "CreateVM"}
				raw := custody.RawBootstrapIntent{Present: true, UserData: []byte{}}
				tag, err := key.IntentTag("epoch", intentScope, raw)
				if err != nil {
					t.Fatal("exact lifetime receipt failed")
				}
				before := lifetimeSnapshot(t, path)
				for name, file := range before {
					if file.mode.IsDir() {
						if name != "." {
							if seenNames[name] {
								t.Fatal("different exact At spellings shared a key path")
							}
							seenNames[name] = true
						}
						continue
					}
					var record struct {
						Version uint32
						Scope   custody.CustodyScope
					}
					if json.Unmarshal([]byte(file.body), &record) != nil || record.Version != 2 || record.Scope != scope {
						t.Fatal("root or material lost the exact v2 lifetime")
					}
				}
				if err := store.Close(); err != nil {
					t.Fatal("exact lifetime close failed")
				}
				for _, changedAt := range []string{"2026-10-19T00:00:01Z", "2026-10-19T00:00:00.000Z"} {
					changed := scope
					changed.AdmittedAt = changedAt
					wrong, err := custody.OpenLocalCustody(path, changed)
					if wrong != nil {
						wrong.Close()
					}
					if wrong != nil || !errors.Is(err, custody.ErrCustodyConflict) {
						t.Fatal("same N with changed exact At did not conflict")
					}
				}
				opened, err := custody.OpenLocalCustody(path, scope)
				if err != nil {
					t.Fatal("exact v2 lifetime reopen failed")
				}
				defer opened.Close()
				restored, err := opened.OpenVoterIdentity(ref, recipient)
				if err != nil || restored.Recipient() != recipient {
					t.Fatal("v2 lifetime reopen lost the native identity")
				}
				recovered, err := opened.OpenEqualityKey(ref)
				if err != nil {
					t.Fatal("v2 lifetime reopen lost equality material")
				}
				if equal, err := recovered.CompareIntent("epoch", intentScope, raw, tag); err != nil || !equal {
					t.Fatal("v2 lifetime reopen changed equality receipt")
				}
				if !reflect.DeepEqual(before, lifetimeSnapshot(t, path)) {
					t.Fatal("exact lifetime reopen changed files or modes")
				}
			})
		}
	}
}

func TestAutomationCustodyLifetimeMalformedRecordRefusal(t *testing.T) {
	for name, body := range map[string]string{
		"unknown-version":    strings.Replace(frozenCustodyV1Scope, `"Version":1`, `"Version":3`, 1),
		"noncanonical-v1":    frozenCustodyV1Scope + "\n",
		"unknown-v1-field":   strings.Replace(frozenCustodyV1Scope, `"HostIncarnation":17`, `"HostIncarnation":17,"AdmittedAt":"2026-10-19T00:00:00Z"`, 1),
		"duplicate-version":  strings.Replace(frozenCustodyV1Scope, `"Version":1`, `"Version":1,"Version":1`, 1),
		"missing-host":       strings.Replace(frozenCustodyV1Scope, `"HostID":"host",`, "", 1),
		"invalid-old-number": strings.Replace(frozenCustodyV1Scope, `"HostIncarnation":17`, `"HostIncarnation":0`, 1),
		"unknown-purpose":    strings.Replace(frozenCustodyV1Scope, `"Purpose":"scope"`, `"Purpose":"other"`, 1),
		"invalid-material":   strings.Replace(frozenCustodyV1Material, `"Material":"RlJPWkVOLVYxLU1BVEVSSUFMLVNFTlRJTkVMLTAwMDA="`, `"Material":"YQ=="`, 1),
		"trailing-json":      frozenCustodyV1Scope + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			if err := os.Chmod(parent, 0700); err != nil {
				t.Fatal("malformed fixture parent failed")
			}
			path := filepath.Join(parent, "custody")
			if os.Mkdir(path, 0700) != nil || os.WriteFile(filepath.Join(path, "scope"), []byte(body), 0600) != nil {
				t.Fatal("malformed fixture setup failed")
			}
			before := lifetimeSnapshot(t, path)
			scope := custody.CustodyScope{ClusterUID: "cluster", HostID: "host", HostIncarnation: 17, AdmittedAt: "2026-10-19T00:00:00Z"}
			store, err := custody.OpenLocalCustody(path, scope)
			if store != nil {
				store.Close()
			}
			if store != nil || !errors.Is(err, custody.ErrCustodyCorrupt) {
				t.Fatal("malformed or unknown record was classified as recoverable")
			}
			if !reflect.DeepEqual(before, lifetimeSnapshot(t, path)) {
				t.Fatal("malformed record was rewritten")
			}
		})
	}
}

func TestAutomationCustodyLifetimeMixedV1MaterialRefusal(t *testing.T) {
	for _, purpose := range []string{"equality", "voter-identity"} {
		t.Run(purpose, func(t *testing.T) {
			parent := t.TempDir()
			if os.Chmod(parent, 0700) != nil {
				t.Fatal("mixed fixture parent failed")
			}
			path := filepath.Join(parent, "custody")
			scope := custody.CustodyScope{ClusterUID: "cluster", HostID: "host", HostIncarnation: 17, AdmittedAt: "2026-10-19T00:00:00Z"}
			store, err := custody.CreateLocalCustody(path, scope)
			if err != nil {
				t.Fatal("v2 mixed root setup failed")
			}
			defer store.Close()
			ref := custody.CustodyKeyRef{Epoch: "epoch-old", KeyID: "key", Generation: 8, ConfigDigest: "config"}
			body, recipient := frozenCustodyV1Material, ""
			if purpose == "equality" {
				if _, err := store.ImportEqualityKey(ref, []byte(frozenCustodyV1Sentinel)); err != nil {
					t.Fatal("v2 equality setup failed")
				}
			} else {
				key, err := store.CreateVoterIdentity(ref)
				if err != nil {
					t.Fatal("v2 voter setup failed")
				}
				recipient = key.Recipient()
				legacy, err := age.GenerateX25519Identity()
				if err != nil {
					t.Fatal("native v1 fixture setup failed")
				}
				body = strings.Replace(body, `"Purpose":"equality"`, `"Purpose":"voter-identity"`, 1)
				body = strings.Replace(body, "RlJPWkVOLVYxLU1BVEVSSUFMLVNFTlRJTkVMLTAwMDA=", base64.StdEncoding.EncodeToString([]byte(legacy.String())), 1)
			}
			files, err := filepath.Glob(filepath.Join(path, "key-*", "material"))
			if err != nil || len(files) != 1 || os.WriteFile(files[0], []byte(body), 0600) != nil {
				t.Fatal("mixed v1 material setup failed")
			}
			if store.Close() != nil {
				t.Fatal("mixed fixture close failed")
			}
			before := lifetimeSnapshot(t, path)
			opened, err := custody.OpenLocalCustody(path, scope)
			if err != nil {
				t.Fatal("valid v2 root could not reopen")
			}
			defer opened.Close()
			if purpose == "equality" {
				key, err := opened.OpenEqualityKey(ref)
				if !errors.Is(err, custody.ErrCustodyRecoveryRequired) || key != (custody.BootstrapEqualityKey{}) {
					t.Fatal("mixed original v1 equality material was returned")
				}
				if _, err := opened.ImportEqualityKey(ref, []byte(frozenCustodyV1Sentinel)); !errors.Is(err, custody.ErrCustodyRecoveryRequired) {
					t.Fatal("mixed v1 equality material was healed on retry")
				}
			} else {
				key, err := opened.OpenVoterIdentity(ref, recipient)
				if !errors.Is(err, custody.ErrCustodyRecoveryRequired) || key != nil {
					t.Fatal("mixed original v1 voter material was returned")
				}
				if _, err := opened.CreateVoterIdentity(ref); !errors.Is(err, custody.ErrCustodyRecoveryRequired) {
					t.Fatal("mixed v1 voter material was regenerated")
				}
			}
			if !reflect.DeepEqual(before, lifetimeSnapshot(t, path)) {
				t.Fatal("mixed original v1 material was rewritten")
			}
		})
	}
}
