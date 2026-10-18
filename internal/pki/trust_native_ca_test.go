package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// Decode independently of the production codec: a versioned, fixed-size
// unassigned operation binds the exact retained PEM bytes, not just a path.
func inspectNativeCA(t *testing.T, dir string) ([]byte, []byte, []byte) {
	t.Helper()
	record, err := os.ReadFile(filepath.Join(dir, ".operator-ca-operation"))
	if err != nil {
		t.Fatalf("actual root creation lacks durable native operation: %v", err)
	}
	if len(record) != 104 || string(record[:8]) != "LVNCA001" || bytes.Equal(record[8:40], make([]byte, 32)) {
		t.Fatal("invalid bounded unassigned native operation")
	}
	cert, err := os.ReadFile(filepath.Join(dir, ".operator-ca-native", "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(dir, ".operator-ca-native", "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	certHash, keyHash := sha256.Sum256(cert), sha256.Sum256(key)
	if !bytes.Equal(record[40:72], certHash[:]) || !bytes.Equal(record[72:], keyHash[:]) {
		t.Fatal("native operation does not bind retained root/key")
	}
	if _, err := tls.X509KeyPair(cert, key); err != nil {
		t.Fatal("native root/key mismatch", err)
	}
	return record, cert, key
}

func TestOperatorCANativeOperationCreatedByActualRoot(t *testing.T) {
	dir := t.TempDir()
	if err := InitializeOperatorCA(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	record, cert, key := inspectNativeCA(t, dir)
	for name, want := range map[string][]byte{"ca.crt": cert, "ca.key": key} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("published pair differs from retained operation", name, err)
		}
	}
	if err := InitializeOperatorCA(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	again, _, _ := inspectNativeCA(t, dir)
	if !bytes.Equal(record, again) {
		t.Fatal("retry minted another operation")
	}
}

func TestOperatorCANativeLegacyAndAliases(t *testing.T) {
	t.Run("legacy", func(t *testing.T) {
		dir := t.TempDir()
		if err := GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
			t.Fatal(err)
		}
		if err := InitializeOperatorCA(context.Background(), dir); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Join(dir, ".operator-ca-operation")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("legacy root acquired native operation", err)
		}
	})
	t.Run("concurrent-aliases", func(t *testing.T) {
		dir := t.TempDir()
		alias := filepath.Join(t.TempDir(), "alias")
		if err := os.Symlink(dir, alias); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make(chan error, 12)
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				path := dir
				if i%2 == 0 {
					path = alias
				}
				errs <- InitializeOperatorCA(context.Background(), path)
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		inspectNativeCA(t, dir)
	})
}

func TestOperatorCANativeCrashProcess(t *testing.T) {
	dir, stage := os.Getenv("LITEVIRT_NATIVE_CA_DIR"), os.Getenv("LITEVIRT_NATIVE_CA_STAGE")
	if dir == "" {
		return
	}
	trustDurabilitySeam = func(at string) error {
		if stage == "root-reopen" && at == "reopen" {
			if _, err := os.Stat(filepath.Join(dir, "ca.crt")); err == nil {
				os.Exit(73)
			}
			return nil
		}
		if stage == "rename" && at == stage {
			if _, err := os.Stat(filepath.Join(dir, ".operator-ca-operation")); err != nil {
				return nil
			}
		}
		if at != stage {
			return nil
		}
		if at == "reopen" || at == "file-sync" || at == "directory-sync" {
			if _, err := os.Stat(filepath.Join(dir, "ca.key")); err != nil {
				return nil
			}
		}
		os.Exit(73)
		return nil
	}
	if err := InitializeOperatorCA(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash boundary was not reached")
}

func TestOperatorCANativeOwnedPublicationResume(t *testing.T) {
	for _, stage := range []string{"native-ca:record-committed", "rename", "native-ca:key-published", "reopen", "file-sync", "directory-sync", "root-reopen", "native-ca:root-published"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestOperatorCANativeCrashProcess$")
			cmd.Env = append(os.Environ(), "LITEVIRT_NATIVE_CA_DIR="+dir, "LITEVIRT_NATIVE_CA_STAGE="+stage)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 73 {
				t.Fatalf("crash boundary failed: %v %s", err, out)
			}
			record, cert, key := inspectNativeCA(t, dir)
			if err := InitializeOperatorCA(context.Background(), dir); err != nil {
				t.Fatal("owned restart refused", err)
			}
			again, _, _ := inspectNativeCA(t, dir)
			if !bytes.Equal(record, again) {
				t.Fatal("restart replaced operation")
			}
			for name, want := range map[string][]byte{"ca.crt": cert, "ca.key": key} {
				got, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("restart replaced committed pair", name, err)
				}
			}
		})
	}
}

func TestOperatorCANativeUncommittedCrashRefuses(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestOperatorCANativeCrashProcess$")
	cmd.Env = append(os.Environ(), "LITEVIRT_NATIVE_CA_DIR="+dir, "LITEVIRT_NATIVE_CA_STAGE=native-ca:staged")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 73 {
		t.Fatalf("precommit crash failed: %v %s", err, out)
	}
	if err := InitializeOperatorCA(context.Background(), dir); err == nil {
		t.Fatal("uncommitted staging minted operation")
	}
	for _, name := range []string{"ca.key", "ca.crt", ".operator-ca-operation"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("uncommitted staging published", name, err)
		}
	}
}

func TestOperatorCANativeRefusesAmbiguousEvidence(t *testing.T) {
	for _, kind := range []string{"record-corrupt", "record-oversize", "record-missing", "stage-missing", "key-mismatch", "active-mismatch", "active-symlink", "record-symlink", "stage-symlink", "unrecorded-key", "unrecorded-stage", "established-loss"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			if kind == "unrecorded-key" {
				if err := os.WriteFile(filepath.Join(dir, "ca.key"), []byte("partial"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if kind == "unrecorded-stage" {
				if err := os.Mkdir(filepath.Join(dir, ".operator-ca-native"), 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := InitializeOperatorCA(context.Background(), dir); err != nil {
					t.Fatal(err)
				}
				p := filepath.Join(dir, ".operator-ca-operation")
				switch kind {
				case "record-corrupt":
					if err := os.WriteFile(p, make([]byte, 104), 0600); err != nil {
						t.Fatal(err)
					}
				case "record-oversize":
					if err := os.WriteFile(p, make([]byte, 105), 0600); err != nil {
						t.Fatal(err)
					}
				case "record-missing":
					if err := os.Remove(p); err != nil {
						t.Fatal(err)
					}
				case "stage-missing":
					if err := os.Remove(filepath.Join(dir, ".operator-ca-native", "ca.key")); err != nil {
						t.Fatal(err)
					}
				case "key-mismatch":
					if err := os.WriteFile(filepath.Join(dir, ".operator-ca-native", "ca.key"), []byte("wrong"), 0600); err != nil {
						t.Fatal(err)
					}
				case "active-mismatch":
					if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("wrong"), 0600); err != nil {
						t.Fatal(err)
					}
				case "active-symlink":
					if err := os.Remove(filepath.Join(dir, "ca.key")); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(filepath.Join(dir, ".operator-ca-native", "ca.key"), filepath.Join(dir, "ca.key")); err != nil {
						t.Fatal(err)
					}
				case "record-symlink":
					if err := os.Rename(p, p+".saved"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(p+".saved", p); err != nil {
						t.Fatal(err)
					}
				case "stage-symlink":
					p = filepath.Join(dir, ".operator-ca-native")
					if err := os.Rename(p, p+".saved"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(p+".saved", p); err != nil {
						t.Fatal(err)
					}
				case "established-loss":
					if err := GenerateHostCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), "native", nil); err != nil {
						t.Fatal(err)
					}
					if _, err := CaptureHostTrust(context.Background(), dir, "native"); err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(filepath.Join(dir, "ca.crt")); err != nil {
						t.Fatal(err)
					}
				}
			}
			before, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
			if err := InitializeOperatorCA(context.Background(), dir); err == nil {
				t.Fatal("ambiguous evidence allowed initialization")
			}
			after, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
			if !bytes.Equal(before, after) {
				t.Fatal("refusal changed root")
			}
		})
	}
}
