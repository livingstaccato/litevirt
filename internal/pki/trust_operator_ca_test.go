package pki

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOperatorCAFirstCreationAndDurability(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	alias := filepath.Join(t.TempDir(), "operator")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if err := InitializeOperatorCA(ctx, alias); err != nil {
		t.Fatal(err)
	}
	original, err := os.Stat(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := GenerateHostCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), "test-host", nil); err != nil {
		t.Fatal("new operator CA pair is unusable", err)
	}
	if err := InitializeOperatorCA(ctx, dir); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(filepath.Join(dir, "ca.crt"))
	if err != nil || !os.SameFile(original, after) {
		t.Fatal("existing operator CA was replaced")
	}
	if _, err := CaptureHostTrust(ctx, dir, "test-host"); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"rename", "reopen", "file-sync", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			injected := errors.New("injected first CA " + stage)
			trustDurabilitySeam = func(at string) error {
				if at == stage {
					if at == "directory-sync" {
						if _, err := os.Stat(filepath.Join(dir, "ca.key")); err != nil {
							return nil
						}
					}
					return injected
				}
				return nil
			}
			defer func() { trustDurabilitySeam = nil }()
			if err := InitializeOperatorCA(ctx, dir); !errors.Is(err, injected) {
				t.Fatalf("first CA creation ignored durability failure: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, "ca.crt")); !os.IsNotExist(err) {
				t.Fatal("failed key publication exposed a root")
			}
			trustDurabilitySeam = nil
			if stage == "rename" {
				if err := InitializeOperatorCA(ctx, dir); err != nil {
					t.Fatal("pre-write retry did not progress", err)
				}
			} else {
				if err := InitializeOperatorCA(ctx, dir); err == nil {
					t.Fatal("partial CA key evidence was silently treated as unused")
				}
			}
		})
	}
}
