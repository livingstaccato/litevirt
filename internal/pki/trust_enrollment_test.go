package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func enrollmentMaterial(t *testing.T, dir string) *HostEnrollment {
	t.Helper()
	m, err := ValidateHostEnrollment("test-host", mustReadFile(t, filepath.Join(dir, "ca.crt")), mustReadFile(t, filepath.Join(dir, "host.crt")), mustReadFile(t, filepath.Join(dir, "host.key")))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestHostEnrollmentPreservesRootAndHostContinuity(t *testing.T) {
	ctx := context.Background()
	source := setupPKI(t)
	dest := t.TempDir()
	material := enrollmentMaterial(t, source)
	if err := InstallHostEnrollment(ctx, dest, material); err != nil {
		t.Fatal(err)
	}
	old, err := CaptureHostTrust(ctx, dest, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := ServedHostKeyPair(dest)
	if err != nil {
		t.Fatal(err)
	}
	cap, err := old.ValidateHostCertificate(ctx, pair.Certificate, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	mintInto(t, source, source, "test-host")
	if err := InstallHostEnrollment(ctx, dest, enrollmentMaterial(t, source)); err != nil {
		t.Fatal(err)
	}
	if lease, err := AcquireHostCertificateLease(ctx, dest, cap); err == nil {
		lease.Release()
		t.Fatal("enrollment left old capability active")
	}
	foreign := setupPKI(t)
	foreignMaterial := enrollmentMaterial(t, foreign)
	before := mustReadFile(t, filepath.Join(dest, "ca.crt"))
	if err := InstallHostEnrollment(ctx, dest, foreignMaterial); err == nil {
		t.Fatal("normal enrollment replaced the root")
	}
	if !bytes.Equal(before, mustReadFile(t, filepath.Join(dest, "ca.crt"))) {
		t.Fatal("refused enrollment changed root")
	}
	mintInto(t, source, source, "other-host")
	renamed, err := ValidateHostEnrollment("other-host", mustReadFile(t, filepath.Join(source, "ca.crt")), mustReadFile(t, filepath.Join(source, "host.crt")), mustReadFile(t, filepath.Join(source, "host.key")))
	if err != nil {
		t.Fatal(err)
	}
	if err := InstallHostEnrollment(ctx, dest, renamed); err == nil {
		t.Fatal("normal enrollment changed host identity")
	}
}

func TestHostEnrollmentRequiresRealExclusiveAdmission(t *testing.T) {
	ctx := context.Background()
	dest := setupPKI(t)
	material := enrollmentMaterial(t, setupPKI(t))
	before := mustReadFile(t, filepath.Join(dest, "ca.crt"))
	zero := &HostDomainLease{}
	shared, err := AcquireHostDomain(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := AcquireHostReinitialization(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Release()
	for _, lease := range []*HostDomainLease{nil, zero, shared, foreign} {
		if err := ReinitializeHostDomain(ctx, dest, material, lease); err == nil {
			t.Fatal("reinitialization accepted invalid admission")
		}
	}
	shared.Release()
	exclusive, err := AcquireHostReinitialization(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	copied := HostDomainLease{self: exclusive.self, dir: exclusive.dir, file: exclusive.file, exclusive: exclusive.exclusive}
	if err := ReinitializeHostDomain(ctx, dest, material, &copied); err == nil {
		t.Fatal("reinitialization accepted copied admission")
	}
	exclusive.Release()
	if err := ReinitializeHostDomain(ctx, dest, material, exclusive); err == nil {
		t.Fatal("reinitialization accepted released admission")
	}
	if !bytes.Equal(before, mustReadFile(t, filepath.Join(dest, "ca.crt"))) {
		t.Fatal("invalid admission changed active root")
	}
	// A previously issued view pins the old root permanently in this process.
	if _, err := CaptureHostTrust(ctx, dest, "test-host"); err != nil {
		t.Fatal(err)
	}
	exclusive, err = AcquireHostReinitialization(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer exclusive.Release()
	if err := ReinitializeHostDomain(ctx, dest, material, exclusive); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureHostTrust(ctx, dest, "test-host"); err == nil {
		t.Fatal("new domain repinned old process owner")
	}
}

func TestHostEnrollmentValidatesBeforeActiveWrites(t *testing.T) {
	dir := setupPKI(t)
	ca := mustReadFile(t, filepath.Join(dir, "ca.crt"))
	cert := mustReadFile(t, filepath.Join(dir, "host.crt"))
	key := mustReadFile(t, filepath.Join(dir, "host.key"))
	other := setupPKI(t)
	for _, bad := range []struct {
		name          string
		ca, cert, key []byte
	}{
		{"root", []byte("bad"), cert, key}, {"name", ca, cert, key}, {"key", ca, cert, mustReadFile(t, filepath.Join(other, "host.key"))}, {"foreign", mustReadFile(t, filepath.Join(other, "ca.crt")), cert, key},
	} {
		host := "test-host"
		if bad.name == "name" {
			host = "other-host"
		}
		if _, err := ValidateHostEnrollment(host, bad.ca, bad.cert, bad.key); err == nil {
			t.Fatalf("accepted invalid %s", bad.name)
		}
	}
	dest := t.TempDir()
	if err := InstallHostEnrollment(context.Background(), dest, &HostEnrollment{}); err == nil {
		t.Fatal("accepted zero enrollment")
	}
	if _, err := os.Stat(filepath.Join(dest, "ca.crt")); !os.IsNotExist(err) {
		t.Fatal("zero enrollment changed active files")
	}
}

func TestHostEnrollmentRepairsExpiredAndRefusesUnknownIdentity(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		dir := setupPKI(t)
		leaf := readLeaf(t, filepath.Join(dir, "host.crt"))
		ca, key, err := loadCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
		if err != nil {
			t.Fatal(err)
		}
		leaf.NotAfter = time.Now().Add(-time.Minute)
		leaf.NotBefore = time.Now().Add(-time.Hour)
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "host.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
			t.Fatal(err)
		}
		source := t.TempDir()
		if err := os.WriteFile(filepath.Join(source, "ca.crt"), mustReadFile(t, filepath.Join(dir, "ca.crt")), 0644); err != nil {
			t.Fatal(err)
		}
		mintInto(t, dir, source, "test-host")
		if err := InstallHostEnrollment(context.Background(), dir, enrollmentMaterial(t, source)); err != nil {
			t.Fatal("same-root host could not repair expired identity", err)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		source := setupPKI(t)
		dir := t.TempDir()
		for _, name := range []string{"ca.crt", "host.crt", "host.key"} {
			if err := os.Symlink("missing-"+name, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
		if err := InstallHostEnrollment(context.Background(), dir, enrollmentMaterial(t, source)); err == nil {
			t.Fatal("dangling existing identity was guessed to be first enrollment")
		}
	})
}

func TestHostEnrollmentForceRenameAndCorruptRepair(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		dir := setupPKI(t)
		source := t.TempDir()
		if err := os.WriteFile(filepath.Join(source, "ca.crt"), mustReadFile(t, filepath.Join(dir, "ca.crt")), 0644); err != nil {
			t.Fatal(err)
		}
		mintInto(t, dir, source, "new-host")
		material, err := ValidateHostEnrollment("new-host", mustReadFile(t, filepath.Join(source, "ca.crt")), mustReadFile(t, filepath.Join(source, "host.crt")), mustReadFile(t, filepath.Join(source, "host.key")))
		if err != nil {
			t.Fatal(err)
		}
		if corrupt {
			if err := os.WriteFile(filepath.Join(dir, "host.crt"), []byte("corrupt"), 0644); err != nil {
				t.Fatal(err)
			}
		}
		if err := InstallHostEnrollment(context.Background(), dir, material); err == nil {
			t.Fatal("ordinary installer accepted changed or unknown identity")
		}
		lease, err := AcquireHostReinitialization(context.Background(), dir)
		if err != nil {
			t.Fatal(err)
		}
		err = ReinitializeHostDomain(context.Background(), dir, material, lease)
		lease.Release()
		if err != nil {
			t.Fatal("quiescent explicit reinitialization refused", err)
		}
		if leaf := readLeaf(t, filepath.Join(dir, "host.crt")); leaf.Subject.CommonName != "new-host" {
			t.Fatal("forced rename was not installed")
		}
	}
}

func TestHostEnrollmentMissingFilesDoNotEraseEstablishedDomain(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(fmt.Sprint(foreign), func(t *testing.T) {
			ctx := context.Background()
			dir := setupPKI(t)
			material := enrollmentMaterial(t, dir)
			if _, err := CaptureHostTrust(ctx, dir, "test-host"); err != nil {
				t.Fatal(err)
			}
			if foreign {
				material = enrollmentMaterial(t, setupPKI(t))
			}
			for _, name := range []string{"host.crt", "host.key", "ca.crt"} {
				if err := os.Remove(filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			}
			if err := InstallHostEnrollment(ctx, dir, material); err == nil {
				t.Fatal("missing files erased established domain and authorized first enrollment")
			}
			if _, err := os.Lstat(filepath.Join(dir, "ca.crt")); !os.IsNotExist(err) {
				t.Fatal("refused enrollment recreated active root")
			}
		})
	}
}

func TestHostEnrollmentDurabilityFailureRefusesStableSuccess(t *testing.T) {
	for _, stage := range []string{"rename", "reopen", "file-sync", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			dir := setupPKI(t)
			source := t.TempDir()
			if err := os.WriteFile(filepath.Join(source, "ca.crt"), mustReadFile(t, filepath.Join(dir, "ca.crt")), 0644); err != nil {
				t.Fatal(err)
			}
			mintInto(t, dir, source, "test-host")
			material := enrollmentMaterial(t, source)
			ctx := context.Background()
			view, err := CaptureHostTrust(ctx, dir, "test-host")
			if err != nil {
				t.Fatal(err)
			}
			pair, err := ServedHostKeyPair(dir)
			if err != nil {
				t.Fatal(err)
			}
			cap, err := view.ValidateHostCertificate(ctx, pair.Certificate, "test-host")
			if err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected enrollment " + stage)
			trustDurabilitySeam = func(at string) error {
				if at == stage {
					return injected
				}
				return nil
			}
			defer func() { trustDurabilitySeam = nil }()
			if err := InstallHostEnrollment(ctx, dir, material); !errors.Is(err, injected) {
				t.Fatalf("durability failure was not returned: %v", err)
			}
			if lease, err := AcquireHostCertificateLease(ctx, dir, cap); err == nil {
				lease.Release()
				t.Fatal("failed enrollment left old capability usable")
			}
			reconciled, captureErr := CaptureHostTrust(ctx, dir, "test-host")
			if stage == "rename" {
				if captureErr != nil || !bytes.Equal(reconciled.served.Certificate[0], pair.Certificate[0]) {
					t.Fatal("pre-rename failure did not retain durably reconcilable old identity", captureErr)
				}
			} else if captureErr == nil {
				t.Fatal("failed durability certified stable trust")
			}
			trustDurabilitySeam = nil
			if err := InstallHostEnrollment(ctx, dir, material); err != nil {
				t.Fatal("durable retry did not progress", err)
			}
			if _, err := CaptureHostTrust(ctx, dir, "test-host"); err != nil {
				t.Fatal("durable enrollment did not establish trust", err)
			}
		})
	}
}

func TestCLIClientCopyAndFirstEnrollmentSerializeClassification(t *testing.T) {
	for _, enrollFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(enrollFirst), func(t *testing.T) {
			dir := t.TempDir()
			source := setupPKI(t)
			foreign := setupPKI(t)
			material := enrollmentMaterial(t, source)
			ctx := context.Background()
			foreignCA := mustReadFile(t, filepath.Join(foreign, "ca.crt"))
			copyClient := func() error {
				return InstallCLIClientFiles(ctx, dir, foreignCA, []byte("client cert"), []byte("client key"), -1, -1)
			}
			enroll := func() error { return InstallHostEnrollment(ctx, dir, material) }
			first, second := copyClient, enroll
			if enrollFirst {
				first, second = enroll, copyClient
			}
			reached, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			trustDurabilitySeam = func(stage string) error {
				if stage == "rename" {
					once.Do(func() { close(reached); <-release })
				}
				return nil
			}
			defer func() { trustDurabilitySeam = nil }()
			firstDone := make(chan error, 1)
			go func() { firstDone <- first() }()
			select {
			case <-reached:
			case <-time.After(5 * time.Second):
				t.Fatal("first writer did not reach owner-held publication")
			}
			secondDone := make(chan error, 1)
			go func() { secondDone <- second() }()
			select {
			case err := <-secondDone:
				t.Fatalf("second writer crossed active classification barrier: %v", err)
			case <-time.After(60 * time.Millisecond):
			}
			close(release)
			if err := <-firstDone; err != nil {
				t.Fatal(err)
			}
			if err := <-secondDone; err == nil {
				t.Fatal("later writer ignored the first writer's established root")
			}
			if enrollFirst {
				if !bytes.Equal(mustReadFile(t, filepath.Join(dir, "ca.crt")), material.ca) {
					t.Fatal("client copy replaced first enrollment root")
				}
				if _, err := os.Stat(filepath.Join(dir, "client.crt")); !os.IsNotExist(err) {
					t.Fatal("refused client copy changed client files")
				}
			} else {
				if !bytes.Equal(mustReadFile(t, filepath.Join(dir, "ca.crt")), foreignCA) {
					t.Fatal("enrollment replaced workstation root")
				}
				if _, err := os.Stat(filepath.Join(dir, "host.crt")); !os.IsNotExist(err) {
					t.Fatal("refused enrollment installed host under foreign root")
				}
			}
		})
	}
}

func TestHostEnrollmentLatePointerFailureRequiresReconciliation(t *testing.T) {
	dir := setupPKI(t)
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "ca.crt"), mustReadFile(t, filepath.Join(dir, "ca.crt")), 0644); err != nil {
		t.Fatal(err)
	}
	mintInto(t, dir, source, "test-host")
	material := enrollmentMaterial(t, source)
	ctx := context.Background()
	view, err := CaptureHostTrust(ctx, dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := ServedHostKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	cap, err := view.ValidateHostCertificate(ctx, pair.Certificate, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected directory sync after active pointer switch")
	reached := false
	trustDurabilitySeam = func(stage string) error {
		if stage == "directory-sync" {
			raw, _ := os.ReadFile(filepath.Join(dir, "host.crt"))
			if bytes.Equal(raw, material.cert) {
				reached = true
				return injected
			}
		}
		return nil
	}
	defer func() { trustDurabilitySeam = nil }()
	if err := InstallHostEnrollment(ctx, dir, material); !errors.Is(err, injected) {
		t.Fatalf("late failure was not returned: %v", err)
	}
	if !reached || !bytes.Equal(mustReadFile(t, filepath.Join(dir, "host.crt")), material.cert) {
		t.Fatal("test never crossed actual active identity switch")
	}
	if lease, err := AcquireHostCertificateLease(ctx, dir, cap); err == nil {
		lease.Release()
		t.Fatal("late failed installation left old capability usable")
	}
	if _, err := CaptureHostTrust(ctx, dir, "test-host"); err == nil {
		t.Fatal("failed post-switch directory durability minted stable evidence")
	}
	trustDurabilitySeam = nil
	if err := InstallHostEnrollment(ctx, dir, material); err != nil {
		t.Fatal("retry after partial active install did not progress", err)
	}
	current, err := CaptureHostTrust(ctx, dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := current.ValidateHostCertificate(ctx, [][]byte{material.leaf.Raw}, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := AcquireHostCertificateLease(ctx, dir, fresh)
	if err != nil {
		t.Fatal("reconciled installation did not permit fresh verification", err)
	}
	lease.Release()
}
