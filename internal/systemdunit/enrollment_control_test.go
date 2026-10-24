package systemdunit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

const controlPolicyExpected = `<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="root">
    <allow own="org.litevirt.EnrollmentControl1"/>
  </policy>
</busconfig>
`

func controlRequirePublishedPolicy(t *testing.T, files enrollmentControlFiles) os.FileInfo {
	t.Helper()
	body, err := os.ReadFile(files.policy)
	if err != nil || string(body) != controlPolicyExpected || fmt.Sprintf("%x", sha256.Sum256(body)) != "48b495f0a3e29bb3160bd441273ac0949875cdfeb71c8918389f2395fd50d1a9" {
		t.Fatalf("RED_ENROLLMENT_POLICY: fixed exact-name policy not published: %v", err)
	}
	info, err := os.Lstat(files.policy)
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0644 || owner.Uid != files.owner || owner.Gid != files.group {
		t.Fatal("policy did not retain exact regular owner/group/mode")
	}
	return info
}

func TestControlHelperPolicyPublicationAndRetry(t *testing.T) {
	files, source := controlBootstrapFixture(t), controlExecutingFile(t)
	before := enrollmentControlDurability
	defer func() { enrollmentControlDurability = before }()
	gateObserved := false
	enrollmentControlDurability = func(point string) error {
		if point == "override-create" {
			controlRequirePublishedPolicy(t, files)
			gateObserved = true
		}
		return nil
	}
	if err := installEnrollmentControlFiles(context.Background(), source, files); err != nil {
		t.Fatalf("RED_ENROLLMENT_POLICY: fixed policy bootstrap failed: %v", err)
	}
	first := controlRequirePublishedPolicy(t, files)
	if !gateObserved {
		t.Fatal("callback override bypassed durable policy prerequisite")
	}
	if err := installEnrollmentControlFiles(context.Background(), source, files); err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(first, controlRequirePublishedPolicy(t, files)) {
		t.Fatal("exact-current policy retry replaced the existing verified policy")
	}
}

func TestControlHelperPolicyRefusesForeignArtifacts(t *testing.T) {
	for _, kind := range []string{"body", "mode", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			files, source := controlBootstrapFixture(t), controlExecutingFile(t)
			if err := os.MkdirAll(filepath.Dir(files.policy), 0700); err != nil {
				t.Fatal(err)
			}
			if kind == "symlink" {
				outside := filepath.Join(filepath.Dir(files.policy), "foreign")
				if err := os.WriteFile(outside, []byte(controlPolicyExpected), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, files.policy); err != nil {
					t.Fatal(err)
				}
			} else {
				body, mode := controlPolicyExpected, os.FileMode(0644)
				if kind == "body" {
					body = "<busconfig><policy user=\"root\"><allow own=\"*\"/></policy></busconfig>"
				}
				if kind == "mode" {
					mode = 0600
				}
				if err := os.WriteFile(files.policy, []byte(body), mode); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(files.policy)
			if err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(files.policy)
			if err != nil {
				t.Fatal(err)
			}
			if err := installEnrollmentControlFiles(context.Background(), source, files); err == nil {
				t.Fatal("RED_ENROLLMENT_POLICY: foreign policy accepted")
			}
			after, err := os.Lstat(files.policy)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("foreign policy metadata changed")
			}
			actual, err := os.ReadFile(files.policy)
			if err != nil || !bytes.Equal(body, actual) {
				t.Fatal("foreign policy body changed")
			}
			for _, path := range []string{files.image, files.override} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("foreign policy refusal followed a program publication")
				}
			}
		})
	}
}

func TestControlHelperPolicyDurabilityPrecedesOverride(t *testing.T) {
	for _, point := range []string{"policy-create", "policy-write", "policy-sync", "policy-reopen", "policy-rename", "policy-parent-sync"} {
		t.Run(point, func(t *testing.T) {
			files, source := controlBootstrapFixture(t), controlExecutingFile(t)
			before := enrollmentControlDurability
			defer func() { enrollmentControlDurability = before }()
			fired := false
			enrollmentControlDurability = func(actual string) error {
				if actual == point {
					fired = true
					return errors.New("injected actual policy publication failure")
				}
				return nil
			}
			if err := installEnrollmentControlFiles(context.Background(), source, files); err == nil || !fired {
				t.Fatalf("RED_ENROLLMENT_POLICY: policy durability gate %s was bypassed: %v", point, err)
			}
			if _, err := os.Stat(files.override); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("callback override preceded durable policy")
			}
			if _, err := os.Stat(files.policy); err == nil {
				controlRequirePublishedPolicy(t, files)
			}
		})
	}
}

func controlBootstrapFixture(t *testing.T) enrollmentControlFiles {
	t.Helper()
	dir := t.TempDir()
	return enrollmentControlFiles{image: filepath.Join(dir, "control", "litevirt"), override: filepath.Join(dir, "rollback.service.d", "90-enrollment-control.conf"), policy: filepath.Join(dir, "bus", "org.litevirt.EnrollmentControl1.conf"), owner: uint32(os.Geteuid()), group: uint32(os.Getegid())}
}

func controlExecutingFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestControlHelperBootstrapBeforeUpgradeSwap(t *testing.T) {
	files := controlBootstrapFixture(t)
	source := controlExecutingFile(t)
	before, err := os.ReadFile(source.Name())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(filepath.Dir(files.image))
	protected := map[string]string{"litevirt": "current", "litevirt.old": "old", "litevirt.upgrade-pending": "sentinel"}
	for name, body := range protected {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := installEnrollmentControlFiles(context.Background(), source, files); err != nil {
		t.Fatalf("RED_ENROLLMENT_CONTROL_BOOTSTRAP: actual executing image was not published: %v", err)
	}
	got, err := os.ReadFile(files.image)
	if err != nil || sha256.Sum256(got) != sha256.Sum256(before) {
		t.Fatal("published helper differs from the actual executing descriptor")
	}
	info, err := os.Stat(files.image)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("independent helper lost its deliberate executable mode")
	}
	drop, err := os.ReadFile(files.override)
	if err != nil || string(drop) != enrollmentControlDropIn(files.image) {
		t.Fatal("exact fixed companion override was not published after the image")
	}
	for name, body := range protected {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || string(got) != body {
			t.Fatalf("bootstrap modified main/old/sentinel %s", name)
		}
	}
	if err := installEnrollmentControlFiles(context.Background(), controlExecutingFile(t), files); err != nil {
		t.Fatalf("same current image/bootstrap retry failed: %v", err)
	}
	child := exec.Command(files.image, "-test.run=^TestControlHelperBootstrapImageProcess$", "-test.count=1", "-test.v")
	child.Env = append(os.Environ(), "LITEVIRT_ENROLLMENT_BOOTSTRAP_CHILD=1")
	out, err := child.CombinedOutput()
	t.Logf("independent image pid=%d original Wait=%v %s", child.Process.Pid, err, out)
	if err != nil || !bytes.Contains(out, []byte("INDEPENDENT_IMAGE_EXECUTED")) {
		t.Fatal("published image did not independently execute")
	}
}

func TestControlHelperBootstrapImageProcess(t *testing.T) {
	if os.Getenv("LITEVIRT_ENROLLMENT_BOOTSTRAP_CHILD") != "1" {
		t.Skip("subprocess only; actual bootstrap parent owns PID/Wait")
	}
	t.Log("INDEPENDENT_IMAGE_EXECUTED")
}

func TestControlHelperBootstrapDurabilityRefusesSwap(t *testing.T) {
	for _, point := range []string{"image-create", "image-write", "image-sync", "image-reopen", "image-rename", "image-parent-sync", "override-write", "override-sync", "override-rename", "override-parent-sync"} {
		t.Run(point, func(t *testing.T) {
			files := controlBootstrapFixture(t)
			old := enrollmentControlDurability
			t.Cleanup(func() { enrollmentControlDurability = old })
			fired := false
			enrollmentControlDurability = func(step string) error {
				if step == point && !fired {
					fired = true
					return errors.New("injected actual bootstrap durability failure")
				}
				return nil
			}
			if err := installEnrollmentControlFiles(context.Background(), controlExecutingFile(t), files); err == nil || !fired {
				t.Fatalf("RED_ENROLLMENT_CONTROL_BOOTSTRAP: unobserved durability failure at %s: %v", point, err)
			}
			// A landed helper/override may exist, but never a truncated helper.
			if image, err := os.ReadFile(files.image); err == nil {
				self, _ := os.ReadFile("/proc/self/exe")
				if sha256.Sum256(image) != sha256.Sum256(self) {
					t.Fatal("failed bootstrap left a truncated or foreign helper")
				}
			}
			if _, err := os.Stat(files.override); err == nil {
				if _, err := os.Stat(files.image); err != nil {
					t.Fatal("override published without its independently executable image")
				}
			}
		})
	}
}

func TestControlHelperBootstrapRefusesForeignPaths(t *testing.T) {
	for _, which := range []string{"helper-link", "parent-link", "foreign-override"} {
		t.Run(which, func(t *testing.T) {
			files := controlBootstrapFixture(t)
			outside := filepath.Join(t.TempDir(), "unrelated")
			if err := os.WriteFile(outside, []byte("foreign"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(files.image), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(files.override), 0700); err != nil {
				t.Fatal(err)
			}
			switch which {
			case "helper-link":
				if err := os.Symlink(outside, files.image); err != nil {
					t.Fatal(err)
				}
			case "parent-link":
				if err := os.Remove(filepath.Dir(files.image)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Dir(outside), filepath.Dir(files.image)); err != nil {
					t.Fatal(err)
				}
			case "foreign-override":
				if err := os.WriteFile(files.override, []byte("ExecStart=/foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := installEnrollmentControlFiles(context.Background(), controlExecutingFile(t), files); err == nil {
				t.Fatal("foreign helper/layout accepted")
			}
			got, _ := os.ReadFile(outside)
			if string(got) != "foreign" {
				t.Fatal("bootstrap overwrote an unrelated file")
			}
		})
	}
}

func TestControlHelperBootstrapRejectsParentReplacement(t *testing.T) {
	files := controlBootstrapFixture(t)
	parent := filepath.Dir(files.image)
	old := enrollmentControlDurability
	t.Cleanup(func() { enrollmentControlDurability = old })
	fired := false
	var fixtureErr error
	enrollmentControlDurability = func(step string) error {
		if step == "image-parent-sync" && !fired {
			fired = true
			fixtureErr = os.Rename(parent, parent+".moved")
			if fixtureErr == nil {
				fixtureErr = os.Mkdir(parent, 0700)
			}
			return fixtureErr
		}
		return nil
	}
	err := installEnrollmentControlFiles(context.Background(), controlExecutingFile(t), files)
	if !fired || fixtureErr != nil {
		t.Fatalf("actual parent replacement fixture failed: %v", fixtureErr)
	}
	if err == nil {
		t.Fatal("RED_ENROLLMENT_CONTROL_PARENT_REPLACEMENT: publication succeeded into a detached parent")
	}
	if _, err := os.Stat(files.override); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("override was published for a detached independent image")
	}
	retained, err := os.ReadFile(filepath.Join(parent+".moved", "litevirt"))
	self, _ := os.ReadFile("/proc/self/exe")
	if err != nil || sha256.Sum256(retained) != sha256.Sum256(self) {
		t.Fatal("detached complete image was erased or corrupted")
	}
}
