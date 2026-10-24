package systemdunit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const EnrollmentControlImagePath = "/usr/lib/litevirt/enrollment-control/litevirt"
const EnrollmentControlRollbackOverridePath = "/etc/systemd/system/litevirt-rollback.service.d/90-enrollment-control.conf"
const EnrollmentControlPolicyPath = "/etc/dbus-1/system.d/org.litevirt.EnrollmentControl1.conf"

type enrollmentControlFiles struct {
	image, override, policy string
	owner                   uint32
	group                   uint32
}

var enrollmentControlDurability = func(string) error { return nil }

func enrollmentControlDropIn(image string) string {
	return "[Service]\nExecStart=\nExecStart=" + image + " host-enroll-control rollback\n"
}

func enrollmentControlPolicy() string {
	return `<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="root">
    <allow own="org.litevirt.EnrollmentControl1"/>
  </policy>
</busconfig>
`
}

func controlDirectory(path string, owner uint32, private bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\r\n\x00%") {
		return nil, errors.New("invalid enrollment control directory")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || real != path {
		return nil, errors.New("enrollment control directory is not canonical")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != owner || info.Mode().Perm()&022 != 0 || private && info.Mode().Perm()&077 != 0 {
		_ = f.Close()
		return nil, errors.New("enrollment control directory is not privately owned")
	}
	return f, nil
}

func openControlAt(dir *os.File, name string, owner uint32) (*os.File, error) {
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	i, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || !i.Mode().IsRegular() || st.Uid != owner || i.Mode().Perm()&022 != 0 {
		_ = f.Close()
		return nil, errors.New("foreign enrollment control file")
	}
	return f, nil
}

type enrollmentControlReader struct {
	ctx context.Context
	r   io.Reader
}

func (r enrollmentControlReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}

func publishControlFile(ctx context.Context, dir *os.File, name, purpose string, source io.Reader, size int64, mode os.FileMode, owner, group uint32) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := enrollmentControlDurability(purpose + "-create"); err != nil {
		return err
	}
	temporary := "." + name + ".enrollment-publish"
	fd, err := syscall.Openat(int(dir.Fd()), temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), temporary)
	own, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	defer func() {
		_ = f.Close()
		// A later publisher may have created a different temporary inode.
		// Cleanup only this exact created object, never the pathname alone.
		if actual, e := openControlAt(dir, temporary, owner); e == nil {
			i, e := actual.Stat()
			_ = actual.Close()
			if e == nil && os.SameFile(own, i) {
				err = errors.Join(err, syscall.Unlinkat(int(dir.Fd()), temporary))
			}
		}
	}()
	expected := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, expected), io.LimitReader(enrollmentControlReader{ctx, source}, size+1))
	if err != nil || n != size {
		return fmt.Errorf("executing enrollment image changed during copy: %w", errors.Join(err, io.ErrUnexpectedEOF))
	}
	if err := enrollmentControlDurability(purpose + "-write"); err != nil {
		return err
	}
	if err := f.Chown(int(owner), int(group)); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := enrollmentControlDurability(purpose + "-sync"); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := enrollmentControlDurability(purpose + "-reopen"); err != nil {
		return err
	}
	verify := func(target string) error {
		r, err := openControlAt(dir, target, owner)
		if err != nil {
			return err
		}
		defer r.Close()
		i, err := r.Stat()
		if err != nil || i.Size() != size || i.Mode().Perm() != mode {
			return errors.New("enrollment control image metadata changed")
		}
		st, ok := i.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != owner || st.Gid != group {
			return errors.New("enrollment control file ownership changed")
		}
		actual := sha256.New()
		if _, err := io.Copy(actual, io.LimitReader(enrollmentControlReader{ctx, r}, size+1)); err != nil {
			return err
		}
		if !bytes.Equal(actual.Sum(nil), expected.Sum(nil)) {
			return errors.New("enrollment control image bytes changed")
		}
		return r.Sync()
	}
	if err := verify(temporary); err != nil {
		return err
	}
	if err := enrollmentControlDurability(purpose + "-rename"); err != nil {
		return err
	}
	if err := syscall.Renameat(int(dir.Fd()), temporary, int(dir.Fd()), name); err != nil {
		return err
	}
	if err := enrollmentControlDurability(purpose + "-parent-sync"); err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	publishedParent, err := os.Lstat(dir.Name())
	heldParent, heldErr := dir.Stat()
	if err != nil || heldErr != nil || !publishedParent.IsDir() || !os.SameFile(heldParent, publishedParent) {
		return errors.New("enrollment control parent changed during publication")
	}
	return verify(name)
}

// The public entry supplies fixed paths and the actual executing descriptor.
// Internal mapped owners permit private file fixtures, not runtime path input.
func installEnrollmentControlFiles(ctx context.Context, source *os.File, files enrollmentControlFiles) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	sourceInfo, err := source.Stat()
	if err != nil || !sourceInfo.Mode().IsRegular() || sourceInfo.Size() <= 0 || sourceInfo.Mode().Perm()&0111 == 0 {
		return errors.New("actual executing enrollment image required")
	}
	image, err := controlDirectory(filepath.Dir(files.image), files.owner, true)
	if err != nil {
		return err
	}
	defer image.Close()
	override, err := controlDirectory(filepath.Dir(files.override), files.owner, false)
	if err != nil {
		return err
	}
	defer override.Close()
	policy, err := controlDirectory(filepath.Dir(files.policy), files.owner, false)
	if err != nil {
		return err
	}
	defer policy.Close()
	verifyPolicy := func() (bool, error) {
		currentParent, err := os.Lstat(policy.Name())
		heldParent, heldErr := policy.Stat()
		if err != nil || heldErr != nil || !currentParent.IsDir() || !os.SameFile(currentParent, heldParent) {
			return false, errors.New("enrollment policy parent changed")
		}
		f, err := openControlAt(policy, filepath.Base(files.policy), files.owner)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			return false, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode().Perm() != 0644 || st.Gid != files.group {
			return false, errors.New("foreign enrollment ownership policy metadata")
		}
		body, err := io.ReadAll(io.LimitReader(f, 4097))
		if err != nil || string(body) != enrollmentControlPolicy() {
			return false, errors.New("foreign enrollment ownership policy")
		}
		return true, f.Sync()
	}
	// Refuse unknown policy before publishing either executable or callback.
	hasPolicy, err := verifyPolicy()
	if err != nil {
		return err
	}
	drop := enrollmentControlDropIn(files.image)
	hasOverride := false
	if f, err := openControlAt(override, filepath.Base(files.override), files.owner); err == nil {
		body, readErr := io.ReadAll(io.LimitReader(f, 4097))
		_ = f.Close()
		if readErr != nil || string(body) != drop {
			return errors.New("foreign enrollment rollback override")
		}
		hasOverride = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if f, err := openControlAt(image, filepath.Base(files.image), files.owner); err == nil {
		defer f.Close()
		if !hasOverride {
			// Exact retry after image publication is inert; unknown preexisting
			// program bytes without the current override are not adopted.
			a, b := sha256.New(), sha256.New()
			if _, err := source.Seek(0, io.SeekStart); err != nil {
				return err
			}
			if _, err := io.Copy(a, io.LimitReader(source, sourceInfo.Size()+1)); err != nil {
				return err
			}
			if _, err := io.Copy(b, io.LimitReader(f, sourceInfo.Size()+1)); err != nil {
				return err
			}
			if !bytes.Equal(a.Sum(nil), b.Sum(nil)) {
				return errors.New("foreign independent enrollment image")
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := publishControlFile(ctx, image, filepath.Base(files.image), "image", source, sourceInfo.Size(), 0700, files.owner, files.group); err != nil {
		return err
	}
	if !hasPolicy {
		body := enrollmentControlPolicy()
		if err := publishControlFile(ctx, policy, filepath.Base(files.policy), "policy", strings.NewReader(body), int64(len(body)), 0644, files.owner, files.group); err != nil {
			return err
		}
	}
	if present, err := verifyPolicy(); err != nil || !present {
		return errors.Join(errors.New("enrollment ownership policy prerequisite incomplete"), err)
	}
	return publishControlFile(ctx, override, filepath.Base(files.override), "override", strings.NewReader(drop), int64(len(drop)), 0600, files.owner, files.group)
}

func InstallEnrollmentControl(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("enrollment control installation requires root")
	}
	source, err := os.Open("/proc/self/exe")
	if err != nil {
		return err
	}
	defer source.Close()
	return installEnrollmentControlFiles(ctx, source, enrollmentControlFiles{image: EnrollmentControlImagePath, override: EnrollmentControlRollbackOverridePath, policy: EnrollmentControlPolicyPath, owner: 0, group: 0})
}
