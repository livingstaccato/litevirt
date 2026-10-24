package pki

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"
)

var enrollmentBackupSuffix = regexp.MustCompile(`^\.pre-add-([0-9]{8}T[0-9]{6}Z)-[a-f0-9]{12}$`)

// HostEnrollmentUndo is a process-private capability for this install's exact
// footprint. Backups are evidence, never a way to reconstruct this capability.
// It conveys neither a machine claim nor authority to start a service.
type HostEnrollmentUndo struct {
	mu                                      sync.Mutex
	self                                    *HostEnrollmentUndo
	owner                                   *trustOwner
	directory                               os.FileInfo
	suffix                                  string
	ca                                      []byte
	before                                  enrollmentImage
	restoreCurrent                          [2]enrollmentNode
	possible                                [2]enrollmentImage
	count                                   int
	previous, next                          enrollmentPair
	prepared, succeeded, restored, complete bool
}

type enrollmentNode struct {
	kind uint8 // 0 absent, 1 regular, 2 symlink
	mode os.FileMode
	body []byte
	link string
	// Captured inode identities are checked unless this operation itself is
	// about to replace that exact node. A landed own step pins its actual inode.
	info       os.FileInfo
	targetInfo os.FileInfo
	targetMode os.FileMode
}
type enrollmentPair struct {
	serial    string
	cert, key enrollmentNode
}
type enrollmentImage struct {
	paths   [4]enrollmentNode
	current [2]enrollmentNode
}

var enrollmentPaths = [4]string{"ca.crt", "host.crt", "host.key", "host.d/current"}

func InstallHostEnrollmentWithUndo(ctx context.Context, dir string, m *HostEnrollment, admission *HostDomainLease, backupSuffix string) (*HostEnrollmentUndo, error) {
	parts := enrollmentBackupSuffix.FindStringSubmatch(backupSuffix)
	if len(parts) != 2 {
		return nil, errors.New("invalid enrollment backup suffix")
	}
	if _, err := time.Parse("20060102T150405Z", parts[1]); err != nil {
		return nil, err
	}
	if m == nil || m.root == nil || m.leaf == nil {
		return nil, errors.New("validated enrollment input required")
	}
	if _, err := ValidateHostEnrollment(m.host, m.ca, m.cert, m.key); err != nil {
		return nil, err
	}
	if admission == nil {
		return nil, errors.New("exclusive host domain admission required")
	}
	admission.mu.Lock()
	defer admission.mu.Unlock()
	if err := admission.checkLocked(dir); err != nil {
		return nil, err
	}
	o, err := trustOwnerFor(dir)
	if err != nil {
		return nil, err
	}
	lock, err := o.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer lock.release()
	if err := admission.checkLocked(dir); err != nil {
		return nil, err
	}
	info, err := os.Stat(o.dir)
	if err != nil {
		return nil, err
	}
	u := &HostEnrollmentUndo{owner: o, directory: info, suffix: backupSuffix}
	u.self = u
	err = installHostEnrollmentLocked(ctx, o, m, false, u)
	if !u.prepared {
		return nil, err
	}
	u.succeeded = err == nil
	return u, err
}

func readEnrollmentNode(path string, follow bool) (enrollmentNode, error) {
	var n enrollmentNode
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return n, nil
	}
	if err != nil {
		return n, err
	}
	n.info = fi
	n.mode = fi.Mode().Perm()
	if fi.Mode()&os.ModeSymlink != 0 {
		n.kind = 2
		n.link, err = os.Readlink(path)
		if err != nil {
			return n, err
		}
		if len(n.link) > 4096 {
			return n, errors.New("oversized enrollment link")
		}
		if !follow {
			return n, nil
		}
		n.targetInfo, err = os.Stat(path)
		if err != nil {
			return n, err
		}
		if !n.targetInfo.Mode().IsRegular() {
			return n, errors.New("enrollment link target is not regular")
		}
		n.targetMode = n.targetInfo.Mode().Perm()
	} else if fi.Mode().IsRegular() {
		n.kind = 1
	} else {
		return n, errors.New("unsupported enrollment endpoint")
	}
	n.body, err = readBoundedN(path, 1<<20)
	return n, err
}

func readEnrollmentImage(dir string) (enrollmentImage, error) {
	var image enrollmentImage
	total := 0
	for i, name := range enrollmentPaths {
		n, err := readEnrollmentNode(filepath.Join(dir, name), i != 3)
		if err != nil {
			return image, err
		}
		image.paths[i] = n
		total += len(n.body) + len(n.link)
	}
	cur := image.paths[3]
	if cur.kind != 0 {
		if cur.kind != 2 || !hexSerialRE.MatchString(cur.link) {
			return image, errors.New("unsupported current identity pointer")
		}
		for i, name := range []string{"host.crt", "host.key"} {
			n, err := readEnrollmentNode(filepath.Join(dir, hostDirName, cur.link, name), false)
			if err != nil {
				return image, err
			}
			if n.kind == 2 {
				return image, errors.New("retained identity cannot be a link")
			}
			image.current[i] = n
			total += len(n.body)
		}
	}
	if total > 5<<20 {
		return image, errors.New("oversized enrollment undo image")
	}
	return image, nil
}

func sameEnrollmentNode(want, got enrollmentNode, inodes bool) bool {
	if want.kind != got.kind {
		return false
	}
	if want.kind == 0 {
		return true
	}
	if want.mode != got.mode || want.link != got.link || !bytes.Equal(want.body, got.body) || want.targetMode != got.targetMode {
		return false
	}
	if inodes && want.info != nil && (got.info == nil || !os.SameFile(want.info, got.info)) {
		return false
	}
	if inodes && want.targetInfo != nil && (got.targetInfo == nil || !os.SameFile(want.targetInfo, got.targetInfo)) {
		return false
	}
	return true
}
func sameEnrollmentImage(want, got enrollmentImage, inodes bool) bool {
	for i := range want.paths {
		if !sameEnrollmentNode(want.paths[i], got.paths[i], inodes) {
			return false
		}
	}
	for i := range want.current {
		if !sameEnrollmentNode(want.current[i], got.current[i], inodes) {
			return false
		}
	}
	return true
}
func pinEnrollmentImage(known, actual enrollmentImage) enrollmentImage {
	for i := range actual.paths {
		actual.paths[i].body = known.paths[i].body
		actual.paths[i].link = known.paths[i].link
	}
	for i := range actual.current {
		actual.current[i].body = known.current[i].body
		actual.current[i].link = known.current[i].link
	}
	return actual
}

func enrollmentFile(body []byte, mode os.FileMode) enrollmentNode {
	return enrollmentNode{kind: 1, body: bytes.Clone(body), mode: mode}
}
func enrollmentLink(link string) enrollmentNode {
	return enrollmentNode{kind: 2, mode: 0777, link: link}
}

func (u *HostEnrollmentUndo) prepare(m *HostEnrollment, previous *x509.Certificate) error {
	if fi, err := os.Lstat(hostDir(u.owner.dir)); err == nil {
		if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			return errors.New("retained identity directory is not canonical")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	before, err := readEnrollmentImage(u.owner.dir)
	if err != nil {
		return err
	}
	// Count every owned payload buffer, including admitted material, before
	// cloning or backing up. Later images share these immutable bounded bytes.
	total := len(m.ca) + len(m.cert) + len(m.key)
	for _, n := range before.paths {
		total += len(n.body) + len(n.link)
	}
	for _, n := range before.current {
		total += len(n.body) + len(n.link)
	}
	if total > 5<<20 {
		return errors.New("oversized aggregate enrollment undo receipt")
	}
	u.ca = bytes.Clone(m.ca)
	u.before = before
	u.restoreCurrent = before.current
	if previous != nil {
		u.previous = enrollmentPair{serial: previous.SerialNumber.Text(16), cert: enrollmentNode{kind: 1, body: before.paths[1].body, mode: 0644}, key: enrollmentNode{kind: 1, body: before.paths[2].body, mode: 0600}}
	}
	u.next = enrollmentPair{serial: m.leaf.SerialNumber.Text(16), cert: enrollmentFile(m.cert, 0644), key: enrollmentFile(m.key, 0600)}
	// The existing retained pair can be hardened independently of the active
	// regular files. Preserve secretfile.Write's actual mode ceiling per file.
	if previous != nil {
		for i, name := range []string{"host.crt", "host.key"} {
			n, err := readEnrollmentNode(filepath.Join(hostDir(u.owner.dir), u.previous.serial, name), false)
			if err != nil {
				return err
			}
			if n.kind == 1 {
				if i == 0 {
					u.previous.cert.mode &= n.mode
				} else {
					u.previous.key.mode &= n.mode
				}
			}
		}
	}

	// A retained candidate must be the actual directory and fixed regular
	// files under this owner, not an equal-byte external symlink target.
	nextDir := filepath.Join(hostDir(u.owner.dir), u.next.serial)
	if fi, err := os.Lstat(nextDir); err == nil {
		if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			return errors.New("retained enrollment candidate is not canonical")
		}
		for i, name := range []string{"host.crt", "host.key"} {
			n, err := readEnrollmentNode(filepath.Join(nextDir, name), false)
			if err != nil {
				return err
			}
			want := m.cert
			if i == 1 {
				want = m.key
			}
			if n.kind != 1 || !bytes.Equal(n.body, want) {
				return errors.New("enrollment serial collides with a retained identity")
			}
			if i == 0 {
				u.next.cert.mode = n.mode
			} else {
				u.next.key.mode = n.mode
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Every existing fixed endpoint gets a bounded private copy before effects.
	for i, n := range before.paths {
		if n.kind == 0 {
			continue
		}
		body := n.body
		if i == 3 {
			body = []byte(n.link)
		}
		if err := writeEnrollmentBackup(filepath.Join(u.owner.dir, enrollmentPaths[i])+u.suffix, body); err != nil {
			return err
		}
	}
	// The owner and EX are still held: no snapshot/install interleaving window.
	current, err := readEnrollmentImage(u.owner.dir)
	if err != nil {
		return err
	}
	if !sameEnrollmentImage(before, current, true) {
		return errors.New("enrollment image changed while preparing backups")
	}
	u.possible[0] = before
	u.count = 1
	u.prepared = true
	return nil
}

func writeEnrollmentBackup(path string, body []byte) error {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if errors.Is(err, syscall.EEXIST) {
		n, e := readEnrollmentNode(path, false)
		if e != nil {
			return e
		}
		if n.kind != 1 || n.mode != 0600 || !bytes.Equal(n.body, body) {
			return errors.New("enrollment backup collision")
		}
		return durableTrustReopen(path, body)
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	if _, err = f.Write(body); err == nil {
		err = f.Chmod(0600)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return durableTrustReopen(path, body)
}

type enrollmentMutation uint8

const (
	enrollmentPlaceNew enrollmentMutation = iota
	enrollmentPreviousKey
	enrollmentPreviousCert
	enrollmentSwitchPrevious
	enrollmentSwitchNew
	enrollmentLinkKey
	enrollmentLinkCert
	enrollmentWriteCA
)

func (u *HostEnrollmentUndo) resolve(image *enrollmentImage) {
	for i := 1; i <= 2; i++ {
		n := &image.paths[i]
		if n.kind == 2 && n.link == filepath.Join(hostDirName, currentLinkName, enrollmentPaths[i]) {
			target := image.current[i-1]
			n.body = target.body
			n.targetMode = target.mode
			n.targetInfo = target.info
		}
	}
}
func (u *HostEnrollmentUndo) prediction(before enrollmentImage, step enrollmentMutation) enrollmentImage {
	after := before
	switch step {
	case enrollmentPlaceNew:
		if after.paths[3].link == u.next.serial {
			after.current = [2]enrollmentNode{u.next.cert, u.next.key}
		}
	case enrollmentPreviousKey:
		if after.paths[3].link == u.previous.serial {
			after.current[1] = u.previous.key
		}
	case enrollmentPreviousCert:
		if after.paths[3].link == u.previous.serial {
			after.current[0] = u.previous.cert
		}
	case enrollmentSwitchPrevious:
		after.paths[3] = enrollmentLink(u.previous.serial)
		after.current = [2]enrollmentNode{u.previous.cert, u.previous.key}
	case enrollmentSwitchNew:
		after.paths[3] = enrollmentLink(u.next.serial)
		after.current = [2]enrollmentNode{u.next.cert, u.next.key}
	case enrollmentLinkKey:
		after.paths[2] = enrollmentLink(filepath.Join(hostDirName, currentLinkName, "host.key"))
	case enrollmentLinkCert:
		after.paths[1] = enrollmentLink(filepath.Join(hostDirName, currentLinkName, "host.crt"))
	case enrollmentWriteCA:
		// secretfile.Write uses the old resolved mode as a ceiling.
		mode := os.FileMode(0644)
		old := before.paths[0]
		if old.kind == 1 {
			mode &= old.mode
		} else if old.kind == 2 {
			mode &= old.targetMode
		}
		// Reuse the already owned immutable CA bytes; cloning here would
		// retain unaccounted payload after the aggregate admission check.
		after.paths[0] = enrollmentNode{kind: 1, body: u.ca, mode: mode}
	}
	u.resolve(&after)
	return after
}

// All callers are the finite local install steps above. The closure is not an
// authority-bearing API and cannot choose a snapshot or add a receipt path.
func enrollmentStep(u *HostEnrollmentUndo, step enrollmentMutation, apply func() error) error {
	if u == nil {
		return apply()
	}
	before, err := u.match()
	if err != nil {
		return err
	}
	after := u.prediction(before, step)
	u.possible = [2]enrollmentImage{before, after}
	u.count = 2 // intent before syscall
	err = apply()
	actual, readErr := readEnrollmentImage(u.owner.dir)
	if readErr != nil {
		return errors.Join(err, readErr)
	}
	if sameEnrollmentImage(after, actual, true) {
		actual = pinEnrollmentImage(after, actual)
	} else if sameEnrollmentImage(before, actual, true) {
		actual = pinEnrollmentImage(before, actual)
	} else {
		return errors.Join(err, errors.New("foreign change during enrollment step"))
	}
	u.rememberCurrent(actual)
	u.possible[0] = actual
	u.count = 1
	return err
}

// Only a fully matched finite operation prefix can update this expectation.
// The original current pointer can be inert behind regular active files. Own
// conversion may fill its retained pair; restoring raw preimages must keep that
// pair rather than erase it or expect the old absent/partial referent forever.
func (u *HostEnrollmentUndo) rememberCurrent(image enrollmentImage) {
	if u.before.paths[3].kind == 2 && image.paths[3].kind == 2 && image.paths[3].link == u.before.paths[3].link {
		u.restoreCurrent = image.current
	}
}

func (u *HostEnrollmentUndo) match() (enrollmentImage, error) {
	var empty enrollmentImage
	fi, err := os.Stat(u.owner.dir)
	if err != nil || !os.SameFile(u.directory, fi) {
		return empty, errors.New("enrollment owner directory changed")
	}
	actual, err := readEnrollmentImage(u.owner.dir)
	if err != nil {
		return empty, err
	}
	for i := 0; i < u.count; i++ {
		if sameEnrollmentImage(u.possible[i], actual, true) {
			actual = pinEnrollmentImage(u.possible[i], actual)
			u.rememberCurrent(actual)
			return actual, nil
		}
	}
	return empty, errors.New("enrollment footprint is not this operation's exact prefix")
}

func (u *HostEnrollmentUndo) Restore(ctx context.Context, admission *HostDomainLease) (err error) {
	if u == nil {
		return errors.New("live enrollment undo receipt required")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.self != u || u.complete || !u.prepared {
		return errors.New("live enrollment undo receipt required")
	}
	if admission == nil {
		return errors.New("exclusive host domain admission required")
	}
	admission.mu.Lock()
	defer admission.mu.Unlock()
	if err := admission.checkLocked(u.owner.dir); err != nil {
		return err
	}
	owner, e := trustOwnerFor(u.owner.dir)
	if e != nil {
		return e
	}
	if owner != u.owner {
		return errors.New("enrollment owner changed")
	}
	lock, e := owner.lock(ctx)
	if e != nil {
		return e
	}
	defer lock.release()
	if err := admission.checkLocked(owner.dir); err != nil {
		return err
	}
	if _, err := u.match(); err != nil {
		return err
	}
	// Completion describes the current durable phase, not historical success.
	// Once this valid restore begins, any mutation or durability error must keep
	// retry authority until this restore reaches known local success again.
	u.succeeded = false
	u.restored = false
	owner.invalidateLocked()
	defer func() {
		if err != nil {
			owner.dirty = err
		}
	}()
	// Each remove/write/link has its own exact before/after intent, including
	// interrupted restore. Never accept a free mixture of old and new fields.
	for _, i := range []int{2, 1, 3, 0} {
		if err := ctx.Err(); err != nil {
			return err
		}
		want := u.before.paths[i]
		current, e := u.match()
		if e != nil {
			return e
		}
		if want.kind == 1 && current.paths[i].kind != 0 && !sameEnrollmentNode(want, current.paths[i], false) {
			if err := u.restoreStep(i, enrollmentNode{}); err != nil {
				return err
			}
		}
		if err := u.restoreStep(i, want); err != nil {
			return err
		}
	}
	for i, n := range u.before.paths {
		if i != 3 && n.kind != 0 {
			if err := durableTrustReopen(filepath.Join(owner.dir, enrollmentPaths[i]), n.body); err != nil {
				return err
			}
		}
	}
	if u.before.paths[3].kind != 0 {
		if err := syncTrustDirectory(hostDir(owner.dir)); err != nil {
			return err
		}
	}
	if err := syncTrustDirectory(owner.dir); err != nil {
		return err
	}
	actual, err := u.match()
	if err != nil {
		return err
	}
	expected := u.before
	expected.current = u.restoreCurrent
	u.resolve(&expected)
	if !sameEnrollmentImage(expected, actual, false) {
		return errors.New("restored enrollment differs from original")
	}
	u.restored = true
	return nil
}

func (u *HostEnrollmentUndo) restoreStep(index int, want enrollmentNode) error {
	before, err := u.match()
	if err != nil {
		return err
	}
	after := before
	replacement := want
	replacement.info = nil
	// Existing external CA links keep their original target identity. Canonical
	// active identity links derive their target from the current pointer below.
	after.paths[index] = replacement
	if index == 3 {
		if want.kind == 0 {
			after.current = [2]enrollmentNode{}
		} else {
			after.current = u.restoreCurrent
			// Check the exact retained referents before changing a pointer to them.
			for i, name := range []string{"host.crt", "host.key"} {
				actual, err := readEnrollmentNode(filepath.Join(hostDir(u.owner.dir), want.link, name), false)
				if err != nil {
					return err
				}
				if !sameEnrollmentNode(after.current[i], actual, true) {
					return errors.New("original current referent changed outside this operation")
				}
			}
		}
	}
	u.resolve(&after)
	if sameEnrollmentImage(before, after, false) {
		return nil
	}
	u.possible = [2]enrollmentImage{before, after}
	u.count = 2
	path := filepath.Join(u.owner.dir, enrollmentPaths[index])
	switch want.kind {
	case 0:
		err = os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
		if err == nil {
			err = syncTrustDirectory(filepath.Dir(path))
		}
	case 1:
		err = writeTrustFile(path, want.body, want.mode)
	case 2:
		err = atomicSymlink(want.link, path)
	}
	actual, readErr := readEnrollmentImage(u.owner.dir)
	if readErr != nil {
		return errors.Join(err, readErr)
	}
	if sameEnrollmentImage(after, actual, true) {
		actual = pinEnrollmentImage(after, actual)
	} else if sameEnrollmentImage(before, actual, true) {
		actual = pinEnrollmentImage(before, actual)
	} else {
		return errors.Join(err, errors.New("foreign change during enrollment restore"))
	}
	u.rememberCurrent(actual)
	u.possible[0] = actual
	u.count = 1
	return err
}

func (u *HostEnrollmentUndo) Complete() error {
	if u == nil {
		return errors.New("live enrollment undo receipt required")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.self != u || u.complete || !u.prepared || !u.succeeded && !u.restored {
		return errors.New("completed local enrollment required")
	}
	u.complete = true
	u.before = enrollmentImage{}
	u.restoreCurrent = [2]enrollmentNode{}
	u.possible = [2]enrollmentImage{}
	u.previous = enrollmentPair{}
	u.next = enrollmentPair{}
	u.ca = nil
	return nil
}

func checkEnrollmentPrevious(dir, serial string, cert, key []byte) error {
	if !hexSerialRE.MatchString(serial) {
		return errors.New("invalid previous serial")
	}
	path := filepath.Join(hostDir(dir), serial)
	if fi, err := os.Lstat(path); err == nil {
		if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			return errors.New("retained previous identity directory is not canonical")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, item := range []struct {
		name string
		body []byte
	}{{"host.crt", cert}, {"host.key", key}} {
		n, err := readEnrollmentNode(filepath.Join(path, item.name), false)
		if err != nil {
			return err
		}
		if n.kind != 0 && (n.kind != 1 || !bytes.Equal(n.body, item.body)) {
			return errors.New("previous enrollment serial collides with a retained identity")
		}
	}
	return nil
}

func ensureEnrollmentLinkedLayout(dir, serial string, u *HostEnrollmentUndo) error {
	cur := filepath.Join(hostDir(dir), currentLinkName)
	_, err := os.Lstat(cur)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if errors.Is(err, os.ErrNotExist) || hasRegularIdentityFile(dir) {
		target := filepath.Join(hostDir(dir), serial)
		if err := os.MkdirAll(target, 0700); err != nil {
			return err
		}
		for _, item := range []struct {
			name string
			mode os.FileMode
			step enrollmentMutation
		}{{"host.key", 0600, enrollmentPreviousKey}, {"host.crt", 0644, enrollmentPreviousCert}} {
			body, err := readBounded(filepath.Join(dir, item.name))
			if err != nil {
				return err
			}
			if err := enrollmentStep(u, item.step, func() error {
				// Recheck after backup preparation and immediately before each write.
				cert, err := readBounded(filepath.Join(dir, "host.crt"))
				if err != nil {
					return err
				}
				key, err := readBounded(filepath.Join(dir, "host.key"))
				if err != nil {
					return err
				}
				if err := checkEnrollmentPrevious(dir, serial, cert, key); err != nil {
					return err
				}
				return writeTrustFile(filepath.Join(target, item.name), body, item.mode)
			}); err != nil {
				return err
			}
		}
		if err := crashPoint("copied-legacy"); err != nil {
			return err
		}
		if err := enrollmentStep(u, enrollmentSwitchPrevious, func() error { return atomicSymlink(serial, cur) }); err != nil {
			return err
		}
		if err := crashPoint("current-created"); err != nil {
			return err
		}
	}
	for _, item := range []struct {
		name string
		step enrollmentMutation
	}{{"host.key", enrollmentLinkKey}, {"host.crt", enrollmentLinkCert}} {
		path := filepath.Join(dir, item.name)
		want := filepath.Join(hostDirName, currentLinkName, item.name)
		if link, err := os.Readlink(path); err == nil && link == want {
			continue
		}
		if err := enrollmentStep(u, item.step, func() error { return atomicSymlink(want, path) }); err != nil {
			return err
		}
		if err := crashPoint("linked-" + item.name); err != nil {
			return err
		}
	}
	return nil
}
