package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/secretfile"
)

// MigrationTLSStatusFunc asks the cluster for every host's migration-TLS view.
type MigrationTLSStatusFunc func(ctx context.Context) ([]*pb.MigrationTLSHostStatus, error)

// RotateMigrationCAOptions are `lv host rotate-migration-ca`'s flags.
type RotateMigrationCAOptions struct {
	NoOverlap bool
	Force     bool
	Now       func() time.Time // nil: time.Now
}

// RotateMigrationCA replaces the migration CA on every host. See
// docs/design/migration-ca-rotation.md. It is resumable: progress is saved in
// pkiDir after every host, and a re-run continues from there.
func RotateMigrationCA(ctx context.Context, pkiDir string, hosts []MigrationTLSHost,
	status MigrationTLSStatusFunc, opts RotateMigrationCAOptions, out io.Writer) error {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	if _, err := os.Stat(filepath.Join(pkiDir, pki.MigrationCAKeyName)); err != nil {
		return fmt.Errorf("%s has no %s, so this is not the machine holding the migration CA; "+
			"run this where `lv host init` ran: %w", pkiDir, pki.MigrationCAKeyName, err)
	}
	r, err := startOrResumeRotation(pkiDir, opts.NoOverlap)
	if err != nil {
		return err
	}
	phases := r.phases()
	start := slices.Index(phases, r.Phase)
	if start < 0 {
		// Falling through would finalize with nothing pushed.
		return fmt.Errorf("%s records phase %q, which is not one of %v; it was edited or written by "+
			"another build, so this run cannot tell what the hosts hold",
			filepath.Join(pkiDir, rotationFileName), r.Phase, phases)
	}
	for i := start; i < len(phases); i++ {
		r.Phase = phases[i]
		if err := r.save(pkiDir); err != nil {
			return err
		}
		fmt.Fprintf(out, "phase %s\n", r.Phase)
		for _, h := range hosts {
			if r.Skipped[h.Name()] || r.hostDone(h.Name(), r.Phase) {
				continue
			}
			pushErr := pushRotationPhase(ctx, pkiDir, r.Phase, h)
			if pushErr == nil {
				r.markDone(h.Name(), r.Phase)
			} else if err := skipOrStop(pkiDir, r, h.Name(), pushErr, opts.Force); err != nil {
				_ = r.save(pkiDir) // keep what earlier hosts finished
				return err
			}
			if err := r.save(pkiDir); err != nil {
				return err
			}
			if pushErr == nil {
				fmt.Fprintf(out, "  %s: done\n", h.Name())
			} else {
				fmt.Fprintf(out, "  %s: skipped (%v)\n", h.Name(), pushErr)
			}
		}
		if err := gatePhase(ctx, pkiDir, r, hosts, status, opts.Force); err != nil {
			return err
		}
	}
	if err := finalizeMigrationRotation(pkiDir, r, now()); err != nil {
		return err
	}
	r.Phase = phaseDone
	if err := r.save(pkiDir); err != nil {
		return err
	}
	fmt.Fprintf(out, "Migration CA rotated; every host not skipped now trusts only %s.\n", r.NewCAFingerprint)
	for _, h := range slices.Sorted(maps.Keys(r.Skipped)) {
		fmt.Fprintf(out, "%s was skipped and still holds the old CA's credentials; once it is back, "+
			"run `lv host install-migration-tls --reissue`\n", h)
	}
	return nil
}

func startOrResumeRotation(pkiDir string, noOverlap bool) (*migrationRotation, error) {
	r, err := loadMigrationRotation(pkiDir)
	if err != nil {
		return nil, err
	}
	if r.inProgress() {
		if r.NoOverlap != noOverlap {
			flag := "without --no-overlap"
			if r.NoOverlap {
				flag = "with --no-overlap"
			}
			return nil, fmt.Errorf("a rotation started %s is in progress; re-run it the same way", flag)
		}
		return r, nil
	}
	next, nextKey := filepath.Join(pkiDir, nextCACertName), filepath.Join(pkiDir, nextCAKeyName)
	if _, err := os.Stat(next); errors.Is(err, fs.ErrNotExist) {
		if err := pki.GenerateMigrationCA(next, nextKey); err != nil {
			return nil, fmt.Errorf("generate the new migration CA: %w", err)
		}
	}
	oldPEM, err := os.ReadFile(filepath.Join(pkiDir, pki.MigrationCACertName))
	if err != nil {
		return nil, err
	}
	newPEM, err := os.ReadFile(next)
	if err != nil {
		return nil, err
	}
	if err := secretfile.Write(filepath.Join(pkiDir, bundleCACertName), append(oldPEM, newPEM...), 0o644); err != nil {
		return nil, err
	}
	fp, err := pki.CAFileFingerprint(next)
	if err != nil {
		return nil, err
	}
	r = &migrationRotation{NoOverlap: noOverlap, NewCAFingerprint: fp}
	r.Phase = r.phases()[0]
	return r, r.save(pkiDir)
}

// pushRotationPhase pushes what phase delivers to one host. The rotation's Phase is
// already saved, so migrationIssuingCA picks the right CA and trust bundle.
func pushRotationPhase(ctx context.Context, pkiDir, phase string, h MigrationTLSHost) error {
	caFile := func(path string) migrationFile {
		return migrationFile{path, filepath.Join(remoteMigrationDir, pki.MigrationCAName), 0o644}
	}
	switch phase {
	case phaseTrustBoth:
		return h.Push(ctx, []migrationFile{caFile(filepath.Join(pkiDir, bundleCACertName))})
	case phaseDropOld:
		// The new CA alone: next.crt, or the current CA once finalize has
		// renamed next.crt over it and only "done" went unsaved.
		_, _, trust, err := migrationIssuingCA(pkiDir)
		if err != nil {
			return err
		}
		return h.Push(ctx, []migrationFile{caFile(trust)})
	}
	ip := net.ParseIP(h.Address())
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("recorded address %q is not an IPv4 address", h.Address())
	}
	files, err := issueMigrationCredentials(pkiDir, h.Name(), ip, nil)
	if err != nil {
		return err
	}
	if phase == phaseReissue {
		files = files[1:] // certificate and key only; ca.crt already holds both CAs
	}
	return h.Push(ctx, files)
}

func skipOrStop(pkiDir string, r *migrationRotation, host string, cause error, force bool) error {
	if !force {
		return fmt.Errorf("%s: %w. Progress is saved; re-run `lv host rotate-migration-ca` once it "+
			"is reachable, or pass --force to leave it behind", host, cause)
	}
	if r.Skipped == nil {
		r.Skipped = map[string]bool{}
	}
	r.Skipped[host] = true
	return nil
}

// gatePhase asks every host's daemon what it would install, and requires the
// phase's result on each host not skipped. A host that falls short is no
// longer done with the phase, so the re-run pushes to it again rather than
// re-checking a push its daemon never took.
func gatePhase(ctx context.Context, pkiDir string, r *migrationRotation, hosts []MigrationTLSHost,
	status MigrationTLSStatusFunc, force bool) error {
	rows, err := status(ctx)
	if err != nil {
		return fmt.Errorf("check hosts after phase %s: %w", r.Phase, err)
	}
	byHost := map[string]*pb.MigrationTLSHostStatus{}
	for _, row := range rows {
		byHost[row.GetHost()] = row
	}
	var unmet []error
	for _, h := range hosts {
		if r.Skipped[h.Name()] {
			continue
		}
		if why := phaseUnmet(r.Phase, r.NewCAFingerprint, byHost[h.Name()]); why != "" {
			if err := skipOrStop(pkiDir, r, h.Name(), errors.New(why), force); err != nil {
				if r.Done != nil {
					r.Done[h.Name()] = slices.DeleteFunc(r.Done[h.Name()], func(p string) bool { return p == r.Phase })
				}
				unmet = append(unmet, err)
			}
		}
	}
	if err := r.save(pkiDir); err != nil {
		return err
	}
	return errors.Join(unmet...)
}

// phaseUnmet says why row does not show phase's result, or "" when it does.
func phaseUnmet(phase, newFP string, row *pb.MigrationTLSHostStatus) string {
	if row == nil {
		return "did not answer the status check"
	}
	if row.GetError() != "" {
		return row.GetError()
	}
	var trusts []string
	for _, ca := range row.GetTrustedCas() {
		trusts = append(trusts, ca.GetFingerprint())
	}
	switch phase {
	case phaseTrustBoth:
		if !slices.Contains(trusts, newFP) {
			return "its daemon does not yet trust the new CA"
		}
	case phaseReissue:
		if row.GetCertIssuerFingerprint() != newFP || row.GetValidationError() != "" {
			return "its daemon does not yet hold a valid certificate from the new CA: " + row.GetValidationError()
		}
	default: // drop-old, cutover
		if len(trusts) != 1 || trusts[0] != newFP || row.GetCertIssuerFingerprint() != newFP || row.GetValidationError() != "" {
			return "its daemon does not yet trust the new CA alone with a valid certificate from it"
		}
	}
	return ""
}

// finalizeMigrationRotation makes the new CA current on this machine. Each step
// is idempotent, so a crash anywhere is finished by the re-run: the old
// certificate is retired, then next.crt and next.key are renamed over the
// current pair, certificate first.
func finalizeMigrationRotation(pkiDir string, r *migrationRotation, now time.Time) error {
	cur, curKey := filepath.Join(pkiDir, pki.MigrationCACertName), filepath.Join(pkiDir, pki.MigrationCAKeyName)
	next, nextKey := filepath.Join(pkiDir, nextCACertName), filepath.Join(pkiDir, nextCAKeyName)
	if fp, err := pki.CAFileFingerprint(cur); err == nil && fp != r.NewCAFingerprint {
		retired := filepath.Join(pkiDir, "migration-ca.retired-"+now.Format("20060102")+".crt")
		data, err := os.ReadFile(cur)
		if err != nil {
			return err
		}
		if err := secretfile.Write(retired, data, 0o644); err != nil {
			return err
		}
	}
	for _, mv := range [][2]string{{next, cur}, {nextKey, curKey}} {
		if err := os.Rename(mv[0], mv[1]); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("make the new migration CA current: %w", err)
		}
	}
	if err := os.Remove(filepath.Join(pkiDir, bundleCACertName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
