package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/secretfile"
	"github.com/litevirt/litevirt/internal/ssh"
)

const maxEnrollmentRequest = 12 << 20

// HostEnrollmentRequest is the bounded stdin protocol to the staged current
// helper. Force records administrative init intent, never proof of quiescence.
// Private keys are carried only on stdin and never included in errors or logs.
type HostEnrollmentRequest struct {
	Host                         string
	CA, Certificate, Key, Gossip []byte
	Migration                    [3][]byte
	Rejoin                       []byte
	RemoveRejoin                 bool
	SetupEnv                     []string
	Founding, Force              bool
}

func DecodeHostEnrollment(r io.Reader) (HostEnrollmentRequest, error) {
	var request HostEnrollmentRequest
	raw, err := io.ReadAll(io.LimitReader(r, maxEnrollmentRequest+1))
	if err != nil {
		return request, err
	}
	if len(raw) > maxEnrollmentRequest {
		return request, errors.New("enrollment request exceeds bound")
	}
	if err := json.Unmarshal(raw, &request); err != nil {
		return request, errors.New("invalid enrollment request")
	}
	return request, nil
}

type hostEnrollmentOps struct {
	pkiDir, migrationDir, configPath               string
	prepare, stop, installBinary, configure, start func(context.Context, HostEnrollmentRequest) error
}

// RunHostEnrollment executes on the destination, from the current helper.
func RunHostEnrollment(ctx context.Context, request HostEnrollmentRequest) error {
	return runHostEnrollment(ctx, request, hostEnrollmentOps{
		pkiDir: "/etc/litevirt/pki", migrationDir: remoteMigrationDir, configPath: daemonConfigPath,
		prepare: func(ctx context.Context, _ HostEnrollmentRequest) error {
			return runEnrollmentScript(ctx, setupDependencyScript, nil)
		},
		stop:          func(ctx context.Context, _ HostEnrollmentRequest) error { return stopEnrollmentService(ctx) },
		installBinary: func(ctx context.Context, _ HostEnrollmentRequest) error { return installEnrollmentBinary(ctx) },
		configure: func(ctx context.Context, r HostEnrollmentRequest) error {
			return runEnrollmentScript(ctx, strings.TrimPrefix(setupScriptContent, setupDependencyScript), append(append([]string(nil), r.SetupEnv...), "LITEVIRT_DEFER_START=1"))
		},
		start: func(ctx context.Context, _ HostEnrollmentRequest) error {
			return exec.CommandContext(ctx, "systemctl", "restart", "litevirt.service").Run()
		},
	})
}

func runHostEnrollment(ctx context.Context, r HostEnrollmentRequest, ops hostEnrollmentOps) error {
	if r.Force && !r.Founding {
		return errors.New("only explicit host init may reinitialize a domain")
	}
	material, err := pki.ValidateHostEnrollment(r.Host, r.CA, r.Certificate, r.Key)
	if err != nil {
		return err
	}
	if len(r.Gossip) > 64<<10 || len(r.Rejoin) > 1<<20 || len(r.SetupEnv) > 64 {
		return errors.New("enrollment auxiliary input exceeds bound")
	}
	if len(r.Gossip) > 0 {
		if _, err := pki.ParseGossipKeyring(r.Gossip); err != nil {
			return errors.New("invalid staged gossip keyring")
		}
	}
	migrationPresent := false
	for _, b := range r.Migration {
		migrationPresent = migrationPresent || len(b) > 0
	}
	if migrationPresent {
		if _, err := pki.ValidateHostEnrollment(r.Host, r.Migration[0], r.Migration[1], r.Migration[2]); err != nil {
			return fmt.Errorf("staged migration identity: %w", err)
		}
	}
	envBytes := 0
	for _, value := range r.SetupEnv {
		envBytes += len(value)
		if len(value) > 64<<10 || envBytes > 256<<10 || strings.ContainsRune(value, 0) {
			return errors.New("enrollment setup environment exceeds bound")
		}
	}
	// This is the early pre-effect boundary for retained publication/use checks
	// when those consumers exist. Force is not evidence that a node was unused.
	if r.Founding {
		cfg, err := os.ReadFile(ops.configPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := refuseIfAlreadyAMember("this host", cfg, r.Force); err != nil {
			return err
		}
	}
	if err := ops.prepare(ctx, r); err != nil {
		return fmt.Errorf("prepare enrollment dependencies: %w", err)
	}
	if err := ops.stop(ctx, r); err != nil {
		return fmt.Errorf("quiesce enrollment service: %w", err)
	}
	if err := os.MkdirAll(ops.pkiDir, 0700); err != nil {
		return err
	}
	admissionCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	admission, err := pki.AcquireHostReinitialization(admissionCtx, ops.pkiDir)
	if err != nil {
		return fmt.Errorf("exclude running daemon before enrollment: %w", err)
	}
	defer admission.Release()
	// Recheck destination configuration after waiting for actual exclusion.
	if r.Founding {
		cfg, err := os.ReadFile(ops.configPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := refuseIfAlreadyAMember("this host", cfg, r.Force); err != nil {
			return err
		}
	}
	if r.Force {
		err = pki.ReinitializeHostDomain(ctx, ops.pkiDir, material, admission)
	} else {
		err = pki.InstallHostEnrollment(ctx, ops.pkiDir, material)
	}
	if err != nil {
		return fmt.Errorf("install enrollment identity: %w", err)
	}
	// The owner/file mutation lease is released before these local setup effects.
	// Lifetime admission still prevents a daemon from consuming partial setup.
	if len(r.Gossip) > 0 {
		if err := writeEnrollmentFile(filepath.Join(ops.pkiDir, pki.GossipKeyName), r.Gossip, 0600); err != nil {
			return err
		}
	}
	if migrationPresent {
		if err := os.MkdirAll(ops.migrationDir, 0700); err != nil {
			return err
		}
		for i, name := range []string{pki.MigrationCAName, pki.MigrationHostCertName, pki.MigrationHostKeyName} {
			mode := os.FileMode(0644)
			if i == 2 {
				mode = 0600
			}
			if err := writeEnrollmentFile(filepath.Join(ops.migrationDir, name), r.Migration[i], mode); err != nil {
				return err
			}
		}
	}
	rejoinPath := filepath.Join(ops.pkiDir, corrosion.AuditRejoinFileName)
	if len(r.Rejoin) > 0 {
		if err := writeEnrollmentFile(rejoinPath, r.Rejoin, 0644); err != nil {
			return err
		}
	} else if r.RemoveRejoin {
		if err := os.Remove(rejoinPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := syncEnrollmentDirectory(ops.pkiDir); err != nil {
			return err
		}
	}
	if err := ops.installBinary(ctx, r); err != nil {
		return fmt.Errorf("install current enrollment binary: %w", err)
	}
	if err := ops.configure(ctx, r); err != nil {
		return fmt.Errorf("configure enrolled host (service remains stopped): %w", err)
	}
	// Starting while EX is held deadlocks the new daemon's SH admission.
	admission.Release()
	if err := ops.start(ctx, r); err != nil {
		return fmt.Errorf("start enrolled host: %w", err)
	}
	return nil
}

func syncEnrollmentDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func writeEnrollmentFile(path string, body []byte, mode os.FileMode) error {
	if err := secretfile.Write(path, body, mode); err != nil {
		return err
	}
	return syncEnrollmentDirectory(filepath.Dir(path))
}

func runEnrollmentScript(ctx context.Context, script string, env []string) error {
	cmd := exec.CommandContext(ctx, "bash", "-s")
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func stopEnrollmentService(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	inspect := func() (string, error) {
		out, err := exec.CommandContext(ctx, "systemctl", "show", "litevirt.service", "--property=LoadState", "--property=ActiveState", "--property=SubState").Output()
		if err != nil {
			return string(out), fmt.Errorf("inspect litevirt.service: %w", err)
		}
		return string(out), nil
	}
	state, err := inspect()
	parse := func(raw string) map[string]string {
		m := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if ok {
				m[k] = v
			}
		}
		return m
	}
	before := parse(state)
	if before["LoadState"] == "not-found" && before["ActiveState"] == "inactive" && before["SubState"] == "dead" {
		return nil
	}
	if err != nil {
		return err
	}
	if before["LoadState"] != "loaded" {
		return errors.New("ambiguous litevirt.service load state")
	}
	if err := exec.CommandContext(ctx, "systemctl", "stop", "litevirt.service").Run(); err != nil {
		return fmt.Errorf("stop litevirt.service: %w", err)
	}
	state, err = inspect()
	if err != nil {
		return err
	}
	after := parse(state)
	if after["LoadState"] != "loaded" || after["ActiveState"] != "inactive" || after["SubState"] != "dead" {
		return errors.New("litevirt.service did not reach verified inactive/dead state")
	}
	return nil
}

func installEnrollmentBinary(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := os.Executable()
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, (512<<20)+1))
	if err != nil {
		return err
	}
	if len(body) > 512<<20 {
		return errors.New("enrollment binary exceeds bound")
	}
	if err := os.MkdirAll("/usr/local/bin", 0755); err != nil {
		return err
	}
	if err := writeEnrollmentFile("/usr/local/bin/litevirt", body, 0755); err != nil {
		return err
	}
	if err := os.Chmod("/usr/local/bin/litevirt", 0755); err != nil {
		return err
	}
	return exec.CommandContext(ctx, "ln", "-sf", "/usr/local/bin/litevirt", "/usr/local/bin/lv").Run()
}

type enrollmentRemote interface {
	Run(string) error
	RunOutput(string) ([]byte, error)
	RunWithInput(string, []byte) error
	CopyFileMode(string, string, os.FileMode) error
}

type enrollmentConnection interface {
	enrollmentRemote
	Close() error
}

var connectEnrollmentRemote = func(target *ssh.Target) (enrollmentConnection, error) {
	return ssh.NewClientResolved(target)
}
var enrollLocalHost = RunHostEnrollment

func runRemoteEnrollment(sc enrollmentRemote, r HostEnrollmentRequest) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(body) > maxEnrollmentRequest {
		return errors.New("enrollment request exceeds bound")
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	raw, err := sc.RunOutput("mktemp -d /var/tmp/litevirt-enrollment.XXXXXXXXXX")
	if err != nil {
		return err
	}
	staging := strings.TrimSpace(string(raw))
	if filepath.Dir(staging) != "/var/tmp" || !strings.HasPrefix(filepath.Base(staging), "litevirt-enrollment.") || strings.ContainsAny(staging, "\r\n") {
		return errors.New("invalid enrollment staging directory")
	}
	defer sc.Run("rm -rf -- " + ssh.ShellQuote(staging))
	helper := filepath.Join(staging, "litevirt")
	if err := sc.CopyFileMode(binary, helper, 0700); err != nil {
		return err
	}
	return sc.RunWithInput("exec "+ssh.ShellQuote(helper)+" host-enroll", body)
}

func readEnrollmentFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("enrollment input file exceeds bound")
	}
	return b, nil
}
func loadEnrollmentRequest(host, ca, cert, key, gossip string, migration []migrationFile) (HostEnrollmentRequest, error) {
	r := HostEnrollmentRequest{Host: host}
	var err error
	for _, item := range []struct {
		path string
		dest *[]byte
	}{{ca, &r.CA}, {cert, &r.Certificate}, {key, &r.Key}, {gossip, &r.Gossip}} {
		if item.path == "" {
			continue
		}
		*item.dest, err = readEnrollmentFile(item.path)
		if err != nil {
			return r, err
		}
	}
	if len(migration) != 3 {
		return r, errors.New("incomplete migration enrollment")
	}
	for i, f := range migration {
		r.Migration[i], err = readEnrollmentFile(f.local)
		if err != nil {
			return r, err
		}
	}
	return r, nil
}
