package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/daemon"
	"github.com/litevirt/litevirt/internal/secretfile"
)

func newUserResetAdminCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset-admin",
		Short: "Reset admin password (run as root on a cluster node)",
		Long: `Resets the existing admin user's password to a new random value and
writes it to /etc/litevirt/admin-password. It never creates an admin.

Run it as root on a node. It needs no login: it reaches the local daemon
over loopback with this host's own certificate, and the daemon applies the
reset and records a user.reset-admin audit row.

If the daemon is not running, the reset is written to the local database
directly and the audit entry is journalled under the data directory; the
daemon folds it into the audit log, signed and at the time it happened,
when it next starts.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := daemon.LoadConfig()
			if err != nil {
				return fmt.Errorf("load config (is this a litevirt node?): %w", err)
			}
			return runResetAdmin(cmd.Context(), resetAdminEnv{
				connect: func() (pb.LiteVirtClient, func(), error) {
					return cli.ConnectLocalRoot(cfg.PKIDir, cfg.GRPCPort)
				},
				openDB: func() (*corrosion.Client, error) {
					db, err := corrosion.NewLocalClient(cfg.DataDir, cfg.HostName)
					if err != nil {
						return nil, err
					}
					// Write user_credentials too once this node has latched
					// credentials_split_v1, as the daemon would.
					db.SetCredentialsSplitGate(daemon.CredentialsSplitLatchedOnDisk(cfg.DataDir))
					return db, nil
				},
				dataDir: cfg.DataDir,
				pwPath:  adminPasswordPath,
				osUser:  invokingOSUser(),
				out:     cmd.OutOrStdout(),
				errOut:  cmd.ErrOrStderr(),
			})
		},
	}
}

// adminPasswordPath is where reset-admin writes the new credential.
const adminPasswordPath = "/etc/litevirt/admin-password"

// resetAdminRPCTimeout bounds the daemon path. A reset is one indexed read and
// one write; a daemon that has not answered in this long is wedged, and saying
// so beats hanging a recovery command.
const resetAdminRPCTimeout = 30 * time.Second

// resetAdminEnv is everything reset-admin touches, so a test can point it at a
// temporary data dir and a daemon of its choosing.
type resetAdminEnv struct {
	connect     func() (pb.LiteVirtClient, func(), error) // the local root channel
	openDB      func() (*corrosion.Client, error)         // the daemon-down fallback
	dataDir     string
	pwPath      string
	osUser      string
	out, errOut io.Writer
}

// runResetAdmin resets the admin password through the daemon when it is
// running, and in the local database with a journalled audit entry when it is
// not.
//
// The daemon path is not a nicety. This host's audit chain is extended by its
// daemon alone: a row appended from this process forks the chain and is
// unsigned, and `lv audit verify` reports both as tampering
// (TestAudit_SecondProcessRowForksTheChain). So the only way for a reset to be
// on the record while the daemon runs is for the daemon to write it.
//
// The fallback is taken only when the daemon cannot be reached (Unavailable) or
// predates the RPC (Unimplemented). Anything else, a refusal included, is the
// daemon's answer and is returned as it is: falling back on a refusal would turn
// every guard the daemon applies into a suggestion. A timeout is not a fallback
// either, because the daemon may have applied the reset, and a second one would
// leave the password file and the database disagreeing.
func runResetAdmin(ctx context.Context, env resetAdminEnv) error {
	password, hash, err := mintAdminPassword()
	if err != nil {
		return err
	}
	client, closeConn, err := env.connect()
	if err != nil {
		return fmt.Errorf("reach the local daemon: %w", err)
	}
	rpcCtx, cancel := context.WithTimeout(ctx, resetAdminRPCTimeout)
	_, err = client.ResetAdminPassword(rpcCtx, &pb.ResetAdminPasswordRequest{PasswordHash: hash, OsUser: env.osUser})
	cancel()
	closeConn()
	switch status.Code(err) {
	case codes.OK:
		if err := secretfile.Write(env.pwPath, []byte(password+"\n"), 0600); err != nil {
			return fmt.Errorf("the admin password was reset but the password file could not be written: %w", err)
		}
		fmt.Fprintln(env.out, "Admin password reset.")
		fmt.Fprintf(env.out, "New password written to %s\n", env.pwPath)
		fmt.Fprintln(env.out, "Recorded in the audit log as user.reset-admin.")
		return nil
	case codes.Unavailable, codes.Unimplemented:
		fmt.Fprintf(env.errOut, "litevirtd on this node could not take the reset (%s).\n"+
			"Resetting in the local database instead. The audit entry is journalled under %s\n"+
			"and the daemon records it, signed, once it is running.\n",
			status.Convert(err).Message(), filepath.Join(env.dataDir, corrosion.PendingAuditDirName))
	default:
		return err
	}

	db, err := env.openDB()
	if err != nil {
		return fmt.Errorf("connect to corrosion: %w", err)
	}
	defer db.Close()
	return resetAdminOffline(ctx, db, env.dataDir, env.pwPath, env.osUser, password, hash, env.out)
}

// resetAdminOffline is the daemon-down path: journal the intent, reset, then
// journal the outcome under the same id, holding the journal's lock throughout
// so the daemon never folds the intent as the outcome. A crash in between
// leaves the entry saying "interrupted", which is what happened.
//
// The reset itself is corrosion.ResetAdminPassword, the same function the
// daemon's RPC calls, so the "reset, never create" rule cannot drift between the
// two paths.
func resetAdminOffline(ctx context.Context, db *corrosion.Client, dataDir, pwPath, osUser, password, hash string, out io.Writer) error {
	j, err := corrosion.OpenPendingAuditJournal(dataDir)
	if err != nil {
		// No journal, no reset: an unrecorded admin reset is exactly what this
		// path exists to prevent.
		return fmt.Errorf("cannot journal the audit entry, so the reset was not made: %w", err)
	}
	defer j.Close()
	entry := corrosion.PendingAuditEntry{
		Action: "user.reset-admin",
		Target: "admin",
		Detail: corrosion.ResetAdminAuditDetail("journal", osUser),
		Result: "interrupted",
	}
	if err := j.Record(&entry); err != nil {
		return fmt.Errorf("cannot journal the audit entry, so the reset was not made: %w", err)
	}

	resetErr := corrosion.ResetAdminPassword(ctx, db, hash)
	switch {
	case resetErr == nil:
		entry.Result = "ok"
	case errors.Is(resetErr, corrosion.ErrNoLiveAdmin):
		entry.Result = "denied: no live admin account"
	default:
		entry.Result = "error"
	}
	if err := j.Record(&entry); err != nil {
		return errors.Join(resetErr, fmt.Errorf("journal the outcome of the reset: %w", err))
	}
	if resetErr != nil {
		return resetErr
	}
	if err := secretfile.Write(pwPath, []byte(password+"\n"), 0600); err != nil {
		return fmt.Errorf("the admin password was reset but the password file could not be written: %w", err)
	}
	fmt.Fprintln(out, "Admin password reset.")
	fmt.Fprintf(out, "New password written to %s\n", pwPath)
	return nil
}

// mintAdminPassword returns a fresh random admin password and its bcrypt hash.
// Only the hash leaves this process.
func mintAdminPassword() (password, hash string, err error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	password = hex.EncodeToString(b)
	h, err := bcrypt.GenerateFromPassword([]byte(password), auth.BcryptCost)
	if err != nil {
		return "", "", err
	}
	return password, string(h), nil
}

// invokingOSUser names who ran the command, for the audit row: the sudo caller
// when there is one, since by now everyone is root. The daemon records it as a
// claim.
func invokingOSUser() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}
