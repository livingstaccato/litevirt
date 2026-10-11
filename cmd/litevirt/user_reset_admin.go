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
	var clear2FA bool
	var username string
	cmd := &cobra.Command{
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
when it next starts.

It also re-enables the admin account if it is disabled or has an expiry.
--clear-2fa additionally removes every second factor and recovery code of
the admin account, for a sole admin who lost both under a mandatory
second-factor policy, and prints an enrollment code for the first factor
the admin enrolls at the next login, and is recorded as clear_2fa=true on
the audit row. Both are login rules: they need the cluster upgrade to have
finished and litevirtd running on this node, and with the daemon down
reset-admin refuses them and changes nothing.

--user resets another admin-role account instead of "admin". It is how an
account the admin floor reinstated gets a credential: the floor brings back
a deleted admin's account but never its old password, sessions, API tokens
or second factors, so nobody can log in as it until root runs
` + "`lv user reset-admin --user <name>`" + `. The no_unrestricted_admin health
condition names the account. An account whose role is not admin is refused.`,
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
					// credentials_split_v1, and leave users.password_hash
					// empty once it has latched credentials_clear_v1, as the
					// daemon would. The login
					// rules are a release feature, opened only through the
					// daemon's gate: this process writes none of their data.
					db.SetCredentialsSplitGate(daemon.CredentialsSplitLatchedOnDisk(cfg.DataDir))
					db.SetCredentialsClearGate(daemon.CredentialsClearLatchedOnDisk(cfg.DataDir))
					return db, nil
				},
				dataDir:  cfg.DataDir,
				pwPath:   adminPasswordPath,
				osUser:   invokingOSUser(),
				clear2FA: clear2FA,
				username: username,
				out:      cmd.OutOrStdout(),
				errOut:   cmd.ErrOrStderr(),
			})
		},
	}
	cmd.Flags().BoolVar(&clear2FA, "clear-2fa", false,
		"also remove the admin account's second factors and recovery codes, and print an enrollment code")
	cmd.Flags().StringVar(&username, "user", "",
		"the admin-role account to reset (default admin), e.g. the one the admin floor reinstated")
	return cmd
}

// adminPasswordPath is where reset-admin writes the new credential.
const adminPasswordPath = "/etc/litevirt/admin-password"

// resetAdminRPCTimeout bounds the daemon path. A reset is one indexed read and
// one write; a daemon that has not answered in this long is wedged, and saying
// so beats hanging a recovery command.
const resetAdminRPCTimeout = 30 * time.Second

// resetAdminUserSchema is the first schema version of a litevirtd that knows
// ResetAdminPasswordRequest.username (--user). Every released build, and
// main, is below it.
const resetAdminUserSchema = 64

// resetAdminEnv is everything reset-admin touches, so a test can point it at a
// temporary data dir and a daemon of its choosing.
type resetAdminEnv struct {
	connect     func() (pb.LiteVirtClient, func(), error) // the local root channel
	openDB      func() (*corrosion.Client, error)         // the daemon-down fallback
	dataDir     string
	pwPath      string
	osUser      string
	clear2FA    bool
	username    string // --user; "" is admin
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
	if err := refuseUserOnOlderDaemon(ctx, client, env.username); err != nil {
		closeConn()
		return err
	}
	rpcCtx, cancel := context.WithTimeout(ctx, resetAdminRPCTimeout)
	resp, err := client.ResetAdminPassword(rpcCtx, &pb.ResetAdminPasswordRequest{
		PasswordHash: hash, OsUser: env.osUser, ClearTwoFactor: env.clear2FA, Username: env.username,
	})
	cancel()
	switch status.Code(err) {
	case codes.OK:
		defer closeConn()
		// The daemon names the account it reset. One that predates --user
		// names none, and reset "admin" whatever was asked: that password
		// changed, so it is written all the same, and the CLI says so.
		reset := resp.GetUsername()
		older := reset == ""
		if older {
			reset = "admin"
		}
		if err := secretfile.Write(env.pwPath, []byte(password+"\n"), 0600); err != nil {
			return fmt.Errorf("the password of %q was reset but the password file could not be written: %w", reset, err)
		}
		fmt.Fprintln(env.out, "Admin password reset.")
		fmt.Fprintf(env.out, "Account: %s\n", reset)
		fmt.Fprintf(env.out, "New password written to %s\n", env.pwPath)
		fmt.Fprintln(env.out, "Recorded in the audit log as user.reset-admin.")
		if older && env.username != "" && corrosion.NormalizeUsername(env.username) != "admin" {
			return fmt.Errorf("litevirtd on this node predates --user: it reset the password of \"admin\", "+
				"not of %q (the new admin password is in %s). Restart litevirtd on this node with the "+
				"installed binary, then run `lv user reset-admin --user %s` again", env.username, env.pwPath, env.username)
		}
		if env.clear2FA {
			fmt.Fprintf(env.out, "Every second factor of %s was removed.\n", reset)
			codeCtx, cancel := context.WithTimeout(ctx, resetAdminRPCTimeout)
			code, cerr := client.IssueEnrollmentCode(codeCtx, &pb.IssueEnrollmentCodeRequest{Username: reset})
			cancel()
			printEnrollmentCode(env.out, reset, code.GetCode(), code.GetExpiresAt(), code.GetIssuedOn(), cerr)
		}
		return nil
	case codes.Unavailable, codes.Unimplemented:
		closeConn()
		fmt.Fprintf(env.errOut, "litevirtd on this node could not take the reset (%s).\n"+
			"Resetting in the local database instead. The audit entry is journalled under %s\n"+
			"and the daemon records it, signed, once it is running.\n",
			status.Convert(err).Message(), filepath.Join(env.dataDir, corrosion.PendingAuditDirName))
	default:
		closeConn()
		return err
	}

	db, err := env.openDB()
	if err != nil {
		return fmt.Errorf("connect to corrosion: %w", err)
	}
	defer db.Close()
	return resetAdminOffline(ctx, db, env.dataDir, env.pwPath, env.osUser, env.username, password, hash, env.clear2FA, env.out)
}

// refuseUserOnOlderDaemon refuses --user, before anything is reset, when the
// local daemon's Ping shows a build from before the field (re-review 4,
// m-7): that daemon ignores it and resets "admin" — possibly a colleague's
// live password — whatever was named. Plain reset-admin (or --user admin) is
// not probed. A Ping that fails says nothing about the build and refuses
// nothing: the reset is asked as before, and the after-the-fact check in
// runResetAdmin still stands behind it (an unreleased build at the same
// schema version predates --user too).
func refuseUserOnOlderDaemon(ctx context.Context, client pb.LiteVirtClient, username string) error {
	if username == "" || corrosion.NormalizeUsername(username) == "admin" {
		return nil
	}
	pingCtx, cancel := context.WithTimeout(ctx, resetAdminRPCTimeout)
	defer cancel()
	resp, err := client.Ping(pingCtx, &pb.PingRequest{})
	if err != nil || resp.GetSchemaVersion() >= resetAdminUserSchema {
		return nil
	}
	return fmt.Errorf("litevirtd on this node predates --user (its schema version is %d; --user needs %d): "+
		"it would reset the password of \"admin\", not of %q, so nothing was changed. Restart litevirtd on "+
		"this node with the installed binary, then run `lv user reset-admin --user %s` again",
		resp.GetSchemaVersion(), resetAdminUserSchema, username, username)
}

// printEnrollmentCode tells the operator the admin's first-enrollment code, or
// how to get one when it could not be issued.
func printEnrollmentCode(out io.Writer, user, code, expires, issuedOn string, err error) {
	if err != nil || code == "" {
		fmt.Fprintf(out, "No enrollment code could be issued (%v). Issue one as root on a node whose\n"+
			"litevirtd is running, once the cluster upgrade has finished: `sudo lv 2fa enroll-code %s`.\n", err, user)
		return
	}
	fmt.Fprintf(out, "Enrollment code for %s's first factor (single use, until %s):\n  %s\n", user, expires, code)
	if issuedOn != "" {
		fmt.Fprintf(out, "It works only through node %s: log in to that node to enroll.\n", issuedOn)
	}
	fmt.Fprintf(out, "Log in as %s, then `lv 2fa enroll-totp --code <code>`, then log in again.\n", user)
}

// resetAdminOffline is the daemon-down path: journal the intent, reset, then
// journal the outcome under the same id, holding the journal's lock throughout
// so the daemon never folds the intent as the outcome. A crash in between
// leaves the entry saying "interrupted", which is what happened.
//
// The reset itself is corrosion.ResetAdminPassword, the same function the
// daemon's RPC calls, so the "reset, never create" rule cannot drift between the
// two paths.
func resetAdminOffline(ctx context.Context, db *corrosion.Client, dataDir, pwPath, osUser, username, password, hash string, clear2FA bool, out io.Writer) error {
	j, err := corrosion.OpenPendingAuditJournal(dataDir)
	if err != nil {
		// No journal, no reset: an unrecorded admin reset is exactly what this
		// path exists to prevent.
		return fmt.Errorf("cannot journal the audit entry, so the reset was not made: %w", err)
	}
	defer j.Close()
	name := username
	if name == "" {
		name = "admin"
	}
	entry := corrosion.PendingAuditEntry{
		Action: "user.reset-admin",
		Target: name,
		Detail: resetAdminJournalDetail(osUser, clear2FA),
		Result: "interrupted",
	}
	if err := j.Record(&entry); err != nil {
		return fmt.Errorf("cannot journal the audit entry, so the reset was not made: %w", err)
	}

	// No release-feature gate in this process (nil): a reset that needs the
	// login rules' data (--clear-2fa, or a restricted admin) is refused.
	resetErr := corrosion.ResetAdminPasswordFor(ctx, db, nil, name, hash, clear2FA)
	switch {
	case resetErr == nil:
		entry.Result = "ok"
	case errors.Is(resetErr, corrosion.ErrNoLiveAdmin):
		entry.Result = "denied: no live admin account"
	case errors.Is(resetErr, corrosion.ErrNotAnAdmin), errors.Is(resetErr, corrosion.ErrAmbiguousUsername),
		errors.Is(resetErr, corrosion.ErrLoginPolicyGateClosed):
		entry.Result = "denied"
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
	if u, err := corrosion.GetUser(ctx, db, name); err == nil && u != nil {
		name = u.Username
	}
	fmt.Fprintln(out, "Admin password reset.")
	fmt.Fprintf(out, "Account: %s\n", name)
	fmt.Fprintf(out, "New password written to %s\n", pwPath)
	// --clear-2fa never reaches here: it is a login rule, refused above
	// without the daemon's release-feature gate.
	return nil
}

func resetAdminJournalDetail(osUser string, clear2FA bool) string {
	d := corrosion.ResetAdminAuditDetail("journal", osUser)
	if clear2FA {
		d += " clear_2fa=true"
	}
	return d
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
