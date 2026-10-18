package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

func newLoginCmd() *cobra.Command {
	var realm string
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to the cluster (username and password, or an OIDC realm)",
		Long: `Log in and store a session for later commands.

With --realm local (the default) or an LDAP realm, prompts for a username and
password. With --realm oidc:<name>, signs in through that identity provider:
the node returns the provider's URL, a browser on THIS machine opens it, and
the provider sends the browser back to the realm's cli_redirect_url, a
loopback address that this command listens on
(docs/auth.md, "OIDC sign-in").`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.HasPrefix(realm, "oidc:") {
				return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
					opts := cli.OIDCLoginOptions{
						Realm:     realm,
						Out:       cmd.ErrOrStderr(),
						UserAgent: "lv",
						SecondFactor: func() (string, error) {
							return cli.ReadPassword(cmd.Context(), "2FA code (or recovery code): ")
						},
					}
					if !noBrowser {
						opts.OpenBrowser = cli.OpenBrowserDefault
					}
					resp, err := cli.OIDCLogin(ctx, c, opts)
					if err != nil {
						return err
					}
					return saveLogin(resp)
				})
			}
			fmt.Fprint(cmd.ErrOrStderr(), "Username: ")
			line, err := cli.ReadLine(cmd.Context(), cmd.InOrStdin())
			if err != nil {
				if cmd.Context().Err() != nil {
					return err
				}
				return fmt.Errorf("read username: %w", err)
			}
			username := strings.TrimSpace(line)
			if username == "" || strings.ContainsAny(username, " \t") {
				return fmt.Errorf("read username: expected one word, got %q", line)
			}

			password, err := cli.ReadPassword(cmd.Context(), "Password: ")
			if err != nil {
				return err
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				resp, err := c.Login(ctx, &pb.LoginRequest{
					Username: username,
					Password: password,
					Realm:    realm,
				})
				if err != nil {
					return fmt.Errorf("login failed: %w", err)
				}

				// 2FA gate: server returns Requires_2Fa with empty token; prompt
				// for the second factor and re-call Login.
				if resp.Requires_2Fa {
					code, err := cli.ReadPassword(cmd.Context(), "2FA code (or recovery code): ")
					if err != nil {
						return err
					}
					resp, err = c.Login(ctx, &pb.LoginRequest{
						Username: username,
						Password: password,
						Realm:    realm,
						TotpCode: code,
					})
					if err != nil {
						return fmt.Errorf("2fa stage failed: %w", err)
					}
				}

				return saveLogin(resp)
			})
		},
	}
	cmd.Flags().StringVar(&realm, "realm", "", "Authentication realm: local (default), ldap:<name>, or oidc:<name> for an identity-provider sign-in")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "With an oidc: realm, print the sign-in URL instead of opening a browser")
	return cmd
}

// saveLogin stores a minted session and says what it is.
func saveLogin(resp *pb.LoginResponse) error {
	if err := cli.SaveCredential(cli.CredentialEntry{
		Token:    resp.Token,
		Username: resp.Username,
		Role:     resp.Role,
	}); err != nil {
		return fmt.Errorf("save credential: %w", err)
	}

	if resp.GetRequires_2FaEnrollment() {
		fmt.Printf("Logged in as %s with an ENROLLMENT-ONLY session.\n", resp.Username)
		fmt.Println("The login policy requires a second factor and your account has none.")
		fmt.Println("Enroll one with `lv 2fa enroll-totp`, then `lv login` again with its code.")
		return nil
	}
	fmt.Printf("Logged in as %s (role: %s)\n", resp.Username, resp.Role)
	return nil
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Revoke the server-side session and remove stored credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Best-effort server-side revoke: keep going even if unreachable
			// so a stale credential can always be cleared. This deliberately
			// tolerates a connect failure, so it does NOT use withClient.
			c, closer, err := cli.Connect(cmd.Context())
			if err == nil {
				_, _ = c.Logout(cmd.Context(), &emptypb.Empty{})
				closer()
			}
			if err := cli.DeleteCredential(); err != nil {
				return err
			}
			fmt.Println("Logged out.")
			return nil
		},
	}
}

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show current authenticated identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			cred, err := cli.LoadCredential()
			if err != nil {
				return err
			}
			if cred == nil {
				fmt.Println("Not logged in (using mTLS client certificate)")
				return nil
			}
			fmt.Printf("%s (role: %s)\n", cred.Username, cred.Role)
			return nil
		},
	}
}
