package main

import (
	"context"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/pki"
)

// newHostInstallGossipKeyCmd gives an existing cluster its gossip key. A
// cluster founded by this build already has one: `lv host init` mints it.
func newHostInstallGossipKeyCmd() *cobra.Command {
	var sshUser string
	cmd := &cobra.Command{
		Use:   "install-gossip-key",
		Short: "Distribute the cluster gossip encryption key to every host",
		Long: `Put the cluster gossip key on every host, minting it first if this machine has none.

Gossip (memberlist, port 7946) carries cluster membership. It is not covered by
mTLS; it is encrypted and authenticated with a shared AES-256 key kept in
/etc/litevirt/pki/gossip.key (0600) on every host. Clusters created by
'lv host init' have one from the start. Run this on an existing cluster, from the
machine that holds the cluster CA, to install one.

It changes nothing on the wire: a host uses the key only once its
enforcement.gossip_encryption moves off false. The rollout is three rolling
restarts - install, staged, true - each finished on every host before the next
(docs/auth.md, "Gossip encryption"). Re-run this at any point to see every
host's stage; it never replaces a key a host already holds.

  lv host install-gossip-key
  lv host install-gossip-key --ssh-user admin`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				hosts, closeAll, err := cli.SSHGossipKeyHosts(ctx, c, sshUser)
				if err != nil {
					return err
				}
				defer closeAll()
				return cli.InstallGossipKey(ctx, filepath.Join(cli.PKIDir(), pki.GossipKeyName), hosts,
					cli.GossipKeyOptions{Out: cmd.OutOrStdout()})
			})
		},
	}
	cmd.Flags().StringVar(&sshUser, "ssh-user", "root", "user to SSH to each host as")
	return cmd
}

// newHostRotateGossipKeyCmd replaces the cluster gossip key without a restart
// and without a partition.
func newHostRotateGossipKeyCmd() *cobra.Command {
	var sshUser string
	var grace, timeout time.Duration
	cmd := &cobra.Command{
		Use:   "rotate-gossip-key",
		Short: "Replace the cluster gossip encryption key on every host, live",
		Long: `Replace the cluster gossip key everywhere, with no restart and no partition.

Every host must be reachable over SSH and its daemon running. The rotation is
three fleet-wide phases, and each waits until every host's daemon reports it has
LOADED the phase (not merely received the file) before the next begins:

  1. the new key is accepted everywhere; the old one still encrypts
  2. the new key encrypts; the old one is still accepted, for --grace
  3. the old key is removed

Putting the new key first in one step would cut off every host that has not yet
loaded it. If the command stops part-way - a host down, a timeout, Ctrl-C - the
cluster is safe as it stands; run it again and it settles every host on one key,
then run it once more to rotate.

Run it from the machine that holds the cluster's gossip key (the one that ran
'lv host init' or 'lv host install-gossip-key'); that copy is updated as it goes.
Rotate after removing a host you no longer trust: a removed host still knows the key.

  lv host rotate-gossip-key
  lv host rotate-gossip-key --grace 2m --timeout 5m`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				hosts, closeAll, err := cli.SSHGossipKeyHosts(ctx, c, sshUser)
				if err != nil {
					return err
				}
				defer closeAll()
				return cli.RotateGossipKey(ctx, filepath.Join(cli.PKIDir(), pki.GossipKeyName), hosts,
					cli.GossipKeyOptions{Out: cmd.OutOrStdout(), Grace: grace, Timeout: timeout})
			})
		},
	}
	cmd.Flags().StringVar(&sshUser, "ssh-user", "root", "user to SSH to each host as")
	cmd.Flags().DurationVar(&grace, "grace", 30*time.Second,
		"how long the old key stays accepted after every host encrypts with the new one")
	cmd.Flags().DurationVar(&timeout, "timeout", 2*time.Minute,
		"how long each phase waits for every host to load it before stopping")
	return cmd
}
