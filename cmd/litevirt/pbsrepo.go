package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/litevirt/litevirt/internal/pbsstore"
)

// newBackupRepoCmd groups commands that operate on a local backup
// repository directly. Repo operations are host-local (or NFS-mounted)
// — they don't need to round-trip the daemon, which keeps GC and
// verify cheap to run from a backup host without litevirtd installed.
func newBackupRepoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repo",
		Short: "Manage litevirt backup repositories (PBS-equivalent dedup chunk store)",
	}
	cmd.AddCommand(
		newBackupRepoInitCmd(),
		newBackupRepoListCmd(),
		newBackupRepoVerifyCmd(),
		newBackupRepoGCCmd(),
		newBackupRepoPruneCmd(),
		newBackupRepoSyncCmd(),
		newBackupRepoSetCompressionCmd(),
	)
	return cmd
}

// featureBackupZstd is the release feature that makes zstd the compression
// of new repositories. A compressed repo is schema_version 2, which a
// release without compression refuses, so it waits for the cluster's
// release token: once every host runs a build that reads it.
const featureBackupZstd = "backup_zstd"

// releaseFeatureOpen reports whether a release feature may be used, and why
// not. It is the ONE place the shared release token plugs in (feat/release-
// token: health.Checker.RequireFeature, which also records the use). Until
// that lands in this build, no release feature is open.
var releaseFeatureOpen = func(ctx context.Context, feature string) (bool, string) {
	return false, fmt.Sprintf("%s needs the cluster's release token, which this build does not carry yet", feature)
}

// zstdAllowed decides whether a repo may be made compressed: when backup_zstd
// is open, or when the operator forces it for a repo no older host reads.
func zstdAllowed(ctx context.Context, force bool) error {
	if force {
		return nil
	}
	if ok, why := releaseFeatureOpen(ctx, featureBackupZstd); !ok {
		return fmt.Errorf("zstd compression (release feature %s) is not enabled yet: %s. A compressed repository is refused by litevirt "+
			"releases without compression; pass --force if no older host or backup host reads this repository", featureBackupZstd, why)
	}
	return nil
}

func newBackupRepoInitCmd() *cobra.Command {
	var encrypted bool
	var keyPath string
	var compression string
	var force bool
	cmd := &cobra.Command{
		Use:   "init <path>",
		Short: "Create a new backup repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch compression {
			case "":
				// The default: zstd once backup_zstd is open, none until then.
				compression = pbsstore.CompressionNone
				if ok, _ := releaseFeatureOpen(cmd.Context(), featureBackupZstd); ok {
					compression = pbsstore.CompressionZstd
				}
			case pbsstore.CompressionZstd:
				if err := zstdAllowed(cmd.Context(), force); err != nil {
					return err
				}
			}
			opts := pbsstore.InitOptions{Compression: compression}
			var key []byte
			if encrypted {
				if keyPath == "" {
					return errors.New("--encrypted requires --key-file (32 random bytes)")
				}
				k, err := readHexKey(keyPath)
				if err != nil {
					return err
				}
				key = k
				opts.Encryption = pbsstore.EncryptionModeAESGCM
			}
			r, err := pbsstore.InitWithOptions(args[0], opts)
			if err != nil {
				return err
			}
			if key != nil {
				if err := r.SetKey(key); err != nil {
					return err
				}
				fmt.Printf("Encrypted repository initialised at %s (compression: %s)\n", r.Root(), r.Compression())
				fmt.Println("Keep the key file safe — without it, no chunk can be decrypted.")
			} else {
				fmt.Printf("Repository initialised at %s (compression: %s)\n", r.Root(), r.Compression())
			}
			if r.Compression() != pbsstore.CompressionNone {
				fmt.Println("A compressed repository is not readable by litevirt releases without backup compression;",
					"use --compression none if an older host must use it.")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&encrypted, "encrypted", false, "Mark the repo as AES-256-GCM encrypted")
	cmd.Flags().StringVar(&keyPath, "key-file", "", "Path to a hex-encoded 32-byte key (only with --encrypted)")
	cmd.Flags().StringVar(&compression, "compression", "",
		"Chunk compression: zstd or none. Default: zstd once the cluster's release token has latched (feature backup_zstd), none until then")
	cmd.Flags().BoolVar(&force, "force", false, "Allow --compression zstd before the release token has latched (for a repo no older host reads)")
	return cmd
}

// newBackupRepoSetCompressionCmd changes whether an existing repo compresses
// NEW chunks. Existing chunks are never rewritten, so every backup already in
// the repo stays restorable either way.
func newBackupRepoSetCompressionCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "set-compression <path> <zstd|none>",
		Short: "Turn chunk compression on or off for new backups in a repository",
		Long: `Turn zstd chunk compression on or off for chunks written from now on.

Turning it on marks the repository schema_version 2: litevirt releases without
backup compression then refuse to open it (cleanly, before reading anything)
instead of misreading compressed chunks. Upgrade every host and backup host
that uses the repository first. The marker stays if compression is later
turned off, because compressed chunks may already be in the repository.

Turning it on waits for the cluster's release token (feature backup_zstd);
--force allows it earlier for a repository no older host reads.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if args[1] == pbsstore.CompressionZstd {
				if err := zstdAllowed(cmd.Context(), force); err != nil {
					return err
				}
			}
			r, err := pbsstore.Open(args[0])
			if err != nil {
				return err
			}
			if err := r.SetCompression(args[1]); err != nil {
				return err
			}
			fmt.Printf("Repository %s: compression %s for new chunks\n", r.Root(), r.Compression())
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Allow zstd before the release token has latched (for a repo no older host reads)")
	return cmd
}

func newBackupRepoListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls <path>",
		Short: "List snapshots in a backup repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := pbsstore.Open(args[0])
			if err != nil {
				return err
			}
			mans, err := r.ListManifests()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "TIMESTAMP\tVM\tDISK\tSIZE\tCHUNKS\tBASED ON")
			for _, m := range mans {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\n",
					m.Timestamp, m.VMName, m.DiskName, m.TotalSize, len(m.Chunks), m.BasedOn)
			}
			return w.Flush()
		},
	}
}

func newBackupRepoVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <path>",
		Short: "Recompute every referenced chunk's hash and report mismatches",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := pbsstore.Open(args[0])
			if err != nil {
				return err
			}
			stats, err := pbsstore.Verify(cmd.Context(), r)
			if err != nil {
				return err
			}
			fmt.Printf("Checked %d chunks\n", stats.ChunksChecked)
			if len(stats.Mismatches) > 0 {
				fmt.Printf("Mismatched: %d\n", len(stats.Mismatches))
				for _, id := range stats.Mismatches {
					fmt.Printf("  %s\n", id)
				}
			}
			if len(stats.Missing) > 0 {
				fmt.Printf("Missing:    %d\n", len(stats.Missing))
				for _, id := range stats.Missing {
					fmt.Printf("  %s\n", id)
				}
			}
			if len(stats.Mismatches)+len(stats.Missing) == 0 {
				fmt.Println("OK")
			}
			return nil
		},
	}
}

func newBackupRepoGCCmd() *cobra.Command {
	grace := pbsstore.DefaultChunkGracePeriod
	cmd := &cobra.Command{
		Use:   "gc <path>",
		Short: "Sweep chunks no manifest references",
		Long: "Sweep chunks no manifest references.\n\n" +
			"Unreferenced chunks younger than --grace are retained: a backup in " +
			"flight writes its chunks before its manifest, so a shorter window " +
			"risks deleting a concurrent push's data. Only lower --grace when no " +
			"push can be running against this repository.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := pbsstore.Open(args[0])
			if err != nil {
				return err
			}
			stats, err := pbsstore.GCWithOptions(cmd.Context(), r, pbsstore.GCOptions{ChunkGracePeriod: grace})
			if err != nil {
				return err
			}
			fmt.Printf("Manifests scanned: %d\n", stats.ManifestsScanned)
			fmt.Printf("Live chunks:       %d\n", stats.ChunksReferenced)
			fmt.Printf("Deleted chunks:    %d\n", stats.ChunksDeleted)
			fmt.Printf("Retained (young):  %d\n", stats.ChunksSkippedYoung)
			fmt.Printf("Bytes reclaimed:   %d\n", stats.BytesReclaimed)
			return nil
		},
	}
	cmd.Flags().DurationVar(&grace, "grace", grace,
		"retain unreferenced chunks younger than this (guards against a concurrent push)")
	return cmd
}

func newBackupRepoPruneCmd() *cobra.Command {
	var keepLast, keepDaily, keepWeekly, keepMonthly, keepYearly int
	var apply bool
	cmd := &cobra.Command{
		Use:   "prune <path>",
		Short: "Apply retention policy and drop expired manifests",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := pbsstore.Open(args[0])
			if err != nil {
				return err
			}
			plan, err := pbsstore.PlanPrune(r, pbsstore.RetentionPolicy{
				KeepLast: keepLast, KeepDaily: keepDaily, KeepWeekly: keepWeekly,
				KeepMonthly: keepMonthly, KeepYearly: keepYearly,
			})
			if err != nil {
				return err
			}
			fmt.Printf("Keep:   %d snapshots\n", len(plan.Keep))
			fmt.Printf("Delete: %d snapshots\n", len(plan.Delete))
			for _, m := range plan.Delete {
				fmt.Printf("  - %s %s/%s\n", m.Timestamp, m.VMName, m.DiskName)
			}
			if !apply {
				fmt.Println("\nDry run — re-run with --apply to delete.")
				return nil
			}
			if err := pbsstore.ApplyPrune(r, plan); err != nil {
				return err
			}
			fmt.Println("Pruned. Run `lv backup repo gc` to reclaim chunk space.")
			return nil
		},
	}
	cmd.Flags().IntVar(&keepLast, "keep-last", 0, "Keep the N most recent snapshots regardless of bucket")
	cmd.Flags().IntVar(&keepDaily, "keep-daily", 0, "Keep one snapshot per day for N days")
	cmd.Flags().IntVar(&keepWeekly, "keep-weekly", 0, "Keep one snapshot per ISO week for N weeks")
	cmd.Flags().IntVar(&keepMonthly, "keep-monthly", 0, "Keep one snapshot per month for N months")
	cmd.Flags().IntVar(&keepYearly, "keep-yearly", 0, "Keep one snapshot per year for N years")
	cmd.Flags().BoolVar(&apply, "apply", false, "Actually delete (default: dry-run)")
	return cmd
}

func newBackupRepoSyncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync <src> <dst>",
		Short: "Copy missing snapshots from src to dst (off-site DR)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, err := pbsstore.Open(args[0])
			if err != nil {
				return fmt.Errorf("open src: %w", err)
			}
			dst, err := pbsstore.Open(args[1])
			if err != nil {
				return fmt.Errorf("open dst: %w", err)
			}
			stats, err := pbsstore.SyncRepo(cmd.Context(), src, dst)
			if err != nil {
				return err
			}
			fmt.Printf("Manifests copied: %d\n", stats.ManifestsCopied)
			fmt.Printf("Chunks copied:    %d (%d skipped)\n", stats.ChunksCopied, stats.ChunksSkipped)
			fmt.Printf("Bytes copied:     %d\n", stats.BytesCopied)
			return nil
		},
	}
}

// readHexKey reads a hex-encoded 32-byte key from a file, trimming
// whitespace. The file must be 0600.
func readHexKey(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat key file: %w", err)
	}
	if st.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("key file %s must not be group/other-readable", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Trim trailing newlines / whitespace.
	for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r' || data[len(data)-1] == ' ' || data[len(data)-1] == '\t') {
		data = data[:len(data)-1]
	}
	key, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("decode key (expected 64-char hex): %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key length = %d bytes, want 32", len(key))
	}
	return key, nil
}

// keep filepath imported even when no helper consumes it (anchors
// future restore-from-repo tooling).
var _ = filepath.Join
var _ context.Context = nil
