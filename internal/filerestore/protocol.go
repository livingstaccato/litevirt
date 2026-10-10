// Package filerestore is the host side of single-file restore: it boots a
// throwaway restore VM on a backup and talks to the agent inside it
// (internal/filerestore/agent), without the host ever mounting or parsing
// the backed-up filesystem (docs/design/backup-file-restore.md).
//
// Everything that comes back from the VM is untrusted: listings are
// validated and an extraction's record stream is rebuilt into a tar archive
// entry by entry (sanitize.go), with bounded names, sizes, counts and memory,
// and streamed to the caller. Nothing is written to a host path the guest's
// data chose.
package filerestore

import "github.com/litevirt/litevirt/internal/filerestore/wire"

// Protocol types and limits, re-exported for callers of this package.
type (
	Entry  = wire.Entry
	Volume = wire.Volume
)

const (
	KindFS            = wire.KindFS
	KindArchive       = wire.KindArchive
	TypeFile          = wire.TypeFile
	TypeDir           = wire.TypeDir
	TypeSymlink       = wire.TypeSymlink
	TypeOther         = wire.TypeOther
	MaxListEntries    = wire.MaxListEntries
	MaxVolumes        = wire.MaxVolumes
	MaxRequestPaths   = wire.MaxRequestPaths
	MaxPathLen        = wire.MaxPathLen
	DefaultMaxBytes   = wire.DefaultMaxBytes
	DefaultMaxEntries = wire.DefaultMaxEntries
)

// ErrBadPath is returned for a request path that is not a clean archive path.
var ErrBadPath = wire.ErrBadPath

// CleanArchivePath validates and normalizes a caller-supplied archive path.
func CleanArchivePath(p string) (string, error) { return wire.CleanArchivePath(p) }

// SplitVolume splits a clean archive path into volume and path.
func SplitVolume(p string) (vol, rel string) { return wire.SplitVolume(p) }

// Escape makes text from a restore VM safe to print (wire.Escape).
func Escape(s string) string { return wire.Escape(s) }
