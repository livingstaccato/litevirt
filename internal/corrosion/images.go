package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/hlc"
)

// ImageRecord represents a VM base image.
type ImageRecord struct {
	Name      string
	Format    string
	SourceURL string
	Checksum  string
	SizeBytes int64
	CreatedAt string
	UpdatedAt string
}

// ImageHostRecord tracks which hosts have a copy of an image.
type ImageHostRecord struct {
	ImageName   string
	HostName    string
	Path        string
	Status      string
	PulledAt    string
	ProgressPct float32
}

// imageDeletedAtSQL is the images row's one write of deleted_at: DeleteImage
// sets it, and ReviveImage clears it (a NULL deleted_at) behind its insert.
const imageDeletedAtSQL = `UPDATE images SET deleted_at = ?, updated_at = ? WHERE name = ?`

// imageInsertSQL is the images row's insert. On this host INSERT OR REPLACE
// writes a whole new row; a peer applies it as a column-preserving upsert of
// the columns it names (insertUpsertRewrite), and deleted_at is not one of
// them, so a peer's tombstone survives it.
const imageInsertSQL = `INSERT OR REPLACE INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`

func imageInsert(img ImageRecord, updatedAt string) Statement {
	return Statement{SQL: imageInsertSQL,
		Params: []interface{}{img.Name, img.Format, img.SourceURL, img.Checksum, img.SizeBytes, nowRFC3339(), updatedAt}}
}

// imageRevive is DeleteImage's statement with a NULL deleted_at: it makes the
// row live on every host that applies it (ReviveImage).
func imageRevive(name, updatedAt string) Statement {
	return Statement{SQL: imageDeletedAtSQL, Params: []interface{}{nil, updatedAt, name}}
}

// InsertImage creates or replaces an image record WITHOUT reviving a deleted
// one: a peer that holds the name's tombstone keeps it, and anti-entropy then
// takes it back to this host's row, so a delete wins. A copy from a peer — a
// push, an auto-pull or heal — writes this one, so a copy that finishes after
// lv image rm never brings the image back (review round 1, I-1). The caller
// refuses outright when the row already reads deleted here (grpcapi
// Server.recordImage).
func InsertImage(ctx context.Context, c *Client, img ImageRecord) error {
	return c.ExecuteBatch(ctx, []Statement{imageInsert(img, c.NowTS())})
}

// ReviveImage is InsertImage that also makes the image live on every host, a
// deleted image's name included (lab 2 F-1): an operator's import, pull,
// build or compose download under that name. The insert alone leaves each peer's tombstone in place (see
// imageInsertSQL); anti-entropy then took the tombstone back to this host's
// row, the image left `lv image ls` everywhere, and a prune removed its
// current file as a deleted image's.
//
// So the insert is followed, in the same entry and at a strictly later clock,
// by DeleteImage's own statement with a NULL deleted_at. Every supported build
// applies that shape as a full-PK LWW update (v1.3.0 emits it itself), so a
// peer on an older build revives the row exactly as one on this build: no
// capability gates it. A peer whose row is newer than both keeps its own, as
// for any LWW write. A peer with no row yet gets it from the insert, and the
// update then changes nothing.
//
// One window converges to a mixed row (review round 1, m-1): a delete stamped
// strictly between the insert's clock T1 and the revive's T2 — about one
// clock tick apart. A peer then skips the insert (its delete is newer than
// T1) and applies the revive (T2 is newer), so it ends live with the OLD
// content's checksum, format and size at T2 while this host holds the new
// content at T2; anti-entropy settles the tie by content and may pick the old
// checksum everywhere. A revive carrying the full row would close it, but that
// is a new statement shape and would need the release latch, as
// imageHostReviveSQL does.
func ReviveImage(ctx context.Context, c *Client, img ImageRecord) error {
	clk := ReserveImageClocks(c)
	return c.ExecuteBatch(ctx, []Statement{imageInsert(img, clk.Insert), imageRevive(img.Name, clk.Revive)})
}

// ImageClocks are the clocks of one record of an image: its catalog insert's
// and revive's, Insert strictly before Revive, and this host's image_hosts
// row's (Host).
type ImageClocks struct{ Insert, Revive, Host string }

// ReserveImageClocks takes, now, the clocks a later RecordImage and
// RecordImageHost write at (review re-review 1, R-m1). An operation reserves
// them as it begins, so a delete stamped after that — on any host — is newer
// than the record, and LWW and anti-entropy keep the delete on every replica
// even when it reaches the recording host only after the record is written.
func ReserveImageClocks(c *Client) ImageClocks {
	ins := c.NowTS()
	rev := c.NowTS() // NowTS is strictly monotonic
	return ImageClocks{Insert: ins, Revive: rev, Host: c.NowTS()}
}

// ImageRecordOutcome is what RecordImage did.
type ImageRecordOutcome int

const (
	// ImageRecordWritten: the catalog row was written at the reserved clocks.
	ImageRecordWritten ImageRecordOutcome = iota
	// ImageRecordSuperseded: nothing was written. The row here is not
	// deleted since the operation began, but was written at or after its
	// reserved insert clock: a newer record of the image (another copy, pull
	// or import of it).
	ImageRecordSuperseded
	// ImageRecordDeleted: nothing was written. The row here was deleted
	// since the operation began (lv image rm).
	ImageRecordDeleted
)

func (o ImageRecordOutcome) String() string {
	switch o {
	case ImageRecordWritten:
		return "written"
	case ImageRecordSuperseded:
		return "superseded"
	case ImageRecordDeleted:
		return "deleted"
	}
	return "unknown"
}

// ImageRecordResult is what RecordImage did, and, when it wrote nothing, the
// row it found.
type ImageRecordResult struct {
	Outcome ImageRecordOutcome
	// UpdatedAt and Checksum are the row's here when Outcome is not
	// ImageRecordWritten: the stamp of the record that superseded this one,
	// and that record's content (re-review 3, m-1 and m-2).
	UpdatedAt, Checksum string
}

// RecordImage writes image img's catalog row at clocks clk reserved as the
// operation began: the insert alone (a copy from a peer), or with the revive
// (revive: an operator's import, pull, build or compose download).
//
// It writes only if, in the same transaction, the row still reads as it did
// when the operation began. It reports:
//   - ImageRecordDeleted when the row reads deleted with a deleted_at other
//     than startDeleted ("" live or absent): a delete applied here since the
//     operation began.
//   - ImageRecordSuperseded when it is not, but a write here is at or after
//     clk.Insert: a newer record of the image.
//   - ImageRecordWritten otherwise, having written.
//
// A record at reserved clocks over a newer row would regress it here while
// every peer kept the newer one, so neither case writes.
//
// What remains (the reservation is a clock, not a lock): a delete stamped
// BEFORE the clocks were reserved, but not yet applied here when the record
// is written, is older than the record and loses to the revive everywhere.
// "Before" is by two hosts' clocks, so a delete issued just after the
// operation began on a host whose clock runs behind by more than that gap
// loses too.
//
// The record takes the form its row calls for (catalog_incarnation.go): on a
// node where the release feature is not available, the previous release's
// forms; a record that would give birth over a born lifetime is refused
// (ErrCatalogBirthNeedsLatch). RecordImageWithGrant is the latched node's.
func RecordImage(ctx context.Context, c *Client, img ImageRecord, revive bool, startDeleted string, clk ImageClocks) (ImageRecordResult, error) {
	return RecordImageLifetime(ctx, c, img, revive, startDeleted, clk, false, capabilities.FeatureGrant{})
}

// RecordImageLifetime is RecordImage and RecordImageWithGrant: latched says
// the release feature catalog_incarnation is available on this node, and g,
// when it is a grant of that feature, lets the record give birth.
func RecordImageLifetime(ctx context.Context, c *Client, img ImageRecord, revive bool, startDeleted string, clk ImageClocks, latched bool, g capabilities.FeatureGrant) (ImageRecordResult, error) {
	mode := catalogUnlatched
	if latched {
		mode = catalogLatched
		if g.Check(capabilities.FeatureCatalogIncarnation) == nil {
			mode = catalogBirth
		}
	}
	for attempt := 0; attempt < catalogWriteRetries; attempt++ {
		row, err := readImageRow(ctx, c.db, img.Name)
		if err != nil {
			return ImageRecordResult{}, err
		}
		res := ImageRecordResult{Outcome: ImageRecordWritten}
		if row.found {
			switch {
			case row.deletedAt != "" && row.deletedAt != startDeleted:
				res.Outcome = ImageRecordDeleted
			case lwwOrder(row.updatedAt, clk.Insert) >= 0:
				res.Outcome = ImageRecordSuperseded
			}
		}
		if res.Outcome != ImageRecordWritten {
			res.UpdatedAt, res.Checksum = row.updatedAt, row.checksum
			return res, nil
		}
		// The catalog statements of this record over row
		// (catalog_incarnation.go).
		var stmts []Statement
		live := row.found && !row.deleted
		switch {
		case live && row.incarnation != "":
			stmts = []Statement{{SQL: imageContinueSQL, Params: []interface{}{
				img.Format, img.SourceURL, img.Checksum, img.SizeBytes, clk.Insert, img.Name, row.incarnation}}}
		case row.deleted && !revive:
			// A copy never brings a deleted image back, whatever lifetime
			// its tombstone ends: it writes nothing.
			return ImageRecordResult{Outcome: ImageRecordDeleted, UpdatedAt: row.updatedAt, Checksum: row.checksum}, nil
		case live || !revive:
			// A live row born before the latch keeps the previous forms, and
			// so does a copy over no row: it gives no birth, and the birth
			// that made the image replaces its row on every replica (rule 1).
			stmts = []Statement{imageInsert(img, clk.Insert)}
			if revive {
				stmts = append(stmts, imageRevive(img.Name, clk.Revive))
			}
		case mode == catalogBirth:
			// An operator's record over no row or a tombstone: a birth.
			if err := g.Check(capabilities.FeatureCatalogIncarnation); err != nil {
				return ImageRecordResult{}, err
			}
			stmts = []Statement{{SQL: imageBirthSQL, Params: []interface{}{
				img.Name, img.Format, img.SourceURL, img.Checksum, img.SizeBytes, nowRFC3339(), clk.Insert,
				newCatalogIncarnation(clk.Insert, !row.found)}}}
		case mode == catalogLatched:
			return ImageRecordResult{}, ErrCatalogBirthNeeded
		case row.incarnation != "":
			return ImageRecordResult{}, ErrCatalogBirthNeedsLatch
		default:
			stmts = []Statement{imageInsert(img, clk.Insert), imageRevive(img.Name, clk.Revive)}
		}
		// Written only if, in the same transaction, the row still reads as
		// it did when its form was chosen; otherwise it is decided again.
		ok, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
			again, err := readImageRow(ctx, tx, img.Name)
			return err == nil && again == row, err
		}, stmts)
		if err != nil {
			return ImageRecordResult{}, err
		}
		if ok {
			return res, nil
		}
	}
	return ImageRecordResult{}, fmt.Errorf("image %q: its catalog row kept changing while it was recorded; nothing was written", img.Name)
}

// ObserveStamp advances this host's clock to ts, a row's updated_at another
// host wrote, as the replicator does for each entry it applies
// (hlc.Clock.Update): a clock reserved here afterwards (NowTS,
// ReserveImageClocks) orders after ts. A row that arrived by anti-entropy
// advanced no clock, so a peer's clock running ahead of this host's left it
// newer than every clock this host takes (re-review 3, m-1). The clock refuses
// a stamp more than hlc.MaxSkewMS ahead of this host's wall clock, and one
// that does not parse changes nothing: the caller compares again (LWWNewer).
func ObserveStamp(c *Client, ts string) {
	if c.clock == nil {
		return
	}
	if p, ok := hlc.Parse(ts); ok {
		c.clock.Update(p)
		return
	}
	at, ok := tsInstant(ts)
	if !ok {
		return
	}
	ms := at.UnixMilli()
	if at.After(time.UnixMilli(ms)) {
		ms++ // an RFC3339 stamp inside a millisecond: the clock takes the next one
	}
	c.clock.Update(hlc.Timestamp{PhysicalMS: ms})
}

// ImageDeletedAt is the deleted_at of image name's row here: "" when the row
// is live or absent.
func ImageDeletedAt(ctx context.Context, c *Client, name string) (string, error) {
	rows, err := c.Query(ctx, `SELECT COALESCE(deleted_at, '') AS d FROM images WHERE name = ?`, name)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", nil
	}
	return rows[0].String("d"), nil
}

// imageHostInsertSQL is InsertImageHost's write.
const imageHostInsertSQL = `INSERT OR REPLACE INTO image_hosts (image_name, host_name, path, status, pulled_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`

// InsertImageHost records that a host has a copy of an image.
func InsertImageHost(ctx context.Context, c *Client, ih ImageHostRecord) error {
	return c.ExecuteBatch(ctx, []Statement{imageHostWrite(ih, false, c.NowTS())})
}

// imageHostWrite is this host's image_hosts row for ih at updatedAt: the
// reviving form (ReviveImageHost) or the plain insert (InsertImageHost).
func imageHostWrite(ih ImageHostRecord, revive bool, updatedAt string) Statement {
	params := []interface{}{ih.ImageName, ih.HostName, ih.Path, ih.Status, ih.PulledAt, updatedAt}
	if revive {
		return Statement{SQL: imageHostReviveSQL, Params: params}
	}
	return Statement{SQL: imageHostInsertSQL, Params: params}
}

// RecordImageHost writes ih, an image operation's record of its copy here, in
// the reviving form (revive, ReviveImageHost) or the plain insert
// (InsertImageHost), at the clock the operation reserved as it began (at,
// ImageClocks.Host): a delete stamped after the start is then newer than the
// row on every host, this one too (re-review 2, m-1). When a write here to
// the row is already at or after at — a pull's progress, or another
// operation's record — it writes at a fresh clock instead, so the row never
// regresses here while a peer keeps the newer one; a delete stamped before
// that write then loses to the row.
func RecordImageHost(ctx context.Context, c *Client, ih ImageHostRecord, revive bool, at string) error {
	ok, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		var updatedAt string
		err := tx.QueryRowContext(ctx,
			`SELECT COALESCE(updated_at, '') FROM image_hosts WHERE image_name = ? AND host_name = ?`, ih.ImageName, ih.HostName).
			Scan(&updatedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		return lwwOrder(updatedAt, at) < 0, nil
	}, []Statement{imageHostWrite(ih, revive, at)})
	if err != nil || ok {
		return err
	}
	return c.ExecuteBatch(ctx, []Statement{imageHostWrite(ih, revive, c.NowTS())})
}

// imageHostReviveSQL is InsertImageHost's write as an explicit upsert that
// clears the row's deleted_at: a host's copy of an image imported again under
// a deleted image's name. Its insert shape alone leaves a peer's tombstone in
// place (the peer applies it column-preserving), and anti-entropy then takes
// the tombstone back to the writer's row (lab 2 F-1): the image lists on no
// host, no peer pulls it, and placement refuses it.
//
// A host on a build before release_2026_11_v1 does not know this shape, and
// an unknown shape back-pressures the sender's whole stream to it. So it is
// written only once the release token has durably latched (grpcapi
// Server.recordImageHost), exactly as the replication compare-and-set is, and
// it is listed in latchGatedShapes, which pins every such shape per token.
const imageHostReviveSQL = `INSERT INTO image_hosts (image_name, host_name, path, status, pulled_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(image_name, host_name) DO UPDATE SET
		   path = excluded.path,
		   status = excluded.status,
		   pulled_at = excluded.pulled_at,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`

// ReviveImageHost is InsertImageHost that also clears the row's tombstone on
// every host that applies it. Only once the release token has latched (see
// imageHostReviveSQL); after that it is every image_hosts write's form,
// whatever the row reads here — the delete may not have reached this host
// yet (review round 1, I-2).
func ReviveImageHost(ctx context.Context, c *Client, ih ImageHostRecord) error {
	return c.ExecuteBatch(ctx, []Statement{imageHostWrite(ih, true, c.NowTS())})
}

// UpdateImageHostProgress updates the download progress for a pulling image.
func UpdateImageHostProgress(ctx context.Context, c *Client, imageName, hostName string, pct float32) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE image_hosts SET progress_pct = ?, updated_at = ? WHERE image_name = ? AND host_name = ?`,
		pct, now, imageName, hostName,
	)
}

// UpdateImageHostStatus sets the status of an image on a host.
func UpdateImageHostStatus(ctx context.Context, c *Client, imageName, hostName, status string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE image_hosts SET status = ?, updated_at = ? WHERE image_name = ? AND host_name = ?`,
		status, now, imageName, hostName,
	)
}

// ListImages returns all images.
func ListImages(ctx context.Context, c *Client) ([]ImageRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, format, source_url, checksum, size_bytes, created_at, updated_at
		 FROM images WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}

	images := make([]ImageRecord, len(rows))
	for i, r := range rows {
		images[i] = ImageRecord{
			Name:      r.String("name"),
			Format:    r.String("format"),
			SourceURL: r.String("source_url"),
			Checksum:  r.String("checksum"),
			SizeBytes: r.Int64("size_bytes"),
			CreatedAt: r.String("created_at"),
			UpdatedAt: r.String("updated_at"),
		}
	}
	return images, nil
}

// GetImage returns a single image by name.
func GetImage(ctx context.Context, c *Client, name string) (*ImageRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, format, source_url, checksum, size_bytes, created_at, updated_at
		 FROM images WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}

	r := rows[0]
	return &ImageRecord{
		Name:      r.String("name"),
		Format:    r.String("format"),
		SourceURL: r.String("source_url"),
		Checksum:  r.String("checksum"),
		SizeBytes: r.Int64("size_bytes"),
		CreatedAt: r.String("created_at"),
		UpdatedAt: r.String("updated_at"),
	}, nil
}

// GetImageHosts returns hosts that have a copy of an image (all statuses) —
// of a live image only: a host row live under a deleted catalog row (a copy
// recorded on a host lv image rm had not reached yet) names no source, so an
// auto-pull, a compose deploy and placement do not count it (review re-review
// 1, R-m5).
func GetImageHosts(ctx context.Context, c *Client, imageName string) ([]ImageHostRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT ih.image_name, ih.host_name, ih.path, ih.status, ih.pulled_at, COALESCE(ih.progress_pct, 0) as progress_pct
		 FROM image_hosts ih JOIN images i ON i.name = ih.image_name AND i.deleted_at IS NULL
		 WHERE ih.image_name = ? AND ih.deleted_at IS NULL`,
		imageName)
	if err != nil {
		return nil, err
	}

	hosts := make([]ImageHostRecord, len(rows))
	for i, r := range rows {
		hosts[i] = ImageHostRecord{
			ImageName:   r.String("image_name"),
			HostName:    r.String("host_name"),
			Path:        r.String("path"),
			Status:      r.String("status"),
			PulledAt:    r.String("pulled_at"),
			ProgressPct: float32(r.Int("progress_pct")),
		}
	}
	return hosts, nil
}

// DeleteImage tombstones an image. Its deleted_at is to the nanosecond: a
// prune keeps a file published after it (grpcapi publishedAfterDelete), and a
// delete recorded to the second has to cover the whole second.
//
// A born image's delete names its incarnation (imageLifetimeDeleteSQL): it
// ends that lifetime and no later one (catalog_incarnation.go).
func DeleteImage(ctx context.Context, c *Client, name string) error {
	for attempt := 0; attempt < catalogWriteRetries; attempt++ {
		row, err := readImageRow(ctx, c.db, name)
		if err != nil {
			return err
		}
		now := c.NowTS()
		del := Statement{SQL: imageDeletedAtSQL, Params: []interface{}{nowRFC3339Nano(), now, name}}
		if row.incarnation != "" {
			del = Statement{SQL: imageLifetimeDeleteSQL, Params: []interface{}{nowRFC3339Nano(), now, name, row.incarnation}}
		}
		ok, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
			again, err := readImageRow(ctx, tx, name)
			return err == nil && again.incarnation == row.incarnation, err
		}, []Statement{
			del,
			{SQL: `UPDATE image_hosts SET deleted_at = ?, updated_at = ? WHERE image_name = ?`, Params: []interface{}{nowRFC3339(), now, name}},
		})
		if err != nil || ok {
			return err
		}
	}
	return fmt.Errorf("image %q: its catalog row kept changing while it was deleted; nothing was written", name)
}
