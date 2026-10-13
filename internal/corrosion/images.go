package corrosion

import (
	"context"
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

func imageInsert(c *Client, img ImageRecord) Statement {
	return Statement{SQL: imageInsertSQL,
		Params: []interface{}{img.Name, img.Format, img.SourceURL, img.Checksum, img.SizeBytes, nowRFC3339(), c.NowTS()}}
}

// InsertImage creates or replaces an image record WITHOUT reviving a deleted
// one: a peer that holds the name's tombstone keeps it, and anti-entropy then
// takes it back to this host's row, so a delete wins. A copy from a peer — a
// push, an auto-pull or heal — writes this one, so a copy that finishes after
// lv image rm never brings the image back (review round 1, I-1). The caller
// refuses outright when the row already reads deleted here (grpcapi
// Server.recordImage).
func InsertImage(ctx context.Context, c *Client, img ImageRecord) error {
	return c.ExecuteBatch(ctx, []Statement{imageInsert(c, img)})
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
	ins := imageInsert(c, img)
	revived := c.NowTS() // strictly after the insert's: the receiver's LWW gate applies both
	return c.ExecuteBatch(ctx, []Statement{
		ins,
		{SQL: imageDeletedAtSQL, Params: []interface{}{nil, revived, img.Name}},
	})
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

// InsertImageHost records that a host has a copy of an image.
func InsertImageHost(ctx context.Context, c *Client, ih ImageHostRecord) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT OR REPLACE INTO image_hosts (image_name, host_name, path, status, pulled_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		ih.ImageName, ih.HostName, ih.Path, ih.Status, ih.PulledAt, now,
	)
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
	return c.Execute(ctx, imageHostReviveSQL,
		ih.ImageName, ih.HostName, ih.Path, ih.Status, ih.PulledAt, c.NowTS(),
	)
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

// GetImageHosts returns hosts that have a copy of an image (all statuses).
func GetImageHosts(ctx context.Context, c *Client, imageName string) ([]ImageHostRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT image_name, host_name, path, status, pulled_at, COALESCE(progress_pct, 0) as progress_pct
		 FROM image_hosts WHERE image_name = ? AND deleted_at IS NULL`,
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
func DeleteImage(ctx context.Context, c *Client, name string) error {
	now := c.NowTS()
	return c.ExecuteBatch(ctx, []Statement{
		{SQL: imageDeletedAtSQL, Params: []interface{}{nowRFC3339Nano(), now, name}},
		{SQL: `UPDATE image_hosts SET deleted_at = ?, updated_at = ? WHERE image_name = ?`, Params: []interface{}{nowRFC3339(), now, name}},
	})
}
