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
// sets it, and InsertImage clears it (a NULL deleted_at) behind its insert.
const imageDeletedAtSQL = `UPDATE images SET deleted_at = ?, updated_at = ? WHERE name = ?`

// InsertImage creates or replaces an image record, and makes it a live image
// on every host, a deleted image's name included (lab 2 F-1).
//
// The insert alone does not do that. INSERT OR REPLACE writes a whole new row
// here, but a peer applies the replicated insert as a column-preserving upsert
// of the columns it names (insertUpsertRewrite), and deleted_at is not one of
// them: a peer holding the name's tombstone kept it, with the import's
// checksum and clock, and anti-entropy then took the tombstone back to this
// host's row. The image left `lv image ls` everywhere, and a prune removed
// its current file as a deleted image's.
//
// So the insert is followed, in the same entry and at a later clock, by
// DeleteImage's own statement with a NULL deleted_at. Every build since the
// statement shape ledger knows that shape (a full-PK LWW update), so a peer on
// an older build revives the row exactly as one on this build: no capability
// gates it, and none is needed. A peer whose row is newer than both keeps its
// own, as for any LWW write. A peer that has no row yet gets it from the
// insert, and the update then changes nothing.
func InsertImage(ctx context.Context, c *Client, img ImageRecord) error {
	inserted := c.NowTS()
	revived := c.NowTS() // strictly after inserted: the receiver's LWW gate applies both
	return c.ExecuteBatch(ctx, []Statement{
		{SQL: `INSERT OR REPLACE INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			Params: []interface{}{img.Name, img.Format, img.SourceURL, img.Checksum, img.SizeBytes, nowRFC3339(), inserted}},
		{SQL: imageDeletedAtSQL, Params: []interface{}{nil, revived, img.Name}},
	})
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
// Server.recordImageHost), exactly as the replication compare-and-set is.
const imageHostReviveSQL = `INSERT INTO image_hosts (image_name, host_name, path, status, pulled_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(image_name, host_name) DO UPDATE SET
		   path = excluded.path,
		   status = excluded.status,
		   pulled_at = excluded.pulled_at,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`

// ReviveImageHost is InsertImageHost over a deleted row: it records that a
// host has a copy of an image, and clears the row's tombstone on every host
// that applies it. Only once the release token has latched (see
// imageHostReviveSQL).
func ReviveImageHost(ctx context.Context, c *Client, ih ImageHostRecord) error {
	return c.Execute(ctx, imageHostReviveSQL,
		ih.ImageName, ih.HostName, ih.Path, ih.Status, ih.PulledAt, c.NowTS(),
	)
}

// ImageHostDeleted reports whether host's row for image is here and deleted:
// the row lv image rm left, which a plain InsertImageHost cannot revive on a
// peer.
func ImageHostDeleted(ctx context.Context, c *Client, imageName, hostName string) (bool, error) {
	rows, err := c.Query(ctx,
		`SELECT 1 AS one FROM image_hosts WHERE image_name = ? AND host_name = ? AND deleted_at IS NOT NULL`,
		imageName, hostName)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
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
