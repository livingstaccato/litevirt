package corrosion

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/litevirt/litevirt/internal/pki"
)

const (
	maxPreparedCertificateBytes = 16 << 20
	maxPreparedAcceptPEMBytes   = 256 << 10
	maxPreparedAccepts          = 4096
	maxPreparedConfigBytes      = 16 << 20
	maxPreparedMembers          = 4096
	maxProofPreparationBytes    = 64 << 20
	proofPreparationAttempts    = 3
)

var ErrProofPreparationSize = errors.New("ordinary proof preparation exceeds supported size")
var errProofPreparationAggregate = fmt.Errorf("aggregate preparation budget: %w", ErrProofPreparationSize)

var ErrProofPreparationChanged = errors.New("ordinary proof preparation changed; retry operation")

// Preflight JSON collections before Unmarshal allocates them. json.Valid
// validates syntax/escapes/depth; this pass counts the exact relevant arrays
// and decoded PEM byte lengths without allocating their string values.
func preflightProofJSON(raw string, config bool) error {
	return preflightProofJSONLimits(raw, config, maxPreparedAccepts, maxPreparedMembers, maxPreparedAcceptPEMBytes)
}

func preflightProofJSONLimits(raw string, config bool, acceptLimit, memberLimit, pemLimit int) error {
	if !json.Valid([]byte(raw)) {
		return errors.New("invalid proof JSON")
	}
	i := 0
	space := func() {
		for i < len(raw) && (raw[i] == ' ' || raw[i] == '\n' || raw[i] == '\r' || raw[i] == '\t') {
			i++
		}
	}
	stringEnd := func() (int, int) {
		start := i
		i++
		size := 0
		for raw[i] != '"' {
			if raw[i] != '\\' {
				r, n := utf8.DecodeRuneInString(raw[i:])
				size += utf8.RuneLen(r)
				i += n
				continue
			}
			i++
			if raw[i] != 'u' {
				size++
				i++
				continue
			}
			value, _ := strconv.ParseUint(raw[i+1:i+5], 16, 16)
			runeValue := rune(value)
			i += 5
			paired := false
			if runeValue >= 0xD800 && runeValue <= 0xDBFF && i+5 < len(raw) && raw[i:i+2] == "\\u" {
				next, _ := strconv.ParseUint(raw[i+2:i+6], 16, 16)
				if next >= 0xDC00 && next <= 0xDFFF {
					size += 4
					i += 6
					paired = true
				}
			}
			if !paired {
				if runeValue >= 0xD800 && runeValue <= 0xDFFF {
					size += 3
				} else {
					size += utf8.RuneLen(runeValue)
				}
			}
		}
		i++
		return start, size
	}
	var walk func(int) error
	walk = func(kind int) error {
		space()
		switch raw[i] {
		case '{':
			i++
			space()
			for raw[i] != '}' {
				start, _ := stringEnd()
				end := i
				space()
				i++
				key := ""
				if end-start <= 64 {
					_ = json.Unmarshal([]byte(raw[start:end]), &key)
				}
				child := 0
				if kind == 1 && strings.EqualFold(key, "accepts") {
					child = 2
				}
				space()
				if kind == 3 && strings.EqualFold(key, "cert_pem") && raw[i] == '"' {
					_, size := stringEnd()
					if size > pemLimit {
						return ErrProofPreparationSize
					}
				} else if err := walk(child); err != nil {
					return err
				}
				space()
				if raw[i] == ',' {
					i++
					space()
				} else {
					break
				}
			}
			i++
		case '[':
			i++
			space()
			count := 0
			for raw[i] != ']' {
				count++
				child := 0
				if kind == 2 {
					if count > acceptLimit {
						return ErrProofPreparationSize
					}
					child = 3
				}
				if kind == 4 && count > memberLimit {
					return ErrProofPreparationSize
				}
				if err := walk(child); err != nil {
					return err
				}
				space()
				if raw[i] == ',' {
					i++
					space()
				} else {
					break
				}
			}
			i++
		case '"':
			stringEnd()
		default:
			for i < len(raw) && raw[i] != ',' && raw[i] != ']' && raw[i] != '}' && raw[i] != ' ' && raw[i] != '\n' && raw[i] != '\r' && raw[i] != '\t' {
				i++
			}
		}
		return nil
	}
	kind := 1
	if config {
		kind = 4
	}
	return walk(kind)
}

func decodePreparedCertificate(raw string) (*ClaimCertificate, error) {
	if len(raw) > maxPreparedCertificateBytes {
		return nil, ErrProofPreparationSize
	}
	if err := preflightProofJSON(raw, false); err != nil {
		return nil, err
	}
	cert, err := DecodeClaimCertificate(raw)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

type proofRowDiscovery struct {
	Exists  bool
	Raw     string
	Binding [10]string
}
type proofConfigDiscovery struct {
	Exists bool
	Forced int64
	Raw    string
}
type proofCandidate struct {
	raw         string
	certificate *ClaimCertificate
	members     []VoterMember
}
type proofPreparation struct {
	ctx        context.Context
	rows       map[string]proofRowDiscovery
	configs    map[int64]proofConfigDiscovery
	members    map[int64][]VoterMember
	adopted    int64
	candidates map[string]proofCandidate
	factory    *func() *ClaimVerifier
	verifier   *ClaimVerifier
	lease      *pki.OrdinaryClaimLease
	bytes      int
	err        error
}

func (p *proofPreparation) charge(n int) error {
	if n < 0 || n > maxProofPreparationBytes-p.bytes {
		return errProofPreparationAggregate
	}
	p.bytes += n
	return nil
}

// Test-only observation of the actual stored-row body fetch; nil in production.
var proofRowBodyReadSeam func(string)

// Read lengths, not stored text, before retaining any body. The single-row
// envelope includes its identifier and every compared binding field.
func proofRowLengths(ctx context.Context, tx *sql.Tx, id string) (exists bool, lengths [11]int64, err error) {
	if len(id) > maxProofPreparationBytes {
		return false, lengths, ErrProofPreparationSize
	}
	err = tx.QueryRowContext(ctx, `SELECT length(CAST(claim_certificate AS BLOB)),length(CAST(action AS BLOB)),length(CAST(target_kind AS BLOB)),length(CAST(target_name AS BLOB)),length(CAST(dest_host AS BLOB)),length(CAST(coordinator AS BLOB)),length(CAST(relocation_token AS BLOB)),length(CAST(fence_epoch AS BLOB)),length(CAST(owner_epoch AS BLOB)),length(CAST(lease_term AS BLOB)),length(CAST(lease_key AS BLOB)) FROM runtime_action_proofs WHERE id=?`, id).Scan(&lengths[0], &lengths[1], &lengths[2], &lengths[3], &lengths[4], &lengths[5], &lengths[6], &lengths[7], &lengths[8], &lengths[9], &lengths[10])
	if errors.Is(err, sql.ErrNoRows) {
		return false, lengths, nil
	}
	if err != nil {
		return false, lengths, err
	}
	if lengths[0] > maxPreparedCertificateBytes {
		return false, lengths, ErrProofPreparationSize
	}
	total := int64(len(id))
	for _, n := range lengths {
		if n < 0 || n > int64(maxProofPreparationBytes)-total {
			return false, lengths, ErrProofPreparationSize
		}
		total += n
	}
	return true, lengths, nil
}

func (p *proofPreparation) readRow(tx *sql.Tx, id string) (proofRowDiscovery, error) {
	var row proofRowDiscovery
	exists, lengths, err := proofRowLengths(p.ctx, tx, id)
	if err != nil {
		return row, err
	}
	if err := p.charge(len(id)); err != nil {
		return row, err
	}
	if !exists {
		return row, nil
	}
	bindingBytes := 0
	for _, n := range lengths[1:] {
		bindingBytes += int(n)
	}
	if err := p.charge(bindingBytes); err != nil {
		return row, err
	}
	rawBytes := int(lengths[0])
	reused := false
	// If a new body would cross the budget, compare against already-owned raw
	// candidates inside SQLite. Never fetch an over-budget body just to dedup it.
	if rawBytes > maxProofPreparationBytes-p.bytes {
		for raw := range p.candidates {
			if len(raw) != rawBytes {
				continue
			}
			var same bool
			if err := tx.QueryRowContext(p.ctx, `SELECT CAST(claim_certificate AS BLOB)=CAST(? AS BLOB) FROM runtime_action_proofs WHERE id=?`, raw, id).Scan(&same); err != nil {
				return row, err
			}
			if same {
				row.Raw = raw
				reused = true
				break
			}
		}
	}
	if !reused {
		if err := p.charge(rawBytes); err != nil {
			return row, err
		}
	}
	if proofRowBodyReadSeam != nil {
		proofRowBodyReadSeam(id)
	}
	var fetched string
	err = tx.QueryRowContext(p.ctx, `SELECT CASE WHEN ? THEN '' ELSE claim_certificate END,action,target_kind,target_name,dest_host,coordinator,relocation_token,fence_epoch,owner_epoch,lease_term,lease_key FROM runtime_action_proofs WHERE id=?`, reused, id).Scan(&fetched, &row.Binding[0], &row.Binding[1], &row.Binding[2], &row.Binding[3], &row.Binding[4], &row.Binding[5], &row.Binding[6], &row.Binding[7], &row.Binding[8], &row.Binding[9])
	if err != nil {
		return row, err
	}
	if !reused {
		row.Raw = fetched
		if known, ok := p.candidates[fetched]; ok {
			row.Raw = known.raw
			p.bytes -= rawBytes
		}
	}
	row.Exists = true
	return row, nil
}

func proofConfigMetadata(ctx context.Context, tx *sql.Tx, gen, adopted int64) (cfg proofConfigDiscovery, length int, err error) {
	if gen < 1 || gen > adopted {
		return cfg, 0, nil
	}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM voter_configs WHERE deleted_at IS NULL AND generation>? AND generation<=? AND change LIKE 'force:%'`, gen, adopted).Scan(&cfg.Forced); err != nil {
		return cfg, 0, err
	}
	err = tx.QueryRowContext(ctx, `SELECT length(CAST(members_json AS BLOB)) FROM voter_configs WHERE generation=? AND deleted_at IS NULL`, gen).Scan(&length)
	if errors.Is(err, sql.ErrNoRows) {
		return cfg, 0, nil
	}
	if err != nil {
		return cfg, 0, err
	}
	if length < 0 || length > maxPreparedConfigBytes {
		return cfg, 0, ErrProofPreparationSize
	}
	cfg.Exists = true
	return cfg, length, nil
}

func (p *proofPreparation) addCandidate(tx *sql.Tx, raw string, charged bool) error {
	if _, ok := p.candidates[raw]; ok {
		return nil
	}
	if len(raw) > maxPreparedCertificateBytes {
		return ErrProofPreparationSize
	}
	if !charged {
		if err := p.charge(len(raw)); err != nil {
			return err
		}
	}
	cert, err := decodePreparedCertificate(raw)
	if errors.Is(err, ErrProofPreparationSize) {
		return err
	}
	candidate := proofCandidate{raw: raw, certificate: cert}
	p.candidates[raw] = candidate
	if err != nil || cert.ConfigGeneration < 1 || cert.ConfigGeneration > p.adopted {
		return nil
	}
	gen := cert.ConfigGeneration
	cfg, ok := p.configs[gen]
	if !ok {
		var length int
		cfg, length, err = proofConfigMetadata(p.ctx, tx, gen, p.adopted)
		if err != nil {
			return err
		}
		if err = p.charge(length); err != nil {
			return err
		}
		if cfg.Exists {
			if err = tx.QueryRowContext(p.ctx, `SELECT members_json FROM voter_configs WHERE generation=? AND deleted_at IS NULL`, gen).Scan(&cfg.Raw); err != nil {
				return err
			}
		}
		p.configs[gen] = cfg
		if cfg.Exists && cfg.Forced == 0 {
			err = preflightProofJSON(cfg.Raw, true)
			if errors.Is(err, ErrProofPreparationSize) {
				return err
			}
			if err == nil {
				var members []VoterMember
				if json.Unmarshal([]byte(cfg.Raw), &members) == nil {
					p.members[gen] = members
				}
			}
		}
	}
	candidate.members = p.members[gen]
	p.candidates[raw] = candidate
	return nil
}

// Discovery charges each retained body before materialization and processes it
// incrementally. Shared exact certificates and each generation's decoded member
// set remain privately owned once, rather than once per compared candidate.
func (c *Client) discoverProofPreparation(ctx context.Context, ids []string, incoming []string) (*proofPreparation, error) {
	p := &proofPreparation{ctx: ctx, rows: map[string]proofRowDiscovery{}, configs: map[int64]proofConfigDiscovery{}, members: map[int64][]VoterMember{}, candidates: map[string]proofCandidate{}, factory: c.claimCertVerifier.Load()}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tx, err := c.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(generation),0) FROM local_voter_adoption`).Scan(&p.adopted); err != nil {
		return nil, err
	}
	// Fixed-size metadata is checked across the whole chunk before an earlier
	// aggregate boundary can hide a later individually unsupported row.
	for _, id := range ids {
		if _, _, err := proofRowLengths(ctx, tx, id); err != nil {
			return nil, err
		}
	}
	for _, raw := range incoming {
		if err := p.addCandidate(tx, raw, false); err != nil {
			return nil, err
		}
	}
	for _, id := range ids {
		if _, ok := p.rows[id]; ok {
			continue
		}
		row, err := p.readRow(tx, id)
		if err != nil {
			return nil, err
		}
		p.rows[id] = row
		if err := p.addCandidate(tx, row.Raw, true); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// Before subdivision can commit a prefix, check individual decoded limits in
// every candidate in one read snapshot. This pass retains no chunk bodies or
// member collections. Each certificate is individually bounded and discarded
// before the next; configurations are length-preflighted and scanned one at a
// time. Subsequent subchunks still discover and recheck their exact own facts.
func (c *Client) preflightProofSubdivision(ctx context.Context, ids, incoming []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := c.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var adopted int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(generation),0) FROM local_voter_adoption`).Scan(&adopted); err != nil {
		return err
	}
	for _, id := range ids {
		if _, _, err := proofRowLengths(ctx, tx, id); err != nil {
			return err
		}
	}
	checked := map[int64]bool{}
	checkConfig := func(gen int64) error {
		if checked[gen] || gen < 1 || gen > adopted {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		cfg, _, err := proofConfigMetadata(ctx, tx, gen, adopted)
		if err != nil {
			return err
		}
		if cfg.Exists && cfg.Forced == 0 {
			var raw string
			if err := tx.QueryRowContext(ctx, `SELECT members_json FROM voter_configs WHERE generation=? AND deleted_at IS NULL`, gen).Scan(&raw); err != nil {
				return err
			}
			if err := preflightProofJSON(raw, true); errors.Is(err, ErrProofPreparationSize) {
				return err
			}
		}
		checked[gen] = true
		return nil
	}
	// Decode one bounded candidate to preserve the ordinary malformed-input
	// fallback exactly. Its accepts are not retained across candidates or config
	// loads; only the generation survives this helper's return.
	generation := func(raw string) (int64, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		cert, err := decodePreparedCertificate(raw)
		if errors.Is(err, ErrProofPreparationSize) {
			return 0, err
		}
		if err != nil {
			return 0, nil
		}
		return cert.ConfigGeneration, nil
	}
	for _, raw := range incoming {
		gen, err := generation(raw)
		if err != nil {
			return err
		}
		if err := checkConfig(gen); err != nil {
			return err
		}
	}
	for _, id := range ids {
		exists, _, err := proofRowLengths(ctx, tx, id)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		var raw string
		if err := tx.QueryRowContext(ctx, `SELECT claim_certificate FROM runtime_action_proofs WHERE id=?`, id).Scan(&raw); err != nil {
			return err
		}
		gen, err := generation(raw)
		raw = ""
		if err != nil {
			return err
		}
		if err := checkConfig(gen); err != nil {
			return err
		}
	}
	return nil
}

func (p *proofPreparation) prepare() error {
	if err := p.ctx.Err(); err != nil {
		return err
	}
	if p.factory == nil || *p.factory == nil {
		return nil
	}
	v := (*p.factory)()
	if v == nil {
		return nil
	}
	var leaves []*x509.Certificate
	seen := map[[32]byte]bool{}
	for _, candidate := range p.candidates {
		if len(candidate.members) == 0 {
			continue
		}
		for _, accept := range candidate.certificate.Accepts {
			leaf, err := parseCertPEM([]byte(accept.CertPEM))
			if err != nil {
				continue
			}
			hash := sha256.Sum256(leaf.Raw)
			if !seen[hash] {
				leaves = append(leaves, leaf)
				seen[hash] = true
			}
		}
	}
	view, lease, err := pki.AcquireOrdinaryClaimTrust(p.ctx, v.pkiDir, leaves, v.policyCell, maxProofPreparationBytes-p.bytes)
	if err != nil {
		if errors.Is(err, pki.ErrOrdinaryTrustBudget) {
			return errProofPreparationAggregate
		}
		if errors.Is(err, pki.ErrOrdinaryTrustSize) {
			return ErrProofPreparationSize
		}
		return err
	}
	pure := *v
	pure.ordinary = view
	if pure.policyCell != nil {
		pure.pinned, pure.noPin = pure.policyPinned, pure.policyNoPin
		if view.TrustRotatedPeers() {
			pure.pinned, pure.noPin = false, true
		}
	}
	p.verifier = &pure
	p.lease = lease
	return nil
}
func (p *proofPreparation) release() {
	if p != nil && p.lease != nil {
		p.lease.Release()
		p.lease = nil
	}
}
func (p *proofPreparation) recheck(c *Client, tx *sql.Tx) error {
	if err := p.ctx.Err(); err != nil {
		return err
	}
	if c.claimCertVerifier.Load() != p.factory {
		return ErrProofPreparationChanged
	}
	var adopted int64
	if err := tx.QueryRowContext(p.ctx, `SELECT COALESCE(MAX(generation),0) FROM local_voter_adoption`).Scan(&adopted); err != nil {
		return err
	}
	if adopted != p.adopted {
		return ErrProofPreparationChanged
	}
	for id, was := range p.rows {
		exists, _, err := proofRowLengths(p.ctx, tx, id)
		if err != nil {
			return err
		}
		if exists != was.Exists {
			return ErrProofPreparationChanged
		}
		if !exists {
			continue
		}
		// Comparison returns only a boolean: even changed stored fields are never
		// materialized into another retained row during the final transaction.
		var same bool
		err = tx.QueryRowContext(p.ctx, `SELECT CAST(claim_certificate AS BLOB)=CAST(? AS BLOB) AND CAST(action AS BLOB)=CAST(? AS BLOB) AND CAST(target_kind AS BLOB)=CAST(? AS BLOB) AND CAST(target_name AS BLOB)=CAST(? AS BLOB) AND CAST(dest_host AS BLOB)=CAST(? AS BLOB) AND CAST(coordinator AS BLOB)=CAST(? AS BLOB) AND CAST(relocation_token AS BLOB)=CAST(? AS BLOB) AND CAST(fence_epoch AS BLOB)=CAST(? AS BLOB) AND CAST(owner_epoch AS BLOB)=CAST(? AS BLOB) AND CAST(lease_term AS BLOB)=CAST(? AS BLOB) AND CAST(lease_key AS BLOB)=CAST(? AS BLOB) FROM runtime_action_proofs WHERE id=?`, was.Raw, was.Binding[0], was.Binding[1], was.Binding[2], was.Binding[3], was.Binding[4], was.Binding[5], was.Binding[6], was.Binding[7], was.Binding[8], was.Binding[9], id).Scan(&same)
		if err != nil {
			return err
		}
		if !same {
			return ErrProofPreparationChanged
		}
	}
	for gen, was := range p.configs {
		now, length, err := proofConfigMetadata(p.ctx, tx, gen, adopted)
		if err != nil {
			return err
		}
		if now.Exists != was.Exists || now.Forced != was.Forced || length != len(was.Raw) {
			return ErrProofPreparationChanged
		}
		if now.Exists {
			var same bool
			if err := tx.QueryRowContext(p.ctx, `SELECT CAST(members_json AS BLOB)=CAST(? AS BLOB) FROM voter_configs WHERE generation=? AND deleted_at IS NULL`, was.Raw, gen).Scan(&same); err != nil {
				return err
			}
			if !same {
				return ErrProofPreparationChanged
			}
		}
	}
	return nil
}
func (p *proofPreparation) verifies(raw string) bool {
	candidate, ok := p.candidates[raw]
	if !ok {
		p.err = errors.New("proof merge consulted an unprepared certificate")
		return false
	}
	if p.verifier == nil || candidate.certificate == nil || len(candidate.members) == 0 {
		return false
	}
	cert := *candidate.certificate
	return p.verifier.Verify(cert, CertExpectation{Key: cert.Key, ValueDigest: cert.ValueDigest, ConfigGeneration: cert.ConfigGeneration, Electorate: candidate.members, Quorum: MajorityOf(len(candidate.members))}) == nil
}

func proofPreparationError(err error) error { return fmt.Errorf("prepare ordinary proof: %w", err) }

func cloneProofRows(rows [][]interface{}) [][]interface{} {
	out := make([][]interface{}, len(rows))
	for i, row := range rows {
		out[i] = append([]interface{}(nil), row...)
		for j, cell := range out[i] {
			if raw, ok := cell.([]byte); ok {
				out[i][j] = append([]byte(nil), raw...)
			}
		}
	}
	return out
}

func (c *Client) mergePreparedProofChunk(table syncTable, rows [][]interface{}, insertSQL string, pkCols []string, pkIdx []int, updatedAtIdx int) (int, int, error) {
	ctx := table.mergeContext
	if ctx == nil {
		ctx = context.Background()
	}
	if len(pkCols) != 1 || pkCols[0] != "id" || len(pkIdx) != 1 || pkIdx[0] < 0 {
		return 0, 0, errors.New("proof preparation requires exact proof ID")
	}
	certIdx := indexOf(table.Columns, "claim_certificate")
	ids := make([]string, 0, len(rows))
	raws := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) != len(table.Columns) {
			continue
		}
		ids = append(ids, coerceString(row[pkIdx[0]]))
		if certIdx >= 0 {
			raws = append(raws, coerceString(row[certIdx]))
		}
	}
	for attempt := 0; attempt < proofPreparationAttempts; attempt++ {
		prepared, err := c.discoverProofPreparation(ctx, ids, raws)
		if err == nil {
			err = prepared.prepare()
		}
		if errors.Is(err, errProofPreparationAggregate) && len(rows) > 1 {
			if err := c.preflightProofSubdivision(ctx, ids, raws); err != nil {
				return 0, 0, proofPreparationError(err)
			}
			middle := len(rows) / 2
			m, s, e := c.mergePreparedProofChunk(table, rows[:middle], insertSQL, pkCols, pkIdx, updatedAtIdx)
			if e != nil {
				return m, s, e
			}
			n, t, e := c.mergePreparedProofChunk(table, rows[middle:], insertSQL, pkCols, pkIdx, updatedAtIdx)
			return m + n, s + t, e
		}
		if err != nil {
			return 0, 0, proofPreparationError(err)
		}
		table.proofPreparation = prepared
		m, s, err := c.mergeChunkTransaction(table, cloneProofRows(rows), insertSQL, pkCols, pkIdx, updatedAtIdx)
		prepared.release()
		if errors.Is(err, ErrProofPreparationChanged) {
			continue
		}
		return m, s, err
	}
	return 0, 0, ErrProofPreparationChanged
}
