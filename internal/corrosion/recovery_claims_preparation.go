package corrosion

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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
					if size > maxPreparedAcceptPEMBytes {
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
					if count > maxPreparedAccepts {
						return ErrProofPreparationSize
					}
					child = 3
				}
				if kind == 4 && count > maxPreparedMembers {
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
	certificate *ClaimCertificate
	members     []VoterMember
}
type proofPreparation struct {
	ctx        context.Context
	rows       map[string]proofRowDiscovery
	configs    map[int64]proofConfigDiscovery
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

func readProofRow(ctx context.Context, tx *sql.Tx, id string) (proofRowDiscovery, error) {
	var row proofRowDiscovery
	var length int
	err := tx.QueryRowContext(ctx, `SELECT length(CAST(claim_certificate AS BLOB)) FROM runtime_action_proofs WHERE id=?`, id).Scan(&length)
	if errors.Is(err, sql.ErrNoRows) {
		return row, nil
	}
	if err != nil {
		return row, err
	}
	if length > maxPreparedCertificateBytes {
		return row, ErrProofPreparationSize
	}
	err = tx.QueryRowContext(ctx, `SELECT claim_certificate,action,target_kind,target_name,dest_host,coordinator,relocation_token,fence_epoch,owner_epoch,lease_term,lease_key FROM runtime_action_proofs WHERE id=?`, id).Scan(&row.Raw, &row.Binding[0], &row.Binding[1], &row.Binding[2], &row.Binding[3], &row.Binding[4], &row.Binding[5], &row.Binding[6], &row.Binding[7], &row.Binding[8], &row.Binding[9])
	row.Exists = err == nil
	return row, err
}
func readProofConfig(ctx context.Context, tx *sql.Tx, gen, adopted int64) (proofConfigDiscovery, error) {
	var cfg proofConfigDiscovery
	if gen < 1 || gen > adopted {
		return cfg, nil
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM voter_configs WHERE deleted_at IS NULL AND generation>? AND generation<=? AND change LIKE 'force:%'`, gen, adopted).Scan(&cfg.Forced); err != nil {
		return cfg, err
	}
	var length int
	err := tx.QueryRowContext(ctx, `SELECT length(CAST(members_json AS BLOB)) FROM voter_configs WHERE generation=? AND deleted_at IS NULL`, gen).Scan(&length)
	if errors.Is(err, sql.ErrNoRows) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if length > maxPreparedConfigBytes {
		return cfg, ErrProofPreparationSize
	}
	err = tx.QueryRowContext(ctx, `SELECT members_json FROM voter_configs WHERE generation=? AND deleted_at IS NULL`, gen).Scan(&cfg.Raw)
	cfg.Exists = err == nil
	return cfg, err
}

// discoverProofPreparation owns only DB state. It never invokes the verifier
// factory, a PKI getter, or a writer. Both exact compared candidates are owned.
func (c *Client) discoverProofPreparation(ctx context.Context, ids []string, incoming []string) (*proofPreparation, error) {
	p := &proofPreparation{ctx: ctx, rows: map[string]proofRowDiscovery{}, configs: map[int64]proofConfigDiscovery{}, candidates: map[string]proofCandidate{}, factory: c.claimCertVerifier.Load()}
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
	raws := append([]string(nil), incoming...)
	for _, id := range ids {
		if _, ok := p.rows[id]; ok {
			continue
		}
		row, err := readProofRow(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		p.rows[id] = row
		raws = append(raws, row.Raw)
	}
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(generation),0) FROM local_voter_adoption`).Scan(&p.adopted); err != nil {
		return nil, err
	}
	for _, raw := range raws {
		if _, ok := p.candidates[raw]; ok {
			continue
		}
		if err := p.charge(len(raw)); err != nil {
			return nil, err
		}
		cert, err := decodePreparedCertificate(raw)
		if errors.Is(err, ErrProofPreparationSize) {
			return nil, err
		}
		candidate := proofCandidate{certificate: cert}
		p.candidates[raw] = candidate
		if err != nil || cert.ConfigGeneration < 1 || cert.ConfigGeneration > p.adopted {
			continue
		}
		cfg, ok := p.configs[cert.ConfigGeneration]
		if !ok {
			cfg, err = readProofConfig(ctx, tx, cert.ConfigGeneration, p.adopted)
			if err != nil {
				return nil, err
			}
			if err = p.charge(len(cfg.Raw)); err != nil {
				return nil, err
			}
			p.configs[cert.ConfigGeneration] = cfg
		}
		if !cfg.Exists || cfg.Forced != 0 {
			continue
		}
		if err = preflightProofJSON(cfg.Raw, true); errors.Is(err, ErrProofPreparationSize) {
			return nil, err
		}
		if err != nil {
			continue
		}
		if err = json.Unmarshal([]byte(cfg.Raw), &candidate.members); err != nil {
			candidate.members = nil
		}
		p.candidates[raw] = candidate
	}
	return p, nil
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
		now, err := readProofRow(p.ctx, tx, id)
		if err != nil {
			return err
		}
		if now != was {
			return ErrProofPreparationChanged
		}
	}
	for gen, was := range p.configs {
		now, err := readProofConfig(p.ctx, tx, gen, adopted)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(now, was) {
			return ErrProofPreparationChanged
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
