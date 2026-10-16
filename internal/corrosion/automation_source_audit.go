package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"math"
	"strings"
	"unicode/utf8"
)

const (
	maxSourceConfigBytes      = 32 << 10
	maxSourceCertificateBytes = 1 << 20
	maxSourceFieldBytes       = 4096
	maxSourceManifestBytes    = 64 << 10
	maxSourceAccepts          = 64
	maxSourceAcceptPEMBytes   = 16 << 10
)

func sourceHash(h hash.Hash, parts ...[]byte) {
	for _, b := range parts {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
}
func sourceDigest(parts ...[]byte) string {
	h := sha256.New()
	sourceHash(h, parts...)
	return hex.EncodeToString(h.Sum(nil))
}

// decodeSourceCutRow is the strict inverse of the unchanged schema69 codec1.
// It owns at most one record. The exact field count excludes trailing frames.
func decodeSourceCutRow(section int, ordinal int64, raw []byte) (Row, error) {
	fail := func() (Row, error) { return Row{}, errors.New("invalid source cut frame") }
	if section < 0 || section >= len(automationCutSections) || ordinal <= 0 || len(raw) > maxAutomationCutRecordBytes || !bytes.HasPrefix(raw, []byte("LVCUT\x01")) {
		return fail()
	}
	rest := raw[6:]
	take := func() ([]byte, bool) {
		if len(rest) < 4 {
			return nil, false
		}
		n := uint64(binary.BigEndian.Uint32(rest))
		rest = rest[4:]
		if n > uint64(len(rest)) {
			return nil, false
		}
		p := rest[:int(n)]
		rest = rest[int(n):]
		return p, true
	}
	domain, ok := take()
	if !ok || string(domain) != automationCutSections[section].name {
		return fail()
	}
	ord, ok := take()
	if !ok || len(ord) != 8 || binary.BigEndian.Uint64(ord) != uint64(ordinal) {
		return fail()
	}
	cols := strings.Split(strings.ReplaceAll(strings.ReplaceAll(automationCutSections[section].columns, "\n", ""), "\t", ""), ",")
	for i := range cols {
		cols[i] = strings.TrimSpace(cols[i])
	}
	row := Row{Columns: cols}
	for range cols {
		b, ok := take()
		if !ok || len(b) == 0 {
			return fail()
		}
		switch b[0] {
		case 0:
			if len(b) != 1 {
				return fail()
			}
			row.Values = append(row.Values, nil)
		case 1:
			if len(b) != 9 {
				return fail()
			}
			row.Values = append(row.Values, int64(binary.BigEndian.Uint64(b[1:])))
		case 2:
			if !utf8.Valid(b[1:]) {
				return fail()
			}
			row.Values = append(row.Values, string(b[1:]))
		case 3:
			row.Values = append(row.Values, bytes.Clone(b[1:]))
		default:
			return fail()
		}
	}
	if len(rest) != 0 {
		return fail()
	}
	return row, nil
}

func sourceMembers(members []VoterMember) error {
	if err := automationElectorateBudget(members); err != nil {
		return err
	}
	incs := map[string]bool{}
	for _, m := range members {
		if len(m.Name) > 253 || len(m.Incarnation) > 128 || incs[m.Incarnation] {
			return errors.New("duplicate or over-bound source member lifetime")
		}
		incs[m.Incarnation] = true
	}
	return nil
}
func sourceConfigRow(row Row) (*VoterConfig, error) {
	if len(row.Values) != 8 {
		return nil, errors.New("invalid membership fields")
	}
	if _, ok := row.Values[0].(int64); !ok {
		return nil, errors.New("invalid membership generation type")
	}
	for i := 1; i < 8; i++ {
		if row.Values[i] == nil && i == 7 {
			continue
		}
		if _, ok := row.Values[i].(string); !ok {
			return nil, errors.New("invalid membership field type")
		}
	}
	if len(row.String("members_json")) > maxSourceConfigBytes || len(row.String("certificate")) > maxSourceCertificateBytes || len(row.String("created_by")) > maxSourceFieldBytes || len(row.String("created_at")) > 128 || len(row.String("change")) > maxSourceFieldBytes || row.String("deleted_at") != "" {
		return nil, errors.New("unsupported membership record")
	}
	v := &VoterConfig{VoterConfigValue: VoterConfigValue{Generation: row.Int64("generation"), Change: row.String("change"), CreatedBy: row.String("created_by"), CreatedAt: row.String("created_at")}, MembersHash: row.String("members_hash"), Certificate: row.String("certificate")}
	if err := preflightProofJSONLimits(row.String("members_json"), true, maxSourceAccepts, MaxAutomationVoters, maxSourceAcceptPEMBytes); err != nil {
		return nil, err
	}
	if json.Unmarshal([]byte(row.String("members_json")), &v.Members) != nil || sourceMembers(v.Members) != nil || v.MembersHash != MembersHash(v.Members) || v.Generation <= 0 || IsForcedChange(v.Change) {
		return nil, errors.New("unsupported ordinary membership")
	}
	return v, nil
}
func sourceReadConfig(ctx context.Context, tx *LocalTx, g int64) (*VoterConfig, error) {
	rows, err := tx.Query(ctx, `SELECT length(CAST(members_json AS BLOB)) AS members,length(CAST(certificate AS BLOB)) AS cert,(`+automationCutRowSize(automationCutSections[8])+`) AS size FROM voter_configs WHERE generation=? LIMIT 1`, g)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 || rows[0].Int64("members") > maxSourceConfigBytes || rows[0].Int64("cert") > maxSourceCertificateBytes || rows[0].Int64("size") > maxSourceCertificateBytes+maxSourceConfigBytes+3*maxSourceFieldBytes {
		return nil, errors.New("missing or over-bound source membership")
	}
	rows, err = tx.Query(ctx, `SELECT `+automationCutSections[8].columns+` FROM voter_configs WHERE generation=? LIMIT 1`, g)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, errors.New("membership disappeared")
	}
	return sourceConfigRow(rows[0])
}
func sourceConfigDigest(v *VoterConfig) string {
	d, _ := (ClaimValue{Config: &v.VoterConfigValue}).Digest()
	return d
}

type sourceDiscovery struct {
	cut                        automationCutMetadata
	root, incarnation, lineage string
	adopted                    int64
	old, next                  *VoterConfig
	source, target             sourceHost
}

// auditSourceTx consumes genuine locally retained ordinary adoption/value
// lineage. It does not reinterpret a replica row, seal, or imported_from as a
// certificate. Destructive reseed and forced ancestry are explicitly unavailable.
func (c *Client) auditSourceTx(ctx context.Context, tx *LocalTx, r AutomationSourceRequest) (sourceDiscovery, error) {
	var out sourceDiscovery
	rows, err := tx.Query(ctx, `SELECT incarnation FROM local_voter_incarnation WHERE id=1 AND length(CAST(incarnation AS BLOB)) BETWEEN 1 AND 128`)
	if err != nil {
		return out, err
	}
	if len(rows) != 1 {
		return out, errors.New("missing source incarnation")
	}
	out.incarnation = rows[0].String("incarnation")
	rows, err = tx.Query(ctx, `SELECT (SELECT COUNT(*) FROM reseed_in_progress) AS incomplete,COALESCE((SELECT generation FROM reseed_generation WHERE id=1),0) AS reseeds,COALESCE((SELECT MAX(generation) FROM local_voter_adoption),0) AS adopted`)
	if err != nil {
		return out, err
	}
	if len(rows) != 1 || rows[0].Int64("incomplete") != 0 || rows[0].Int64("reseeds") != 0 {
		return out, errors.New("source lineage lost through reseed")
	}
	out.adopted = rows[0].Int64("adopted")
	if out.adopted < r.Generation || out.adopted == math.MaxInt64 {
		return out, errors.New("source did not adopt old generation")
	}
	h := sha256.New()
	sourceHash(h, []byte("litevirt/source-adopted-lineage/v1"), []byte(out.incarnation))
	var prev *VoterConfig
	for g := int64(1); g <= out.adopted; g++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		cfg, err := sourceReadConfig(ctx, tx, g)
		if err != nil {
			return out, err
		}
		if err := ValidateVoterChange(prev, cfg.VoterConfigValue); err != nil {
			return out, err
		}
		rows, err = tx.Query(ctx, `SELECT generation,imported_from,adopted_at FROM local_voter_adoption WHERE generation=? AND length(CAST(imported_from AS BLOB))<=? AND length(CAST(adopted_at AS BLOB)) BETWEEN 1 AND 128 LIMIT 1`, g, maxSourceFieldBytes)
		if err != nil {
			return out, err
		}
		if len(rows) != 1 {
			return out, errors.New("missing actual local adoption")
		}
		sourceHash(h, automationCutInteger(g), []byte(sourceConfigDigest(cfg)), []byte(rows[0].String("imported_from")), []byte(rows[0].String("adopted_at")))
		if g == r.Generation {
			out.old = cfg
		}
		prev = cfg
	}
	out.lineage = hex.EncodeToString(h.Sum(nil))
	member, ok := out.old.Member(c.hostName)
	if !ok || member.Incarnation != out.incarnation {
		return out, errors.New("source is not the old member lifetime")
	}
	out.next, err = sourceReadConfig(ctx, tx, r.Generation+1)
	if err != nil {
		return out, err
	}
	if err := ValidateVoterChange(out.old, out.next.VoterConfigValue); err != nil {
		return out, err
	}
	rows, err = tx.Query(ctx, `SELECT id,metadata,root,generation,incarnation FROM local_automation_cuts WHERE generation=? AND incarnation=? AND length(CAST(metadata AS BLOB))<=? AND length(id)=32 AND length(root)=64 LIMIT 1`, r.Generation, out.incarnation, maxAutomationCutMetadataBytes)
	if err != nil {
		return out, err
	}
	if len(rows) != 1 {
		return out, errors.New("no completed archived old cut")
	}
	out.cut, err = readAutomationCutMetadata(rows[0])
	if err != nil {
		return out, err
	}
	out.root = rows[0].String("root")
	if out.cut.Generation != r.Generation || out.cut.Source != c.hostName || out.cut.Incarnation != out.incarnation || out.cut.MembersHash != out.old.MembersHash {
		return out, errors.New("archived source binding differs")
	}
	if err = verifyAutomationCutRecordsTx(ctx, tx, out.cut); err != nil {
		return out, err
	}
	if err = c.auditFrozenSourceTx(ctx, tx, out); err != nil {
		return out, err
	}
	if out.adopted == r.Generation {
		st, err := readStandingTx(ctx, tx, c.hostName)
		if err != nil {
			return out, err
		}
		if !st.sealed {
			return out, errors.New("source old standing is not sealed")
		}
	}
	out.source, err = sourceReadHost(ctx, tx, c.hostName)
	if err != nil {
		return out, err
	}
	out.target, err = sourceReadHost(ctx, tx, r.Target)
	if err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) auditFrozenSourceTx(ctx context.Context, tx *LocalTx, d sourceDiscovery) error {
	var oldFound, sealed bool
	var adoptedThrough int64
	for _, section := range []int{0, 6, 7, 8} {
		for ordinal := int64(1); ordinal <= d.cut.Inventory[section].Records; ordinal++ {
			rows, err := tx.Query(ctx, `SELECT record FROM local_automation_cut_records WHERE cut_id=? AND section=? AND ordinal=? AND length(record)<=? LIMIT 1`, d.cut.ID, section, ordinal, maxAutomationCutRecordBytes)
			if err != nil {
				return err
			}
			if len(rows) != 1 {
				return errors.New("missing frozen lineage record")
			}
			row, err := decodeSourceCutRow(section, ordinal, rows[0].Bytes("record"))
			if err != nil {
				return err
			}
			if section == 0 {
				for _, i := range []int{2, 3, 4, 7, 13} {
					if _, ok := row.Values[i].(int64); !ok {
						return errors.New("invalid frozen claim integer")
					}
				}
				for _, i := range []int{0, 1, 5, 8, 10, 11, 12} {
					if row.Values[i] != nil {
						if _, ok := row.Values[i].(string); !ok {
							return errors.New("invalid frozen claim text")
						}
					}
				}
				for _, i := range []int{6, 9} {
					if row.Values[i] != nil {
						if _, ok := row.Values[i].([]byte); !ok {
							return errors.New("invalid frozen claim nonce")
						}
					}
				}
				if row.String("target_kind") == ClaimKindVoterConfig && row.Int64("owner_epoch") == d.cut.Generation && row.Int64("accepted_round") > 0 {
					key := ClaimKey{TargetKind: ClaimKindVoterConfig, OwnerEpoch: d.cut.Generation}
					if row.String("target_name") != "" || row.Int64("attempt") != 0 {
						return errors.New("invalid frozen membership key")
					}
					st, err := scanClaimRow(key, row)
					if err != nil {
						return err
					}
					if st.Accept == nil || st.Value == nil || st.Value.Config == nil || st.Accept.Voter != c.hostName || st.Accept.VoterIncarnation != d.incarnation || st.Accept.ConfigGeneration != d.cut.Generation {
						return errors.New("frozen membership seal is not this source's accept")
					}
					digest, err := st.Value.Digest()
					if err != nil || digest != st.ValueDigest {
						return errors.New("frozen membership seal value differs")
					}
					if err := ValidateVoterChange(d.old, *st.Value.Config); err != nil {
						return err
					}
					if err := auditAutomationCutAccept(*st.Accept, key, st.Accepted, d.cut.Generation, digest); err != nil {
						return err
					}
					sealed = true
				}
				continue
			}
			if _, ok := row.Values[0].(int64); !ok {
				return errors.New("invalid frozen generation type")
			}
			g := row.Int64("generation")
			if g <= 0 {
				return errors.New("invalid frozen lineage generation")
			}
			if section == 8 {
				frozen, err := sourceConfigRow(row)
				if err != nil {
					return err
				}
				if g <= d.cut.Generation {
					live, err := sourceReadConfig(ctx, tx, g)
					if err != nil {
						return err
					}
					if sourceConfigDigest(frozen) != sourceConfigDigest(live) {
						return errors.New("frozen membership differs from preserved lineage")
					}
				}
				if g == d.cut.Generation {
					oldFound = true
				}
			} else {
				for _, v := range row.Values[1:] {
					s, ok := v.(string)
					if !ok || len(s) > maxSourceFieldBytes {
						return errors.New("invalid frozen local fact")
					}
				}
				if section == 6 {
					if g != adoptedThrough+1 {
						return errors.New("frozen adoption gap")
					}
					adoptedThrough = g
					live, err := tx.Query(ctx, `SELECT generation FROM local_voter_adoption WHERE generation=? AND CAST(imported_from AS BLOB)=CAST(? AS BLOB) AND CAST(adopted_at AS BLOB)=CAST(? AS BLOB) LIMIT 1`, g, row.String("imported_from"), row.String("adopted_at"))
					if err != nil {
						return err
					}
					if len(live) != 1 {
						return errors.New("frozen adoption was replaced")
					}
				}
				if section == 7 && g == d.cut.Generation && row.String("reason") != "" && row.String("sealed_at") != "" {
					sealed = true
				}
			}
		}
	}
	if !oldFound || !sealed || adoptedThrough != d.cut.Generation {
		return errors.New("incomplete frozen source standing")
	}
	return nil
}
func (c *Client) discoverSource(ctx context.Context, r AutomationSourceRequest) (sourceDiscovery, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	tx, err := c.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return sourceDiscovery{}, err
	}
	defer tx.Rollback()
	d, err := c.auditSourceTx(ctx, &LocalTx{tx: tx}, r)
	return d, err
}

func sourceDiscoveryDigest(d sourceDiscovery) string {
	b, _ := json.Marshal(struct {
		Cut                        automationCutMetadata
		Root, Incarnation, Lineage string
		Adopted                    int64
		Old, Next                  string
		Source, Target             sourceHost
	}{d.cut, d.root, d.incarnation, d.lineage, d.adopted, sourceConfigDigest(d.old), sourceConfigDigest(d.next), d.source, d.target})
	return sourceDigest(b, []byte(d.next.Certificate))
}
