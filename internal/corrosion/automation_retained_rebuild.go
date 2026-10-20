package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/litevirt/litevirt/internal/pki"
	"math"
	"strings"
	"time"
)

type retainedAggregateRebuild struct {
	notBefore, notAfter   time.Time
	id, claims, temporary string
	scratch               []string
	sources               []aggregateSource
	local                 aggregateLocalAudit
}

func rebuildRetainedAggregate(ctx context.Context, tx *LocalTx, h retainedAggregateHeader, binding []byte, directory retainedDirectoryReader, view *pki.HostTrust) (retainedAggregateRebuild, error) {
	var out retainedAggregateRebuild
	raw, _ := json.Marshal(h)
	h, err := decodeRetainedHeader(raw)
	if err != nil {
		return out, err
	}
	original, want, err := h.originalBinding(binding)
	if err != nil {
		return out, err
	}
	d, address, err := directory.find(ctx, tx, "binding", h.BindingDigest)
	if err != nil {
		return out, err
	}
	object := func(n int64, descriptor retainedObjectDescriptor, address retainedFrameAddress) bool {
		_, _, kind := retainedObjectSections(descriptor.Kind)
		expected, err := retainedAddress(strings.Split(directory.address.namespace, ":")[1], n, descriptor.Source, descriptor.OriginalIdentity, kind)
		return err == nil && expected == address
	}
	if !object(h.BindingObject, d, address) || d.Source != h.Host || d.Incarnation != h.Incarnation {
		return out, errors.New("retained original binding object differs")
	}
	stored, err := address.metadata(ctx, tx, d)
	if err != nil {
		return out, err
	}
	if !bytes.Equal(stored, binding) {
		return out, errors.New("retained original binding bytes differ")
	}
	inventory, err := directory.localInventory(ctx, tx)
	if err != nil {
		return out, err
	}
	if inventory != h.LocalInventoryDigest {
		return out, errors.New("retained original local inventory differs")
	}
	d, address, err = directory.find(ctx, tx, "local", h.LocalID)
	if err != nil {
		return out, err
	}
	if !object(h.LocalRowsObject, d, address) {
		return out, errors.New("retained original local object differs")
	}
	if _, err = retainedOriginalLocalDependency(ctx, tx, h, binding, address, d, directory); err != nil {
		return out, err
	}
	context := receiverAuditContext{original.id, original.value.Intent, original.value.Facts}
	namespace, err := aggregateScratchTx(ctx, tx)
	if err != nil {
		return out, err
	}
	out.scratch = append(out.scratch, namespace)
	out.local, err = auditRetainedLocal(ctx, tx, context, h, address, d, directory, namespace)
	if err != nil {
		return out, err
	}
	for _, roster := range h.Roster {
		d, address, err := directory.find(ctx, tx, "source", roster.Publication)
		if err != nil {
			return out, err
		}
		publication, err := address.publication(ctx, tx, d, original, roster, view)
		if err != nil {
			return out, err
		}
		if publication.notBefore.IsZero() || publication.notAfter.IsZero() || !publication.notBefore.Before(publication.notAfter) {
			return out, errors.New("retained original live interval unavailable")
		}
		if publication.notBefore.After(out.notBefore) {
			out.notBefore = publication.notBefore
		}
		if out.notAfter.IsZero() || publication.notAfter.Before(out.notAfter) {
			out.notAfter = publication.notAfter
		}

		namespace, err := aggregateScratchTx(ctx, tx)
		if err != nil {
			return out, err
		}
		out.scratch = append(out.scratch, namespace)
		store := receiverAuditStore{tx: tx, attempt: address.namespace, source: roster.Source, id: namespace, evidenceID: roster.Audit, publication: publication}
		audit, err := store.auditRetainedSource(ctx, context)
		if err != nil {
			return out, err
		}
		if audit.coverage != roster.Coverage {
			return out, errors.New("retained original source coverage differs")
		}
		member, _ := context.facts.Old.Member(roster.Source)
		out.sources = append(out.sources, aggregateSource{member: member, publication: publication, audit: roster.Audit, store: store, head: audit.head, coverage: audit.coverage})
	}
	rebuilt, err := aggregateRebuildClaimsTx(ctx, tx, h.Attempt, binding, out.sources, out.local)
	if err != nil {
		return out, err
	}
	if rebuilt.id != want || rebuilt.head != h.Head || rebuilt.coverage != h.Coverage {
		return out, errors.New("retained reconstructed aggregate differs")
	}
	out.id, out.temporary = rebuilt.id, rebuilt.temporary
	out.claims, err = retainedClaimsDigest(ctx, tx, out.temporary, out.id)
	return out, err
}

func (a retainedFrameAddress) metadata(ctx context.Context, tx *LocalTx, d retainedObjectDescriptor) ([]byte, error) {
	_, limits, kind := retainedDescriptorSections(d)
	if kind != retainedMetadataStream || len(limits) != 1 {
		return nil, errors.New("retained metadata object kind differs")
	}
	var raw []byte
	err := a.walk(ctx, tx, d, func(component int, n int64, body []byte) error {
		if component != 0 || int64(len(body)) > limits[0]-int64(len(raw)) {
			return errors.New("retained metadata exceeds bound")
		}
		raw = append(raw, body...)
		return nil
	})
	return raw, err
}

func (d retainedDirectoryReader) localInventory(ctx context.Context, tx *LocalTx) (string, error) {
	h := sha256.New()
	sourceHash(h, []byte("litevirt/retained-local-inventory/v1"))
	var count, total int64
	local := false
	err := d.walk(ctx, tx, func(n int64, descriptor retainedObjectDescriptor) error {
		if descriptor.Kind != "local" && descriptor.Kind != "native" {
			return nil
		}
		if descriptor.Kind == "local" {
			if local {
				return errors.New("duplicate retained local inventory")
			}
			local = true
		}
		if count == math.MaxInt64 {
			return errors.New("retained local object overflow")
		}
		count++
		for _, inv := range descriptor.ComponentInventories {
			if inv.Bytes > math.MaxInt64-total {
				return errors.New("retained local bytes overflow")
			}
			total += inv.Bytes
		}
		raw, _ := json.Marshal(descriptor)
		sourceHash(h, []byte("object"), automationCutInteger(n), raw)
		return nil
	})
	if err != nil {
		return "", err
	}
	if !local {
		return "", errors.New("retained local inventory missing")
	}
	sourceHash(h, []byte("end"), automationCutInteger(count), automationCutInteger(total))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func retainedClaimsDigest(ctx context.Context, tx *LocalTx, stored, original string) (string, error) {
	if !receiverDigest(original) {
		return "", errors.New("retained claims original identity differs")
	}
	h := sha256.New()
	sourceHash(h, []byte("litevirt/retained-import-claims/v1"))
	for _, d := range []aggregateTable{aggregateCopiesTable, aggregateMaximaTable, aggregateConflictsTable} {
		sourceHash(h, []byte("table"), []byte(d.name), []byte("bundle,"+d.names(len(d.columns))), []byte("bundle,"+d.names(d.keys)))
		var count int64
		err := aggregateWalkTable(ctx, tx, d, stored, func(row Row) error {
			if count == math.MaxInt64 {
				return errors.New("retained claims count overflow")
			}
			count++
			sourceHash(h, automationCutInteger(count), []byte("bundle"), []byte("text"), []byte(original))
			for i, v := range row.Values {
				sourceHash(h, []byte(row.Columns[i]))
				switch value := v.(type) {
				case []byte:
					sourceHash(h, []byte("blob"), value)
				case string:
					sourceHash(h, []byte("text"), []byte(value))
				case int64:
					sourceHash(h, []byte("integer"), automationCutInteger(value))
				default:
					return errors.New("retained claims field type differs")
				}
			}
			return nil
		})
		if err != nil {
			return "", err
		}
		sourceHash(h, []byte("end"), automationCutInteger(count))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
