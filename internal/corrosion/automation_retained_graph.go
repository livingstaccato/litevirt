package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/litevirt/litevirt/internal/pki"
	"strings"
)

// This verifies consumed immutable graph data. It cannot authenticate a holder,
// establish adoption, publish completion or construct a current proof.
func verifyRetainedGraph(ctx context.Context, tx *LocalTx, holder retainedHolderBody, directory retainedDirectoryReader, view *pki.HostTrust) (out retainedAggregateRebuild, err error) {
	var digest retainedDirectoryDigest
	var header retainedAggregateHeader
	var receipt retainedImportReceipt
	var headerRaw, receiptRaw, binding []byte
	var sourceCount, nativeCount, expectedNative int64
	err = directory.walk(ctx, tx, func(n int64, d retainedObjectDescriptor) error {
		raw, _ := json.Marshal(d)
		if err := digest.add(n, raw); err != nil {
			return err
		}
		_, _, kind := retainedObjectSections(d.Kind)
		address, e := retainedAddress(strings.Split(directory.address.namespace, ":")[1], n, d.Source, d.OriginalIdentity, kind)
		if e != nil {
			return e
		}
		if e = address.walk(ctx, tx, d, nil); e != nil {
			return e
		}
		if kind == retainedMetadataStream {
			body, e := address.metadata(ctx, tx, d)
			if e != nil {
				return e
			}
			domain := ""
			switch d.Kind {
			case "header":
				headerRaw = body
				header, e = decodeRetainedHeader(body)
				domain = retainedHeaderDomain
			case "receipt":
				receiptRaw = body
				receipt, e = decodeRetainedReceipt(body)
				domain = retainedReceiptDomain
			case "binding":
				binding = body
			}
			if e != nil {
				return e
			}
			id := sourceDigest(body)
			if domain != "" {
				id = sourceDigest([]byte(domain), body)
			}
			if id != d.OriginalIdentity || d.Source != holder.Donor || d.Incarnation != holder.DonorIncarnation {
				return errors.New("retained graph metadata identity differs")
			}
		}
		switch d.Kind {
		case "source":
			sourceCount++
		case "native":
			nativeCount++
		case "local":
			expectedNative = d.ComponentInventories[16].Records
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	root, graph, objects, evidenceObjects, _, evidenceBytes, err := digest.finish()
	if err != nil {
		return out, err
	}
	if holder.DirectoryRoot != root || holder.DirectoryObjects != objects || directory.objects != objects || holder.DirectoryBytes != digest.descriptorBytes {
		return out, errors.New("retained complete directory commitment differs")
	}
	if sourceCount != int64(len(header.Roster)) || nativeCount != expectedNative {
		return out, errors.New("retained directory has unreferenced originals")
	}
	original, aggregate, err := header.originalBinding(binding)
	if err != nil {
		return out, err
	}
	next := original.value.Facts.Next
	headRaw, _ := json.Marshal(header.Head)
	if next == nil || receipt.Host != holder.Donor || receipt.Incarnation != holder.DonorIncarnation || receipt.Generation != holder.Generation || receipt.ConfigDigest != holder.ConfigDigest || receipt.MembersDigest != holder.MembersDigest || header.Host != receipt.Host || header.Incarnation != receipt.Incarnation || receipt.Generation != next.Generation || receipt.ConfigDigest != sourceConfigDigest(next) || receipt.MembersDigest != next.MembersHash || receipt.Attempt != header.Attempt || receipt.BindingDigest != header.BindingDigest || receipt.AggregateDigest != aggregate || receipt.AggregateDigest != holder.AggregateDigest || receipt.HeaderDigest != sourceDigest([]byte(retainedHeaderDomain), headerRaw) || receipt.LocalInventoryDigest != header.LocalInventoryDigest || receipt.EvidenceGraphRoot != graph || receipt.EvidenceObjects != evidenceObjects || receipt.EvidenceBytes != evidenceBytes || receipt.BaselineDigest != sourceDigest(headRaw) || holder.ReceiptDigest != sourceDigest([]byte(retainedReceiptDomain), receiptRaw) {
		return out, errors.New("retained original receipt crossbinding differs")
	}
	out, err = rebuildRetainedAggregate(ctx, tx, header, binding, directory, view)
	if err != nil {
		return out, err
	}
	if receipt.ClaimsDigest != out.claims {
		return out, errors.New("retained original receipt claims differ")
	}
	return out, nil
}

func (r retainedAggregateRebuild) clean(ctx context.Context, tx *LocalTx) error {
	for _, id := range r.scratch {
		if err := aggregateCleanScratchTx(ctx, tx, id); err != nil {
			return err
		}
	}
	if r.temporary != "" {
		return aggregateDeleteTemporaryTx(ctx, tx, r.temporary)
	}
	return nil
}
