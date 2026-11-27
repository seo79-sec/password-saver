package syncsession

import (
	"context"
	"reflect"

	"password-saver/internal/replicastore"
	"password-saver/internal/syncmerge"
)

// ReconnectDiffSide identifies which snapshots contain the differing record.
type ReconnectDiffSide uint8

const (
	ReconnectLocalOnly ReconnectDiffSide = iota + 1
	ReconnectRemoteOnly
	ReconnectBoth
)

// ReconnectVersionCounts includes deletions in Versions and counts them separately.
type ReconnectVersionCounts struct {
	Versions  int
	Deletions int
}

// ReconnectRecordDiff contains only the ID and counts of differing versions.
type ReconnectRecordDiff struct {
	ID            string
	Side          ReconnectDiffSide
	Local, Remote ReconnectVersionCounts
}

// ReconnectDiff describes a verified checkpoint without exposing record content.
type ReconnectDiff struct {
	ReconnectInspection
	CheckpointHash [32]byte
	Records        []ReconnectRecordDiff
}

// PreviewReconnectDiff compares snapshots from one read of the disconnected replica.
func PreviewReconnectDiff(ctx context.Context, store reconnectReader, confirmed replicastore.ExchangeContext, remote ReconnectCheckpoint) (ReconnectDiff, error) {
	view, err := store.ReadExchange(ctx, confirmed)
	if err != nil {
		return ReconnectDiff{}, err
	}
	inspection, receiver, err := inspectReconnectView(view, confirmed, remote)
	if err != nil {
		return ReconnectDiff{}, err
	}
	diff := ReconnectDiff{ReconnectInspection: inspection, CheckpointHash: remote.CheckpointHash}
	if inspection.Comparison == ReconnectMismatch {
		diff.Records = diffReconnectRecords(view.Snapshot, receiver.Snapshot())
	}
	return diff, nil
}

// Both snapshots are ordered by record ID, with versions ordered by operation ID.
func diffReconnectRecords(local, remote []syncmerge.Record) []ReconnectRecordDiff {
	var result []ReconnectRecordDiff
	for len(local) != 0 || len(remote) != 0 {
		switch {
		case len(remote) == 0 || (len(local) != 0 && local[0].ID < remote[0].ID):
			result = append(result, ReconnectRecordDiff{ID: local[0].ID, Side: ReconnectLocalOnly, Local: reconnectVersionCounts(local[0])})
			local = local[1:]
		case len(local) == 0 || remote[0].ID < local[0].ID:
			result = append(result, ReconnectRecordDiff{ID: remote[0].ID, Side: ReconnectRemoteOnly, Remote: reconnectVersionCounts(remote[0])})
			remote = remote[1:]
		default:
			if !reflect.DeepEqual(local[0].Versions, remote[0].Versions) {
				result = append(result, ReconnectRecordDiff{ID: local[0].ID, Side: ReconnectBoth,
					Local: reconnectVersionCounts(local[0]), Remote: reconnectVersionCounts(remote[0])})
			}
			local, remote = local[1:], remote[1:]
		}
	}
	return result
}

func reconnectVersionCounts(record syncmerge.Record) ReconnectVersionCounts {
	counts := ReconnectVersionCounts{Versions: len(record.Versions)}
	for _, version := range record.Versions {
		if version.Action == syncmerge.Delete {
			counts.Deletions++
		}
	}
	return counts
}
