package main

import (
	"bytes"
	"fmt"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
)

// Field is one contributor to a marshaled message's size.
type Field struct {
	Name  string
	Bytes int
}

// Breakdown attributes a vote's wire size to its parts, by differential
// measurement: marshal the message, then marshal it again with one field
// emptied, and attribute the difference. This is measured rather than reasoned,
// so protobuf tags and length prefixes land in the part that carries them
// instead of being silently dropped.
//
// It exists because "ML-DSA-65 votes are 3.5 KB" invites the reply "of which how
// much is actually the signature?" A reader who can see that the signature is
// 3,309 of 3,499 bytes can check the claim against FIPS 204 without trusting
// this tool at all.
func Breakdown(scheme Scheme) ([]Field, int, error) {
	sig := bytes.Repeat([]byte{0xA5}, scheme.SigBytes)

	build := func(withSig, withBlockID, withAddr bool) (int, error) {
		v := &types.Vote{
			Type:      cmtproto.PrecommitType,
			Height:    1_000_000,
			Round:     0,
			Timestamp: fixedTimestamp,
		}
		if withBlockID {
			v.BlockID = sampleBlockID()
		}
		if withAddr {
			v.ValidatorAddress = validatorAddress(1)
		}
		if withSig {
			v.Signature = sig
		}
		b, err := v.ToProto().Marshal()
		if err != nil {
			return 0, err
		}
		return len(b), nil
	}

	full, err := build(true, true, true)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal full vote: %w", err)
	}
	noSig, err := build(false, true, true)
	if err != nil {
		return nil, 0, err
	}
	noBlockID, err := build(true, false, true)
	if err != nil {
		return nil, 0, err
	}
	noAddr, err := build(true, true, false)
	if err != nil {
		return nil, 0, err
	}

	sigBytes := full - noSig
	blockIDBytes := full - noBlockID
	addrBytes := full - noAddr
	rest := full - sigBytes - blockIDBytes - addrBytes

	return []Field{
		{"signature", sigBytes},
		{"BlockID (hash + part set header)", blockIDBytes},
		{"validator address", addrBytes},
		{"type, height, round, timestamp, index, framing", rest},
	}, full, nil
}

// StorageProjection is what a validator set costs on disk per year, which is the
// number infrastructure teams budget against. Commit signatures are stored in
// every block forever.
type StorageProjection struct {
	Validators    int
	BlockSeconds  float64
	CommitBytes   int
	BytesPerYear  int64
	BlocksPerYear int64
}

func ProjectStorage(commitBytes, validators int, blockSeconds float64) StorageProjection {
	blocks := int64(365 * 24 * 60 * 60 / blockSeconds)
	return StorageProjection{
		Validators:    validators,
		BlockSeconds:  blockSeconds,
		CommitBytes:   commitBytes,
		BlocksPerYear: blocks,
		BytesPerYear:  blocks * int64(commitBytes),
	}
}

func humanBytes(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(u), 0
	for m := n / u; m >= u; m /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

var _ = time.Second
