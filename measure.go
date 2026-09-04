package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
)

// AddressWidth is CometBFT's consensus address width. It is 20 bytes upstream
// and does not change under a post-quantum signature scheme: the address is a
// truncated hash of the public key, so a larger key does not widen it.
const AddressWidth = 20

// Sizes holds the marshaled protobuf size of each consensus message a
// validator puts on the wire, in bytes.
type Sizes struct {
	// PrevoteNil is a prevote for nil — the message sent when a validator
	// does not accept the proposal. It carries no BlockID.
	PrevoteNil int
	// PrevoteBlock is a prevote for a block, which is what the happy path
	// actually sends. It is the honest figure for steady-state gossip.
	PrevoteBlock int
	// PrecommitNil is a precommit for nil.
	PrecommitNil int
	// PrecommitBlock is a precommit for a block.
	PrecommitBlock int
	// Commits maps validator count to the marshaled size of a Commit
	// containing one signature from every validator.
	Commits map[int]int
}

// RoundTripBytes is the per-validator vote traffic for one happy-path round:
// one prevote for a block plus one precommit for a block.
func (s Sizes) RoundTripBytes() int { return s.PrevoteBlock + s.PrecommitBlock }

// fixedTimestamp keeps every measurement reproducible. Protobuf encodes a
// timestamp as seconds plus nanoseconds, so a value with a non-zero nanosecond
// part is the honest case — a round-numbered time would encode shorter than
// anything a real chain produces.
var fixedTimestamp = time.Date(2026, 9, 2, 12, 0, 0, 123456789, time.UTC)

func digest(label string) []byte {
	sum := sha256.Sum256([]byte(label))
	return sum[:]
}

// sampleBlockID is a complete, realistically sized BlockID.
func sampleBlockID() types.BlockID {
	return types.BlockID{
		Hash: digest("pq-bandwidth-block-hash"),
		PartSetHeader: types.PartSetHeader{
			Total: 1,
			Hash:  digest("pq-bandwidth-parts-hash"),
		},
	}
}

// validatorAddress returns a deterministic address of the consensus width.
// Contents never affect the marshaled size, only the length does.
func validatorAddress(i int) []byte {
	return bytes.Repeat([]byte{byte(i%251 + 1)}, AddressWidth)
}

// voteBytes marshals one vote of the given type, with or without a BlockID,
// carrying a signature of sigBytes length, and returns its wire size.
//
// The signature is a run of filler bytes: protobuf length-prefixes the field,
// so the marshaled size depends on how many bytes the signature occupies and
// not at all on their value. That is precisely why this tool can measure a
// signature scheme it does not implement.
func voteBytes(voteType cmtproto.SignedMsgType, withBlock bool, sigBytes int) (int, error) {
	blockID := types.BlockID{}
	if withBlock {
		blockID = sampleBlockID()
	}
	vote := &types.Vote{
		Type:             voteType,
		Height:           1_000_000,
		Round:            0,
		BlockID:          blockID,
		Timestamp:        fixedTimestamp,
		ValidatorAddress: validatorAddress(1),
		ValidatorIndex:   0,
		Signature:        bytes.Repeat([]byte{0xA5}, sigBytes),
	}
	marshaled, err := vote.ToProto().Marshal()
	if err != nil {
		return 0, fmt.Errorf("marshal vote: %w", err)
	}
	return len(marshaled), nil
}

// commitBytes marshals a Commit carrying one signature per validator.
func commitBytes(validators, sigBytes int) (int, error) {
	sigs := make([]types.CommitSig, validators)
	for i := range sigs {
		sigs[i] = types.CommitSig{
			BlockIDFlag:      types.BlockIDFlagCommit,
			ValidatorAddress: validatorAddress(i),
			Timestamp:        fixedTimestamp,
			Signature:        bytes.Repeat([]byte{0xA5}, sigBytes),
		}
	}
	commit := &types.Commit{
		Height:     1_000_000,
		Round:      0,
		BlockID:    sampleBlockID(),
		Signatures: sigs,
	}
	marshaled, err := commit.ToProto().Marshal()
	if err != nil {
		return 0, fmt.Errorf("marshal commit: %w", err)
	}
	return len(marshaled), nil
}

// Measure builds real CometBFT vote and commit structures for a signature
// scheme of the given size, marshals them with CometBFT's own generated
// protobuf code, and reports the wire sizes.
func Measure(scheme Scheme, validatorCounts []int) (Sizes, error) {
	var s Sizes
	var err error

	if s.PrevoteNil, err = voteBytes(cmtproto.PrevoteType, false, scheme.SigBytes); err != nil {
		return s, err
	}
	if s.PrevoteBlock, err = voteBytes(cmtproto.PrevoteType, true, scheme.SigBytes); err != nil {
		return s, err
	}
	if s.PrecommitNil, err = voteBytes(cmtproto.PrecommitType, false, scheme.SigBytes); err != nil {
		return s, err
	}
	if s.PrecommitBlock, err = voteBytes(cmtproto.PrecommitType, true, scheme.SigBytes); err != nil {
		return s, err
	}

	s.Commits = make(map[int]int, len(validatorCounts))
	for _, n := range validatorCounts {
		if s.Commits[n], err = commitBytes(n, scheme.SigBytes); err != nil {
			return s, fmt.Errorf("validators=%d: %w", n, err)
		}
	}
	return s, nil
}
