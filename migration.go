package main

import (
	"bytes"
	"fmt"

	cmtcrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cometbft/cometbft/types"
)

// Vote size is not what blocks a Cosmos migration. Three other things do, and
// this file measures or models each: what a light client has to download, what
// the round costs in CPU, and which protocol changes buy the validator set back.

// ---------------------------------------------------------------------------
// IBC light-client updates
// ---------------------------------------------------------------------------

// A 07-tendermint client update carries a SignedHeader — the block header plus
// the full Commit, one signature per validator — and, whenever the set changes,
// the ValidatorSet itself, which is one public key per validator. Both grow with
// the signature scheme, and every counterparty chain pays the cost on every
// update.
//
// This is measured with CometBFT's own Commit and ValidatorSet protobuf types,
// not with ibc-go: the 07-tendermint Header wraps exactly these, so the dominant
// terms are measurable without the IBC dependency. The figure is the payload,
// excluding the IBC envelope and any Any-typing overhead, which are small
// relative to a set of post-quantum signatures.
type ClientUpdate struct {
	Validators        int
	CommitBytes       int
	ValidatorSetBytes int
	TotalBytes        int
}

func MeasureClientUpdate(scheme Scheme, validators int) (ClientUpdate, error) {
	commitBytes, err := commitBytes(validators, scheme.SigBytes)
	if err != nil {
		return ClientUpdate{}, fmt.Errorf("commit: %w", err)
	}

	// The validator set carried on a set change: one public key and voting
	// power per validator. The key is what the scheme changes.
	vals := make([]*cmtproto.Validator, validators)
	for i := range vals {
		vals[i] = &cmtproto.Validator{
			Address: validatorAddress(i),
			PubKey: cmtcrypto.PublicKey{
				Sum: &cmtcrypto.PublicKey_Ed25519{
					Ed25519: bytes.Repeat([]byte{0xA5}, scheme.PubKeyBytes),
				},
			},
			VotingPower:      1_000_000,
			ProposerPriority: 0,
		}
	}
	set := &cmtproto.ValidatorSet{Validators: vals, TotalVotingPower: int64(validators) * 1_000_000}
	setBytes, err := set.Marshal()
	if err != nil {
		return ClientUpdate{}, fmt.Errorf("validator set: %w", err)
	}

	return ClientUpdate{
		Validators:        validators,
		CommitBytes:       commitBytes,
		ValidatorSetBytes: len(setBytes),
		TotalBytes:        commitBytes + len(setBytes),
	}, nil
}

// ---------------------------------------------------------------------------
// Realistic gossip versus the broadcast upper bound
// ---------------------------------------------------------------------------

// The ceiling model assumes a validator forwards every vote to every peer. Real
// CometBFT does not: each peer's PeerState carries a bit array of the votes that
// peer already has, and the gossip routine skips those. So the upper bound
// overstates real traffic, and by how much depends on how many peers already
// hold a vote by the time you would have sent it.
//
// This models that with one parameter, the suppression fraction, rather than
// pretending to know it. A capture on a running mesh would replace the parameter
// with a measurement; until someone does that, an operator should size against
// the upper bound and treat the modelled figure as the optimistic end.
type GossipEstimate struct {
	Validators       int
	Peers            int
	UpperBoundBytes  int64
	SuppressionRatio float64
	ModelledBytes    int64
}

func EstimateGossip(voteBytesPerValidator, validators, peers int, suppression float64) GossipEstimate {
	if suppression < 0 {
		suppression = 0
	}
	if suppression > 1 {
		suppression = 1
	}
	upper := int64(validators) * int64(voteBytesPerValidator) * int64(peers)
	return GossipEstimate{
		Validators:       validators,
		Peers:            peers,
		UpperBoundBytes:  upper,
		SuppressionRatio: suppression,
		ModelledBytes:    int64(float64(upper) * (1 - suppression)),
	}
}

// ---------------------------------------------------------------------------
// Mitigations
// ---------------------------------------------------------------------------

// Mitigation is a protocol change and what it does to the per-round vote cost.
type Mitigation struct {
	Name          string
	RoundTripCost int  // bytes per validator per round after the change
	Applicable    bool // whether it works with a lattice signature at all
	Note          string
}

// Mitigations models the changes a chain can make when the ceiling is too low.
// The point is the Applicable column: the mitigation the classical world reaches
// for first is the one post-quantum signatures take away.
func Mitigations(scheme Scheme, validators int) ([]Mitigation, error) {
	sizes, err := Measure(scheme, []int{validators})
	if err != nil {
		return nil, err
	}
	base := sizes.RoundTripBytes()

	// A compact vote drops the BlockID from every vote after the first for a
	// given block, replacing it with a short reference. The saving is the
	// BlockID, which we can measure as the gap between a nil and a block vote.
	blockIDCost := sizes.PrevoteBlock - sizes.PrevoteNil
	compact := base - 2*blockIDCost + 2*4 // a 4-byte reference in its place

	// A committee signs on behalf of the set. Cost per validator is unchanged;
	// what falls is the number of signers, so the round cost scales down.
	const committee = 100

	out := []Mitigation{
		{
			Name:          "none (as shipped)",
			RoundTripCost: base,
			Applicable:    true,
			Note:          "one prevote and one precommit, each carrying a full signature and BlockID",
		},
		{
			Name:          "compact votes (BlockID by reference)",
			RoundTripCost: compact,
			Applicable:    true,
			Note:          fmt.Sprintf("saves the %d-byte BlockID twice per round; %.1f%% of the total, because the signature dominates", blockIDCost, float64(2*blockIDCost)/float64(base)*100),
		},
		{
			Name:          "BLS-style signature aggregation",
			RoundTripCost: base,
			Applicable:    false,
			Note:          "not available: ML-DSA and SLH-DSA have no aggregation or threshold construction, which is exactly the tool the classical world uses to make large validator sets cheap",
		},
		{
			Name:          fmt.Sprintf("signing committee of %d", committee),
			RoundTripCost: base,
			Applicable:    true,
			Note:          fmt.Sprintf("per-validator cost is unchanged, but only %d validators sign, so the round cost is bounded by the committee rather than the set — the only lever here that scales", committee),
		},
	}
	return out, nil
}

// AggregationIsUnavailable states the structural fact behind the table above,
// so a reader does not have to infer it: the standardised post-quantum signature
// schemes have no aggregation, so the classical answer to "too many validators"
// does not transfer.
const AggregationIsUnavailable = "ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) are not aggregatable. " +
	"BLS lets a classical chain compress n signatures into one, which is why large validator sets " +
	"are affordable there. That option does not exist post-quantum today, so the levers are fewer " +
	"signers, fewer bytes around the signature, or more bandwidth."

// verify at compile time that types used above exist as expected
var _ = types.Commit{}
