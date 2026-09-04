package main

import "testing"

// TestCompositeMatchesPublishedMeasurement pins the figures published for a
// composite Ed25519 + ML-DSA-65 validator profile on CometBFT v0.40.0. If a
// CometBFT upgrade changes how a vote or commit encodes, this test fails and
// the published numbers are stale — which is the point of pinning them.
//
// Note which prevote these are: the published prevote figure is a prevote for
// NIL. A happy-path prevote carries a BlockID and is larger. Both are reported
// by the tool, and the ceiling model uses the block-carrying pair.
func TestCompositeMatchesPublishedMeasurement(t *testing.T) {
	scheme, err := lookupScheme("composite-ed25519-ml-dsa-65")
	if err != nil {
		t.Fatalf("lookup scheme: %v", err)
	}

	sizes, err := Measure(scheme, []int{32, 64, 128})
	if err != nil {
		t.Fatalf("measure: %v", err)
	}

	if got, want := sizes.PrevoteNil, 3429; got != want {
		t.Errorf("prevote for nil = %d B, published figure is %d B", got, want)
	}
	if got, want := sizes.PrecommitBlock, 3499; got != want {
		t.Errorf("precommit for block = %d B, published figure is %d B", got, want)
	}

	for validators, want := range map[int]int{32: 109646, 64: 219214, 128: 438350} {
		if got := sizes.Commits[validators]; got != want {
			t.Errorf("commit at %d validators = %d B, published figure is %d B", validators, got, want)
		}
	}
}

// TestCommitGrowthIsLinearInValidators guards the claim that commit size grows
// with the validator set rather than with anything else: doubling the set must
// roughly double the commit, since each validator contributes one signature.
func TestCommitGrowthIsLinearInValidators(t *testing.T) {
	scheme, err := lookupScheme("ml-dsa-65")
	if err != nil {
		t.Fatalf("lookup scheme: %v", err)
	}
	sizes, err := Measure(scheme, []int{64, 128})
	if err != nil {
		t.Fatalf("measure: %v", err)
	}

	ratio := float64(sizes.Commits[128]) / float64(sizes.Commits[64])
	if ratio < 1.98 || ratio > 2.02 {
		t.Errorf("doubling validators changed commit size by %.4fx, want ~2x", ratio)
	}
}

// TestLargerSignaturesCostMore is the whole thesis of the tool in one
// assertion: the wire cost of consensus is set by signature size.
func TestLargerSignaturesCostMore(t *testing.T) {
	classical, err := lookupScheme("ed25519")
	if err != nil {
		t.Fatalf("lookup ed25519: %v", err)
	}
	pq, err := lookupScheme("ml-dsa-87")
	if err != nil {
		t.Fatalf("lookup ml-dsa-87: %v", err)
	}

	small, err := Measure(classical, []int{128})
	if err != nil {
		t.Fatalf("measure ed25519: %v", err)
	}
	large, err := Measure(pq, []int{128})
	if err != nil {
		t.Fatalf("measure ml-dsa-87: %v", err)
	}

	if large.Commits[128] <= small.Commits[128] {
		t.Fatalf("ml-dsa-87 commit (%d B) should exceed ed25519 commit (%d B)",
			large.Commits[128], small.Commits[128])
	}
}

// TestCeilingIsNotSearchLimited catches the failure mode that produced a
// degenerate table on the first attempt at this model: if the search bound is
// too low, every cell reports the bound and the table describes the search
// rather than the network.
func TestCeilingIsNotSearchLimited(t *testing.T) {
	scheme, err := lookupScheme("composite-ed25519-ml-dsa-65")
	if err != nil {
		t.Fatalf("lookup scheme: %v", err)
	}
	sizes, err := Measure(scheme, []int{128})
	if err != nil {
		t.Fatalf("measure: %v", err)
	}

	c := DeriveCeiling(sizes.RoundTripBytes(), Budget{
		LinkBitsPerSec: 1_000_000_000, RoundSeconds: 1, Peers: 50,
	})
	if c.LimitedBySearch {
		t.Error("ceiling hit the search bound; the reported figure describes the search, not the link")
	}
	if c.MaxValidators <= 0 {
		t.Errorf("ceiling = %d validators, want a positive bound", c.MaxValidators)
	}
}
