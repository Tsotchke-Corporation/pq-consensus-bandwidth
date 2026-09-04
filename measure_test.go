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

// TestHybridIsNotDoubleTheOverhead pins the claim the README leads with in its
// hybrid section. The expectation in the public discussion on cometbft#5755 was
// that a composite Ed25519 + ML-DSA signature "would double that overhead". It
// does not, because the limbs are asymmetric: Ed25519 adds 64 bytes to a
// 3,309-byte ML-DSA-65 signature. If this ever approaches 2x, the README is
// wrong and this test says so.
func TestHybridIsNotDoubleTheOverhead(t *testing.T) {
	pure, err := lookupScheme("ml-dsa-65")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	hybrid, err := lookupScheme("composite-ed25519-ml-dsa-65")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	p, err := Measure(pure, []int{100})
	if err != nil {
		t.Fatalf("measure pure: %v", err)
	}
	h, err := Measure(hybrid, []int{100})
	if err != nil {
		t.Fatalf("measure hybrid: %v", err)
	}

	ratio := float64(h.PrecommitBlock) / float64(p.PrecommitBlock)
	if ratio > 1.10 {
		t.Errorf("hybrid precommit is %.2fx pure (%d B vs %d B); the README claims ~1.02x",
			ratio, h.PrecommitBlock, p.PrecommitBlock)
	}
	if ratio < 1.0 {
		t.Errorf("hybrid (%d B) should not be smaller than pure (%d B)", h.PrecommitBlock, p.PrecommitBlock)
	}
}

// TestSignatureDominatesTheVote pins the field breakdown: if the signature ever
// stops being the overwhelming majority of a post-quantum vote, the whole
// premise of this tool has changed.
func TestSignatureDominatesTheVote(t *testing.T) {
	scheme, err := lookupScheme("ml-dsa-65")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	fields, total, err := Breakdown(scheme)
	if err != nil {
		t.Fatalf("breakdown: %v", err)
	}
	var sig int
	for _, f := range fields {
		if f.Name == "signature" {
			sig = f.Bytes
		}
	}
	if sig == 0 {
		t.Fatal("no signature field in the breakdown")
	}
	share := float64(sig) / float64(total)
	if share < 0.95 {
		t.Errorf("signature is %.1f%% of an ML-DSA-65 precommit; the README says 96.6%%", share*100)
	}
	// The parts must account for the whole; a differential measurement that
	// leaks bytes into no category would be silently wrong.
	sum := 0
	for _, f := range fields {
		sum += f.Bytes
	}
	if sum != total {
		t.Errorf("breakdown sums to %d B but the message is %d B", sum, total)
	}
}

// TestPQIdentityAloneDoesNotSecureRecordedTraffic is the assertion behind the
// finding. Upgrading the node identity key to a post-quantum scheme makes the
// handshake much larger and leaves the session key derived from X25519 alone,
// so recorded traffic stays exposed. Only adding a KEM changes that.
func TestPQIdentityAloneDoesNotSecureRecordedTraffic(t *testing.T) {
	pq, err := lookupScheme("ml-dsa-65")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	upstream, err := UpstreamHandshake()
	if err != nil {
		t.Fatalf("upstream handshake: %v", err)
	}
	authOnly, err := PQAuthOnlyHandshake(pq)
	if err != nil {
		t.Fatalf("auth-only handshake: %v", err)
	}
	hybrid, err := HybridKEMHandshake(pq)
	if err != nil {
		t.Fatalf("hybrid handshake: %v", err)
	}

	if upstream.QuantumResistant {
		t.Error("upstream handshake must not be marked safe against recorded traffic")
	}
	if authOnly.QuantumResistant {
		t.Error("a post-quantum identity key alone must not be marked safe: the session key is still X25519")
	}
	if !hybrid.QuantumResistant {
		t.Error("the hybrid KEM handshake should be safe against recorded traffic")
	}

	// The README's arithmetic: the identity upgrade is the expensive half and
	// buys nothing; the KEM is the cheap half and buys everything.
	identityCost := authOnly.Total() - upstream.Total()
	kemCost := hybrid.Total() - authOnly.Total()
	if kemCost >= identityCost {
		t.Errorf("README claims the KEM (%d B) costs less than the identity upgrade (%d B)", kemCost, identityCost)
	}
}
