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

// TestVerifyIsNotTheConstraint pins the CPU conclusion. The common worry is
// that post-quantum signatures make the round too slow to finalize. Measured,
// ML-DSA-65 verification is the same order as Ed25519 — it is signing that is
// slow, and signing happens twice per round rather than 2(n-1) times. If
// verification ever becomes an order of magnitude worse, the README's
// "bandwidth is the constraint, not CPU" claim is wrong and this fails.
func TestVerifyIsNotTheConstraint(t *testing.T) {
	ed, err := lookupScheme("ed25519")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	pq, err := lookupScheme("ml-dsa-65")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	edCPU, err := MeasureCPU(ed, 50)
	if err != nil {
		t.Fatalf("ed25519 cpu: %v", err)
	}
	pqCPU, err := MeasureCPU(pq, 50)
	if err != nil {
		t.Fatalf("ml-dsa-65 cpu: %v", err)
	}
	if !edCPU.Measured || !pqCPU.Measured {
		t.Fatal("both schemes should be measurable; CometBFT ships both")
	}

	// Generous bound: timing on a loaded machine is noisy, and the claim is
	// "same order", not a precise ratio.
	if pqCPU.VerifyP50 > 10*edCPU.VerifyP50 {
		t.Errorf("ML-DSA-65 verify %v is more than 10x Ed25519 %v; the README claims the same order",
			pqCPU.VerifyP50, edCPU.VerifyP50)
	}

	// Verification must be FLAT. That is what makes it safe to size a round on,
	// and it is the property that distinguishes it from signing.
	if edCPU.SignSpread() > 1.5 {
		t.Errorf("Ed25519 signing spread is %.1fx; it has no data-dependent branch and should be flat",
			edCPU.SignSpread())
	}

	// The load-bearing claim: at a realistic set and round, verification is a
	// small fraction of the budget. Sized on p95, not the median.
	f := AssessRound(100, 1.0, pqCPU.VerifyP95, 8)
	if !f.Fits {
		t.Errorf("verification of 100 validators does not fit a 1s round on 8 cores: %v", f.WithCores)
	}
	if f.Share > 0.25 {
		t.Errorf("verification is %.1f%% of a 1s round at 100 validators; the README says it is not the constraint", f.Share*100)
	}
}

// TestIBCUpdateGrowsWithTheScheme pins the migration cost that actually blocks a
// cutover on a chain with live IBC connections: every counterparty downloads a
// commit and, on a set change, the validator set.
func TestIBCUpdateGrowsWithTheScheme(t *testing.T) {
	ed, err := lookupScheme("ed25519")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	pq, err := lookupScheme("ml-dsa-65")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	edUp, err := MeasureClientUpdate(ed, 100)
	if err != nil {
		t.Fatalf("ed25519 update: %v", err)
	}
	pqUp, err := MeasureClientUpdate(pq, 100)
	if err != nil {
		t.Fatalf("ml-dsa-65 update: %v", err)
	}

	if pqUp.TotalBytes <= edUp.TotalBytes {
		t.Fatalf("post-quantum client update (%d B) should exceed classical (%d B)",
			pqUp.TotalBytes, edUp.TotalBytes)
	}
	ratio := float64(pqUp.TotalBytes) / float64(edUp.TotalBytes)
	if ratio < 20 {
		t.Errorf("client update grew only %.1fx; the README reports roughly 31x at 100 validators", ratio)
	}
	// Both halves must be present; a zero validator set would mean the
	// measurement silently lost the set-change cost.
	if pqUp.ValidatorSetBytes == 0 || pqUp.CommitBytes == 0 {
		t.Error("both the commit and the validator set must contribute to a client update")
	}
}

// TestAggregationIsMarkedUnavailable guards the one row in the mitigation table
// that carries the structural point: the classical answer to a large validator
// set does not transfer to lattice signatures.
func TestAggregationIsMarkedUnavailable(t *testing.T) {
	scheme, err := lookupScheme("ml-dsa-65")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	ms, err := Mitigations(scheme, 100)
	if err != nil {
		t.Fatalf("mitigations: %v", err)
	}

	var sawAggregation, sawCompact bool
	for _, m := range ms {
		if m.Name == "BLS-style signature aggregation" {
			sawAggregation = true
			if m.Applicable {
				t.Error("BLS aggregation must be marked unavailable for a lattice scheme")
			}
		}
		if m.Name == "compact votes (BlockID by reference)" {
			sawCompact = true
			if m.RoundTripCost >= ms[0].RoundTripCost {
				t.Error("compact votes should cost less per round than the shipped path")
			}
		}
	}
	if !sawAggregation || !sawCompact {
		t.Error("the mitigation table lost a row it is supposed to carry")
	}
}

// TestGossipModelIsBoundedByTheUpperBound guards the suppression model from
// producing a figure above the broadcast bound, which would be incoherent.
func TestGossipModelIsBoundedByTheUpperBound(t *testing.T) {
	for _, s := range []float64{-1, 0, 0.5, 1, 2} {
		g := EstimateGossip(6854, 100, 50, s)
		if g.ModelledBytes > g.UpperBoundBytes {
			t.Errorf("suppression %v produced %d B, above the upper bound %d B", s, g.ModelledBytes, g.UpperBoundBytes)
		}
		if g.ModelledBytes < 0 {
			t.Errorf("suppression %v produced negative traffic", s)
		}
	}
}

// TestRequirementInvertsTheCeiling checks the arithmetic that makes the "what
// would it take" answer exact rather than rhetorical: a requirement computed
// for a target must be consistent with the ceiling computed from that cost.
func TestRequirementInvertsTheCeiling(t *testing.T) {
	b := Budget{LinkBitsPerSec: 100_000_000, RoundSeconds: 1, Peers: 50}
	for _, target := range []Target{{"a", 36}, {"b", 100}, {"c", 180}, {"d", 1000}} {
		req := Require(target, b)
		if req.MaxCostPerRound <= 0 {
			t.Fatalf("%d validators: no cost ceiling computed", target.Validators)
		}
		// A scheme costing exactly the ceiling must admit at least the target.
		c := DeriveCeiling(int(req.MaxCostPerRound), b)
		if c.MaxValidators < target.Validators {
			t.Errorf("%d validators requires <=%d B/round, but a scheme at that cost admits only %d",
				target.Validators, req.MaxCostPerRound, c.MaxValidators)
		}
	}
}

// TestPostQuantumMovesTheThresholdItDoesNotCreateIt guards the framing the
// analysis rests on: large validator sets are already a gossip problem for
// classical signatures, and post-quantum moves the threshold rather than
// inventing the wall. If Ed25519 ever fits every target, that framing is wrong.
func TestPostQuantumMovesTheThresholdItDoesNotCreateIt(t *testing.T) {
	b := Budget{LinkBitsPerSec: 100_000_000, RoundSeconds: 1, Peers: 50}
	ed, err := lookupScheme("ed25519")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	huge, err := Assess(ed, Require(Target{"ethereum-scale", 10000}, b))
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	if huge.Feasible {
		t.Error("Ed25519 is expected NOT to fit 10,000 validators at this budget; " +
			"the claim that scale is a gossip problem before it is a PQ problem depends on it")
	}
}

// TestEveryApproachDeclaresWhatItLeavesUnsolved keeps the approach table
// honest. An entry that fixes everything and leaves nothing is marketing.
func TestEveryApproachDeclaresWhatItLeavesUnsolved(t *testing.T) {
	if len(Approaches) == 0 {
		t.Fatal("no approaches recorded")
	}
	for _, a := range Approaches {
		if a.DoesNotFix == "" {
			t.Errorf("approach %q does not say what it leaves unsolved", a.Name)
		}
		if a.Evidence == "" {
			t.Errorf("approach %q has no evidence", a.Name)
		}
		if len(a.Fixes) == 0 {
			t.Errorf("approach %q addresses nothing", a.Name)
		}
	}
	// The central distinction: at least one approach must be recorded as NOT
	// fixing vote gossip, because that is the claim the analysis turns on.
	var sawGossipGap bool
	for _, a := range Approaches {
		fixesGossip := false
		for _, f := range a.Fixes {
			if f == SurfaceVoteGossip {
				fixesGossip = true
			}
		}
		if !fixesGossip {
			sawGossipGap = true
		}
	}
	if !sawGossipGap {
		t.Error("no approach is recorded as leaving vote gossip unsolved; " +
			"that separation is the point of the table")
	}
}
