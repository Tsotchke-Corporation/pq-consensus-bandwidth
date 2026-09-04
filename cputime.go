package main

import (
	"fmt"
	"time"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/mldsa65"
)

// Bandwidth answers whether the votes fit on the link. It does not answer
// whether the round finishes, and those are different questions. A validator
// verifies every other validator's prevote and precommit inside the round, so
// verification time scales with the set exactly as bandwidth does.
//
// This file measures sign and verify with the real implementations CometBFT
// ships, because the widespread assumption that post-quantum means slower is
// only half right: ML-DSA verification is competitive with Ed25519, while
// signing is the slower side. A chain rejecting ML-DSA on a guess about CPU
// deserves the actual numbers.

// CPUProfile is measured sign and verify cost for one scheme.
type CPUProfile struct {
	Scheme      string
	Sign        time.Duration
	Verify      time.Duration
	Measured    bool
	Unavailable string // why, when the scheme has no implementation here
}

// benchmark times an operation, discarding a warm-up pass so the first
// allocation and any lazy initialisation do not land in the result.
func benchmark(iterations int, op func()) time.Duration {
	for i := 0; i < iterations/10+1; i++ {
		op()
	}
	start := time.Now()
	for i := 0; i < iterations; i++ {
		op()
	}
	return time.Since(start) / time.Duration(iterations)
}

// MeasureCPU times sign and verify for the schemes CometBFT actually
// implements. Others are reported as unavailable rather than estimated: this
// tool measures wire sizes for any scheme because protobuf does not care what
// the bytes mean, but CPU time cannot be inferred from a length.
func MeasureCPU(scheme Scheme, iterations int) (CPUProfile, error) {
	msg := []byte("pq-consensus-bandwidth canonical vote sign bytes, representative length")

	switch scheme.Name {
	case "ed25519":
		priv := ed25519.GenPrivKey()
		pub := priv.PubKey()
		sig, err := priv.Sign(msg)
		if err != nil {
			return CPUProfile{}, fmt.Errorf("ed25519 sign: %w", err)
		}
		return CPUProfile{
			Scheme:   scheme.Name,
			Sign:     benchmark(iterations, func() { _, _ = priv.Sign(msg) }),
			Verify:   benchmark(iterations, func() { _ = pub.VerifySignature(msg, sig) }),
			Measured: true,
		}, nil

	case "ml-dsa-65":
		priv, err := mldsa65.GenPrivKey()
		if err != nil {
			return CPUProfile{}, fmt.Errorf("ml-dsa-65 keygen: %w", err)
		}
		pub := priv.PubKey()
		sig, err := priv.Sign(msg)
		if err != nil {
			return CPUProfile{}, fmt.Errorf("ml-dsa-65 sign: %w", err)
		}
		return CPUProfile{
			Scheme:   scheme.Name,
			Sign:     benchmark(iterations, func() { _, _ = priv.Sign(msg) }),
			Verify:   benchmark(iterations, func() { _ = pub.VerifySignature(msg, sig) }),
			Measured: true,
		}, nil

	case "composite-ed25519-ml-dsa-65":
		// Both limbs are required, so the composite cost is the sum. Verify is
		// the cheap-limb-first case only when the classical limb rejects; an
		// honest accepting-path cost is both.
		edPriv := ed25519.GenPrivKey()
		edPub := edPriv.PubKey()
		edSig, err := edPriv.Sign(msg)
		if err != nil {
			return CPUProfile{}, err
		}
		pqPriv, err := mldsa65.GenPrivKey()
		if err != nil {
			return CPUProfile{}, err
		}
		pqPub := pqPriv.PubKey()
		pqSig, err := pqPriv.Sign(msg)
		if err != nil {
			return CPUProfile{}, err
		}
		return CPUProfile{
			Scheme: scheme.Name,
			Sign: benchmark(iterations, func() {
				_, _ = edPriv.Sign(msg)
				_, _ = pqPriv.Sign(msg)
			}),
			Verify: benchmark(iterations, func() {
				_ = edPub.VerifySignature(msg, edSig)
				_ = pqPub.VerifySignature(msg, pqSig)
			}),
			Measured: true,
		}, nil
	}

	return CPUProfile{
		Scheme:      scheme.Name,
		Unavailable: "CometBFT ships no implementation; wire size is measurable from the length, CPU time is not",
	}, nil
}

// RoundFeasibility asks the question bandwidth cannot: does the round finish?
//
// Inside one round a validator verifies a prevote and a precommit from every
// other validator. Serial verification alone is 2(n-1) × verify. The model is
// deliberately crude and stated in full so it can be argued with: it ignores
// batching, parallelism across cores, proposal and block-part handling, and
// wall-clock spent waiting on the network.
type RoundFeasibility struct {
	Validators   int
	RoundSeconds float64
	VerifyEach   time.Duration
	SerialVerify time.Duration
	Cores        int
	WithCores    time.Duration
	Share        float64 // fraction of the round budget spent verifying
	Fits         bool
}

func AssessRound(validators int, roundSeconds float64, verify time.Duration, cores int) RoundFeasibility {
	if cores < 1 {
		cores = 1
	}
	votes := 2 * (validators - 1)
	if votes < 0 {
		votes = 0
	}
	serial := time.Duration(votes) * verify
	withCores := serial / time.Duration(cores)
	budget := time.Duration(roundSeconds * float64(time.Second))
	share := float64(withCores) / float64(budget)
	return RoundFeasibility{
		Validators:   validators,
		RoundSeconds: roundSeconds,
		VerifyEach:   verify,
		SerialVerify: serial,
		Cores:        cores,
		WithCores:    withCores,
		Share:        share,
		Fits:         withCores < budget,
	}
}
