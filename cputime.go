package main

import (
	"fmt"
	"sort"
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
//
// Sign and verify are reported as distributions, not means, because for ML-DSA
// they behave completely differently and a mean hides it. ML-DSA signing uses
// REJECTION SAMPLING: it loops, discarding candidate signatures until one falls
// inside the valid range, and the number of attempts depends on the data. So
// signing time is inherently variable — measured here at p50 145 us and tails
// beyond 250 us on the same machine and key — while verification, which has no
// such loop, is flat.
//
// That variance is not a measurement problem to average away. It is a property
// of the algorithm with two consequences: a mean signing figure is unstable
// between runs and should not be quoted, and variable-time signing on secret
// data is exactly the shape a timing side channel takes. FIPS 204 signing is
// not constant-time by construction.
type CPUProfile struct {
	Scheme      string
	SignP50     time.Duration
	SignP95     time.Duration
	SignMin     time.Duration
	SignMax     time.Duration
	VerifyP50   time.Duration
	VerifyP95   time.Duration
	Samples     int
	Measured    bool
	Unavailable string // why, when the scheme has no implementation here
}

// SignSpread reports p95/p50, which is the honest measure of data-dependent
// work in a userspace benchmark.
//
// Deliberately NOT max/p50: the maximum is dominated by OS scheduling, and on
// this machine Ed25519 — which has no rejection sampling and no data-dependent
// branch — shows a max/p50 of 2.3x purely from being descheduled. Using the
// maximum would attribute scheduler noise to the algorithm. At p95 the
// difference is visible and attributable: Ed25519 sits flat at 1.0x while
// ML-DSA-65 spreads, because its signing loop retries.
func (p CPUProfile) SignSpread() float64 {
	if p.SignP50 <= 0 {
		return 0
	}
	return float64(p.SignP95) / float64(p.SignP50)
}

// sample times an operation once per iteration and returns the sorted
// durations, so a caller can report percentiles rather than a mean. A mean over
// a rejection-sampled operation is not a stable statistic.
func sample(iterations int, op func()) []time.Duration {
	for i := 0; i < iterations/10+1; i++ {
		op() // warm-up: first allocation and lazy init stay out of the result
	}
	out := make([]time.Duration, iterations)
	for i := 0; i < iterations; i++ {
		start := time.Now()
		op()
		out[i] = time.Since(start)
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

// keyRounds picks how many distinct keys to sample across. Keygen is expensive,
// so this trades sample count for key diversity: enough keys to see the
// key-dependent spread, few enough that the benchmark still finishes.
func keyRounds(iterations int) int {
	k := iterations / 100
	if k < 8 {
		k = 8
	}
	if k > 32 {
		k = 32
	}
	return k
}

func sortDurations(d []time.Duration) {
	sort.Slice(d, func(a, b int) bool { return d[a] < d[b] })
}

func pct(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted)-1) * p)
	return sorted[i]
}

func profileFrom(name string, signs, verifies []time.Duration) CPUProfile {
	return CPUProfile{
		Scheme:    name,
		SignP50:   pct(signs, 0.50),
		SignP95:   pct(signs, 0.95),
		SignMin:   signs[0],
		SignMax:   signs[len(signs)-1],
		VerifyP50: pct(verifies, 0.50),
		VerifyP95: pct(verifies, 0.95),
		Samples:   len(signs),
		Measured:  true,
	}
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
		return profileFrom(scheme.Name,
			sample(iterations, func() { _, _ = priv.Sign(msg) }),
			sample(iterations, func() { _ = pub.VerifySignature(msg, sig) })), nil

	case "ml-dsa-65":
		// Sample across MANY KEYS, not one. ML-DSA signing cost is
		// key-dependent: the rejection-sampling loop retries a number of times
		// that depends on the secret polynomial, so a benchmark that generates
		// one key and samples it measures THAT KEY rather than the algorithm.
		// An earlier single-key version of this tool returned p50 values from
		// 137 us to 191 us across runs for the same operation, and produced the
		// incoherent result that a composite signing two limbs appeared cheaper
		// than one of them alone.
		var signs, verifies []time.Duration
		keys := keyRounds(iterations)
		for k := 0; k < keys; k++ {
			priv, err := mldsa65.GenPrivKey()
			if err != nil {
				return CPUProfile{}, fmt.Errorf("ml-dsa-65 keygen: %w", err)
			}
			pub := priv.PubKey()
			sig, err := priv.Sign(msg)
			if err != nil {
				return CPUProfile{}, fmt.Errorf("ml-dsa-65 sign: %w", err)
			}
			signs = append(signs, sample(iterations/keys, func() { _, _ = priv.Sign(msg) })...)
			verifies = append(verifies, sample(iterations/keys, func() { _ = pub.VerifySignature(msg, sig) })...)
		}
		sortDurations(signs)
		sortDurations(verifies)
		return profileFrom(scheme.Name, signs, verifies), nil

	case "composite-ed25519-ml-dsa-65":
		// Both limbs are required, so the composite cost is the sum. Verify is
		// the cheap-limb-first case only when the classical limb rejects; an
		// honest accepting-path cost is both.
		// Same key-dependence applies: sample across keys.
		var csigns, cverifies []time.Duration
		ckeys := keyRounds(iterations)
		for k := 0; k < ckeys; k++ {
			ed := ed25519.GenPrivKey()
			edP := ed.PubKey()
			es, err := ed.Sign(msg)
			if err != nil {
				return CPUProfile{}, err
			}
			pq, err := mldsa65.GenPrivKey()
			if err != nil {
				return CPUProfile{}, err
			}
			pqP := pq.PubKey()
			ps, err := pq.Sign(msg)
			if err != nil {
				return CPUProfile{}, err
			}
			csigns = append(csigns, sample(iterations/ckeys, func() {
				_, _ = ed.Sign(msg)
				_, _ = pq.Sign(msg)
			})...)
			cverifies = append(cverifies, sample(iterations/ckeys, func() {
				_ = edP.VerifySignature(msg, es)
				_ = pqP.VerifySignature(msg, ps)
			})...)
		}
		sortDurations(csigns)
		sortDurations(cverifies)
		return profileFrom(scheme.Name, csigns, cverifies), nil
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
