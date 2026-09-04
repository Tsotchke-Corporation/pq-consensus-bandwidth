package main

import "fmt"

// Budget is one link and timing budget to test a validator set against.
type Budget struct {
	LinkBitsPerSec int64
	RoundSeconds   float64
	Peers          int
}

// Ceiling is the largest validator set whose per-node outbound vote gossip
// fits inside a Budget.
type Ceiling struct {
	Budget
	MaxValidators  int
	BytesAtMax     int64
	BudgetBytes    int64
	Utilization    float64
	LimitedBySearch bool
}

// searchMax bounds the validator-set search. A ceiling that lands here is
// reported as search-limited rather than as a real bound — a table whose cells
// all read the search maximum is measuring the search, not the network.
const searchMax = 100_000

// DeriveCeiling returns the largest validator count n whose per-node outbound
// vote traffic for one round fits in the budget.
//
// The model is deliberately simple and stated in full so a reader can disagree
// with it precisely:
//
//	bytes_per_round(n) = n × (prevote_bytes + precommit_bytes) × peers
//
// Every validator originates one prevote and one precommit per round, so a
// node sees n of each, and forwards each to its peers. This is an UPPER BOUND
// on real traffic: CometBFT tracks which votes each peer already has and skips
// sending those, so a real node transmits at or below this figure. It ignores
// protocol framing, retransmission, and latency, and it says nothing about
// whether a round can complete in the time given — only about whether the
// bytes fit.
func DeriveCeiling(voteBytesPerValidator int, b Budget) Ceiling {
	budgetBytes := int64(float64(b.LinkBitsPerSec) / 8.0 * b.RoundSeconds)

	perValidator := int64(voteBytesPerValidator) * int64(b.Peers)
	if perValidator <= 0 {
		return Ceiling{Budget: b, BudgetBytes: budgetBytes}
	}

	maxN := int(budgetBytes / perValidator)
	limited := false
	if maxN > searchMax {
		maxN = searchMax
		limited = true
	}
	if maxN < 0 {
		maxN = 0
	}

	bytesAtMax := int64(maxN) * perValidator
	var util float64
	if budgetBytes > 0 {
		util = float64(bytesAtMax) / float64(budgetBytes)
	}

	return Ceiling{
		Budget:          b,
		MaxValidators:   maxN,
		BytesAtMax:      bytesAtMax,
		BudgetBytes:     budgetBytes,
		Utilization:     util,
		LimitedBySearch: limited,
	}
}

// Tightest returns the ceiling that admits the fewest validators, which is the
// constraint that actually binds a deployment.
func Tightest(cs []Ceiling) (Ceiling, bool) {
	if len(cs) == 0 {
		return Ceiling{}, false
	}
	best := cs[0]
	for _, c := range cs[1:] {
		if c.MaxValidators < best.MaxValidators {
			best = c
		}
	}
	return best, true
}

// Describe renders a budget the way an operator states it.
func (b Budget) Describe() string {
	return fmt.Sprintf("%s, %gs round, %d peers", humanBits(b.LinkBitsPerSec), b.RoundSeconds, b.Peers)
}

func humanBits(bps int64) string {
	switch {
	case bps >= 1_000_000_000 && bps%1_000_000_000 == 0:
		return fmt.Sprintf("%d Gbit/s", bps/1_000_000_000)
	case bps >= 1_000_000 && bps%1_000_000 == 0:
		return fmt.Sprintf("%d Mbit/s", bps/1_000_000)
	default:
		return fmt.Sprintf("%d bit/s", bps)
	}
}
