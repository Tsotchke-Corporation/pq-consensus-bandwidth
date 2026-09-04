package main

import (
	"fmt"
	"sort"
)

// "What would it take?" is a question with an exact answer, because the ceiling
// model inverts. Fix the validator count you want and the budget you have, and
// it returns the per-validator per-round byte cost you must reach:
//
//	bytes_per_round(n) = n × cost × peers ≤ link × round
//	cost ≤ (link × round) / (n × peers)
//
// Everything else here is a comparison against that target.

// Target is a validator count someone actually wants to run.
type Target struct {
	Name       string
	Validators int
}

// DefaultTargets are the scales that matter, from a permissioned pilot to a
// large public validator set.
var DefaultTargets = []Target{
	{"pilot", 4},
	{"small public chain", 64},
	{"mid public chain", 100},
	{"Cosmos Hub scale", 180},
	{"large public set", 1000},
	{"Ethereum-scale committee", 10000},
}

// Requirement is what a target demands of the per-validator round cost.
type Requirement struct {
	Target          Target
	BudgetBytes     int64
	MaxCostPerRound int64 // the ceiling on prevote+precommit per validator
}

func Require(t Target, b Budget) Requirement {
	budget := int64(float64(b.LinkBitsPerSec) / 8.0 * b.RoundSeconds)
	var maxCost int64
	if t.Validators > 0 && b.Peers > 0 {
		maxCost = budget / (int64(t.Validators) * int64(b.Peers))
	}
	return Requirement{Target: t, BudgetBytes: budget, MaxCostPerRound: maxCost}
}

// SchemeAgainstTarget is how a measured scheme fares against a requirement.
type SchemeAgainstTarget struct {
	Scheme          string
	CostPerRound    int
	MaxCostPerRound int64
	Feasible        bool
	ReductionNeeded float64 // 1.0 means it already fits
}

func Assess(scheme Scheme, req Requirement) (SchemeAgainstTarget, error) {
	sizes, err := Measure(scheme, []int{req.Target.Validators})
	if err != nil {
		return SchemeAgainstTarget{}, err
	}
	cost := sizes.RoundTripBytes()
	out := SchemeAgainstTarget{
		Scheme:          scheme.Name,
		CostPerRound:    cost,
		MaxCostPerRound: req.MaxCostPerRound,
	}
	if req.MaxCostPerRound <= 0 {
		out.ReductionNeeded = 0
		return out, nil
	}
	out.Feasible = int64(cost) <= req.MaxCostPerRound
	out.ReductionNeeded = float64(cost) / float64(req.MaxCostPerRound)
	return out, nil
}

// ---------------------------------------------------------------------------
// The approaches, and what each one can and cannot move
// ---------------------------------------------------------------------------

// Surface names the distinct costs a post-quantum consensus has to pay. They
// are separate problems and an approach that fixes one may not touch another,
// which is the distinction most discussions of "PQ consensus" collapse.
type Surface string

const (
	SurfaceVoteGossip  Surface = "vote gossip"  // per round, scales with n × peers
	SurfaceCommit      Surface = "commit"       // stored in every block, and shipped in IBC headers
	SurfaceLightClient Surface = "light client" // what an external verifier downloads
)

// Approach is a candidate route to a larger validator set, with what it is
// known to achieve and what it does not solve.
type Approach struct {
	Name       string
	Fixes      []Surface
	Status     string
	Evidence   string
	DoesNotFix string
}

// Approaches is the field as of 2026-09. Each entry names published work rather
// than a hoped-for result, and each says what it leaves untouched — because the
// gap between "aggregation exists" and "consensus scales" is exactly the set of
// surfaces an approach does not reach.
var Approaches = []Approach{
	{
		Name:   "smaller scheme (Falcon-512 in place of ML-DSA-65)",
		Fixes:  []Surface{SurfaceVoteGossip, SurfaceCommit, SurfaceLightClient},
		Status: "available now, but not FIPS-final; FN-DSA is still draft, and Falcon signing uses floating-point arithmetic that is hard to implement in constant time",
		Evidence: "measured here: a Falcon-512 round costs 1,568 B against ML-DSA-65's 6,854 B, a 4.4x reduction " +
			"across every surface at once",
		DoesNotFix: "nothing structurally — it buys roughly one order of magnitude and then stops",
	},
	{
		Name:   "synchronized multi-signatures (Squirrel, Chipmunk, Lemur)",
		Fixes:  []Surface{SurfaceCommit, SurfaceLightClient},
		Status: "active research, not standardised; one-time keys and stateful signing over a Merkle tree",
		Evidence: "Lemur (eprint 2026/1161) reports a 380 KB aggregate for 2^20 signers and batch verification of " +
			"1024 signers in 15.0 ms. For scale: this tool measures ML-DSA-65 at 335 KB of commit for 100 signers, " +
			"so aggregation buys roughly four orders of magnitude in signer count at comparable commit size",
		DoesNotFix: "vote gossip. Aggregation is non-interactive but it happens somewhere; unless the gossip " +
			"topology aggregates at intermediate hops, every validator still broadcasts its own signature and the " +
			"per-round term is unchanged",
	},
	{
		Name:   "threshold ML-DSA (Quorus, TALUS, Mithril)",
		Fixes:  []Surface{SurfaceCommit, SurfaceLightClient},
		Status: "active standardisation input to the NIST threshold call; Quorus and TALUS at USENIX Security 2026",
		Evidence: "produces a single FIPS 204-verifiable signature from a distributed set, so the verifier is " +
			"unchanged and existing light clients keep working",
		DoesNotFix: "vote gossip, and it changes the trust model: a threshold signature is not the same object as " +
			"n independent attestations, so slashing and accountability have to be redesigned around it",
	},
	{
		Name:   "committee pre-aggregation (the Ethereum route)",
		Fixes:  []Surface{SurfaceVoteGossip, SurfaceCommit, SurfaceLightClient},
		Status: "architecture rather than primitive; requires an aggregatable scheme underneath",
		Evidence: "Ethereum is pursuing hash-based multi-signatures with succinct aggregation as its BLS " +
			"replacement; committees aggregate before propagating, so the gossip term is bounded by committee " +
			"size rather than validator count",
		DoesNotFix: "the security argument. Bounding gossip by committee size means the full set no longer signs " +
			"every round, which is a different protocol with a different fault model",
	},
	{
		Name:   "recursive proof of the commit (SNARK-compressed consensus)",
		Fixes:  []Surface{SurfaceCommit, SurfaceLightClient},
		Status: "researched; proving cost and post-quantum soundness of the proof system are both open in practice",
		Evidence: "a proof of 'n valid signatures exist' is constant-size regardless of n, which is the strongest " +
			"asymptotic answer for light clients and IBC",
		DoesNotFix: "vote gossip, and it adds a prover to the critical path; at small n the proof can be larger " +
			"than the signatures it replaces",
	},
}

// SolveReport is the full answer: what each target demands, which measured
// scheme meets it, and which approaches could close the remainder.
func SolveReport(schemeNames []string, targets []Target, b Budget) (string, error) {
	var out string
	out += fmt.Sprintf("Budget: %s\n", b.Describe())
	out += fmt.Sprintf("A round fits when n x cost x peers <= link x round, so the cost ceiling is\n")
	out += fmt.Sprintf("(link x round) / (n x peers). Everything below inverts that.\n\n")

	out += fmt.Sprintf("%-28s %12s %18s\n", "TARGET", "VALIDATORS", "MAX B/VALIDATOR")
	for _, t := range targets {
		r := Require(t, b)
		out += fmt.Sprintf("%-28s %12d %18d\n", t.Name, t.Validators, r.MaxCostPerRound)
	}
	out += "\n"

	out += fmt.Sprintf("%-30s %10s", "SCHEME", "COST")
	for _, t := range targets {
		out += fmt.Sprintf(" %10d", t.Validators)
	}
	out += "\n"
	for _, n := range schemeNames {
		sc, err := lookupScheme(n)
		if err != nil {
			return "", err
		}
		sizes, err := Measure(sc, []int{100})
		if err != nil {
			return "", err
		}
		out += fmt.Sprintf("%-30s %10d", sc.Name, sizes.RoundTripBytes())
		for _, t := range targets {
			a, err := Assess(sc, Require(t, b))
			if err != nil {
				return "", err
			}
			if a.Feasible {
				out += fmt.Sprintf(" %10s", "fits")
			} else {
				out += fmt.Sprintf(" %9.1fx", a.ReductionNeeded)
			}
		}
		out += "\n"
	}
	out += "\nA number is the factor by which the per-validator round cost must fall for that\n"
	out += "target to fit. \"fits\" means the scheme already meets it at this budget.\n"
	return out, nil
}

// ApproachTable renders the candidate routes and, critically, what each leaves
// unsolved.
func ApproachTable() string {
	out := "APPROACHES\n\n"
	for _, a := range Approaches {
		fixes := make([]string, 0, len(a.Fixes))
		for _, f := range a.Fixes {
			fixes = append(fixes, string(f))
		}
		sort.Strings(fixes)
		out += fmt.Sprintf("%s\n", a.Name)
		out += fmt.Sprintf("  addresses:  %v\n", fixes)
		out += fmt.Sprintf("  status:     %s\n", a.Status)
		out += fmt.Sprintf("  evidence:   %s\n", a.Evidence)
		out += fmt.Sprintf("  unsolved:   %s\n\n", a.DoesNotFix)
	}
	out += "The division that matters: vote gossip is per-round and scales with n x peers.\n" +
		"Commit and light-client costs are per-block and scale with n. Aggregation attacks the\n" +
		"second group. Only a change to the gossip topology, or a smaller signature, attacks the\n" +
		"first. An approach that aggregates beautifully and leaves gossip alone has not raised\n" +
		"the validator ceiling this tool reports.\n"
	return out
}
