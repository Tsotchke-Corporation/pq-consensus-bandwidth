package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

func main() {
	var (
		schemeNames = flag.String("schemes", "ed25519,ml-dsa-65,composite-ed25519-ml-dsa-65",
			"comma-separated signature schemes to measure")
		validators = flag.String("validators", "32,64,128",
			"comma-separated validator set sizes")
		blockBytes = flag.Int64("block-bytes", 8*1024*1024,
			"consensus MaxBytes, for reporting commit size as a share of a block")
		links = flag.String("links", "100Mbit,1Gbit",
			"comma-separated link budgets, e.g. 100Mbit,1Gbit")
		rounds = flag.String("rounds", "1,3",
			"comma-separated round times in seconds")
		peers      = flag.String("peers", "10,50", "comma-separated peer counts")
		listOnly   = flag.Bool("list-schemes", false, "print the known signature schemes and exit")
		handshake  = flag.Bool("handshake", false, "analyse the peer handshake instead of the vote path")
		blockSecs  = flag.Float64("block-seconds", 6, "block interval, for the storage projection")
		storageVal = flag.Int("storage-validators", 100, "validator count for the storage projection")
		migration  = flag.Bool("migration", false, "the costs that actually block a cutover: CPU, IBC updates, mitigations")
		cores      = flag.Int("cores", 8, "cores available for signature verification, for the round-feasibility model")
		suppress   = flag.Float64("gossip-suppression", 0.5, "fraction of vote sends CometBFT's duplicate suppression avoids, for the modelled gossip figure")
		solve      = flag.Bool("solve", false, "what it would take: required byte cost per target validator count, and the approaches that could reach it")
	)
	flag.Parse()

	if *listOnly {
		printSchemes()
		return
	}

	if *solve {
		links, err := parseLinks(*links)
		if err != nil {
			fail("--links: %v", err)
		}
		rt, err := parseFloats(*rounds)
		if err != nil {
			fail("--rounds: %v", err)
		}
		pc, err := parseInts(*peers)
		if err != nil {
			fail("--peers: %v", err)
		}
		rep, err := SolveReport(strings.Split(*schemeNames, ","), DefaultTargets,
			Budget{LinkBitsPerSec: links[0], RoundSeconds: rt[0], Peers: pc[0]})
		if err != nil {
			fail("%v", err)
		}
		fmt.Print(rep)
		fmt.Println()
		fmt.Print(ApproachTable())
		return
	}

	if *migration {
		counts, err := parseInts(*validators)
		if err != nil {
			fail("--validators: %v", err)
		}
		rt, err := parseFloats(*rounds)
		if err != nil {
			fail("--rounds: %v", err)
		}
		pc, err := parseInts(*peers)
		if err != nil {
			fail("--peers: %v", err)
		}
		if err := reportMigration(strings.Split(*schemeNames, ","), counts, rt, pc, *cores, *suppress); err != nil {
			fail("%v", err)
		}
		return
	}

	if *handshake {
		if err := reportHandshake(strings.Split(*schemeNames, ",")); err != nil {
			fail("%v", err)
		}
		return
	}

	counts, err := parseInts(*validators)
	if err != nil {
		fail("--validators: %v", err)
	}
	linkBudgets, err := parseLinks(*links)
	if err != nil {
		fail("--links: %v", err)
	}
	roundTimes, err := parseFloats(*rounds)
	if err != nil {
		fail("--rounds: %v", err)
	}
	peerCounts, err := parseInts(*peers)
	if err != nil {
		fail("--peers: %v", err)
	}

	for i, name := range strings.Split(*schemeNames, ",") {
		scheme, err := lookupScheme(name)
		if err != nil {
			fail("%v", err)
		}
		if i > 0 {
			fmt.Println()
		}
		if err := report(scheme, counts, *blockBytes, linkBudgets, roundTimes, peerCounts, *storageVal, *blockSecs); err != nil {
			fail("%s: %v", scheme.Name, err)
		}
	}
}

func report(scheme Scheme, counts []int, blockBytes int64, links []int64, rounds []float64, peers []int, storageVals int, blockSecs float64) error {
	sizes, err := Measure(scheme, counts)
	if err != nil {
		return err
	}

	fmt.Printf("%s — signature %d B, public key %d B\n", scheme.Name, scheme.SigBytes, scheme.PubKeyBytes)
	if scheme.Note != "" {
		fmt.Printf("  %s\n", scheme.Note)
	}
	if scheme.Variable {
		fmt.Printf("  signature length varies; tables below use the average\n")
		if scheme.SigBytesMax > 0 {
			worst := scheme
			worst.SigBytes = scheme.SigBytesMax
			ws, err := Measure(worst, counts)
			if err == nil {
				fmt.Printf("  at the %d B maximum a precommit is %d B rather than %d B; size link budgets on the maximum, not the average\n",
					scheme.SigBytesMax, ws.PrecommitBlock, mustPrecommit(scheme, counts))
			}
		}
	}
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight)

	fmt.Fprintln(w, "MESSAGE\tFOR NIL\tFOR BLOCK\t")
	fmt.Fprintf(w, "prevote\t%d B\t%d B\t\n", sizes.PrevoteNil, sizes.PrevoteBlock)
	fmt.Fprintf(w, "precommit\t%d B\t%d B\t\n", sizes.PrecommitNil, sizes.PrecommitBlock)
	w.Flush()
	fmt.Println()

	fmt.Fprintln(w, "VALIDATORS\tCOMMIT\tSHARE OF BLOCK\t")
	sort.Ints(counts)
	for _, n := range counts {
		size := sizes.Commits[n]
		share := float64(size) / float64(blockBytes) * 100
		fmt.Fprintf(w, "%d\t%d B\t%.2f%%\t\n", n, size, share)
	}
	w.Flush()
	fmt.Println()

	fields, total, err := Breakdown(scheme)
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "PRECOMMIT FOR A BLOCK\tBYTES\tSHARE\t")
	for _, f := range fields {
		fmt.Fprintf(w, "%s\t%d B\t%.1f%%\t\n", f.Name, f.Bytes, float64(f.Bytes)/float64(total)*100)
	}
	fmt.Fprintf(w, "total\t%d B\t100.0%%\t\n", total)
	w.Flush()
	fmt.Println()

	if sc, ok := sizes.Commits[storageVals]; ok {
		p := ProjectStorage(sc, storageVals, blockSecs)
		fmt.Printf("commit signatures stored: %s per year at %d validators and %gs blocks\n\n",
			humanBytes(p.BytesPerYear), p.Validators, p.BlockSeconds)
	}

	var ceilings []Ceiling
	for _, link := range links {
		for _, rt := range rounds {
			for _, p := range peers {
				ceilings = append(ceilings, DeriveCeiling(sizes.RoundTripBytes(), Budget{
					LinkBitsPerSec: link, RoundSeconds: rt, Peers: p,
				}))
			}
		}
	}

	fmt.Fprintln(w, "LINK\tROUND\tPEERS\tMAX VALIDATORS\t")
	for _, c := range ceilings {
		note := ""
		if c.LimitedBySearch {
			note = " (search limit)"
		}
		fmt.Fprintf(w, "%s\t%gs\t%d\t%d%s\t\n",
			humanBits(c.LinkBitsPerSec), c.RoundSeconds, c.Peers, c.MaxValidators, note)
	}
	w.Flush()

	if t, ok := Tightest(ceilings); ok {
		fmt.Printf("\nbinding constraint: %s admits %d validators\n", t.Describe(), t.MaxValidators)
	}
	fmt.Printf("derived from measured vote sizes: %d B per validator per round (prevote + precommit for a block)\n",
		sizes.RoundTripBytes())
	fmt.Println("upper bound only — real gossip skips votes a peer already has; excludes framing, retransmission and latency")
	fmt.Println("says nothing about round time on your hardware, which must be measured separately")

	return nil
}

func printSchemes() {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SCHEME\tSIGNATURE\tPUBLIC KEY\tNOTE")
	for _, s := range schemes {
		fmt.Fprintf(w, "%s\t%d B\t%d B\t%s\n", s.Name, s.SigBytes, s.PubKeyBytes, s.Note)
	}
	w.Flush()
}

func parseInts(csv string) ([]int, error) {
	var out []int
	for _, f := range strings.Split(csv, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("%q is not a positive integer", f)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no values given")
	}
	return out, nil
}

func parseFloats(csv string) ([]float64, error) {
	var out []float64
	for _, f := range strings.Split(csv, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		v, err := strconv.ParseFloat(f, 64)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("%q is not a positive number", f)
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no values given")
	}
	return out, nil
}

// parseLinks accepts plain bits per second or a Mbit/Gbit suffix.
func parseLinks(csv string) ([]int64, error) {
	var out []int64
	for _, f := range strings.Split(csv, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		lower := strings.ToLower(f)
		mult := int64(1)
		switch {
		case strings.HasSuffix(lower, "gbit"):
			mult, lower = 1_000_000_000, strings.TrimSuffix(lower, "gbit")
		case strings.HasSuffix(lower, "mbit"):
			mult, lower = 1_000_000, strings.TrimSuffix(lower, "mbit")
		case strings.HasSuffix(lower, "kbit"):
			mult, lower = 1_000, strings.TrimSuffix(lower, "kbit")
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(lower), 64)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("%q is not a link budget (try 100Mbit or 1Gbit)", f)
		}
		out = append(out, int64(v*float64(mult)))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no values given")
	}
	return out, nil
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "pq-consensus-bandwidth: "+format+"\n", args...)
	os.Exit(1)
}

// reportHandshake prints the peer-handshake analysis: what CometBFT sends
// today, what upgrading only the node identity key would cost, and what a
// hybrid key agreement would cost. The point of the table is not the byte
// counts. It is the last column.
func reportHandshake(names []string) error {
	upstream, err := UpstreamHandshake()
	if err != nil {
		return err
	}

	profiles := []HandshakeProfile{upstream}
	for _, n := range names {
		s, err := lookupScheme(n)
		if err != nil {
			return err
		}
		if s.Name == "ed25519" {
			continue
		}
		a, err := PQAuthOnlyHandshake(s)
		if err != nil {
			return err
		}
		h, err := HybridKEMHandshake(s)
		if err != nil {
			return err
		}
		profiles = append(profiles, a, h)
	}

	fmt.Println("Peer handshake, outbound bytes for one side of one connection.")
	fmt.Println("CometBFT runs Station-to-Station: ephemeral X25519 exchange, then an")
	fmt.Println("AuthSigMessage carrying the node identity key and a transcript signature.")
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "HANDSHAKE\tBYTES\tKEY AGREEMENT\tRECORDED TRAFFIC SAFE")
	for _, p := range profiles {
		safe := "no"
		if p.QuantumResistant {
			safe = "yes"
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", p.Name, p.Total(), p.KeyAgreement, safe)
	}
	w.Flush()

	fmt.Println()
	fmt.Println("Per-leg detail:")
	w2 := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w2, "PROFILE\tLEG\tBYTES\tSOURCE")
	for _, p := range profiles {
		for _, l := range p.Legs {
			src := "published constant"
			if l.Measured {
				src = "measured (protobuf marshal)"
			}
			fmt.Fprintf(w2, "%s\t%s\t%d\t%s\n", p.Name, l.Step, l.Bytes, src)
		}
	}
	w2.Flush()

	fmt.Println()
	fmt.Println("Why the last column is the one that matters:")
	fmt.Println("  Authentication fails LIVE. Forging a peer identity needs a quantum computer")
	fmt.Println("  at the moment of the attack.")
	fmt.Println("  Confidentiality fails RETROACTIVELY. An adversary records the session today")
	fmt.Println("  and decrypts it when a quantum computer exists. Harvest now, decrypt later.")
	fmt.Println()
	fmt.Println("In CometBFT v0.40.0 the session key comes from X25519 alone")
	fmt.Println("  (p2p/conn/secret_connection.go, computeDHSecret -> curve25519.X25519)")
	fmt.Println("and the node identity key is generated as Ed25519 with no configuration hook")
	fmt.Println("  (p2p/key.go, LoadOrGenNodeKey -> ed25519.GenPrivKey).")
	fmt.Println("Enabling ML-DSA-65 consensus keys changes neither. It is a different surface.")
	return nil
}

// mustPrecommit returns the average-case precommit size, for the variable-length
// note. It returns 0 rather than failing: the note is informational.
func mustPrecommit(scheme Scheme, counts []int) int {
	s, err := Measure(scheme, counts)
	if err != nil {
		return 0
	}
	return s.PrecommitBlock
}

// reportMigration covers the questions bandwidth does not answer: whether the
// round finishes, what a light client downloads, and which protocol changes
// recover the validator set.
func reportMigration(names []string, counts []int, rounds []float64, peers []int, cores int, suppression float64) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Println("SIGN AND VERIFY, measured with the implementations CometBFT ships")
	fmt.Println()
	fmt.Fprintln(w, "SCHEME\tSIGN\tVERIFY\tNOTE")
	var verifyFor = map[string]time.Duration{}
	for _, n := range names {
		sc, err := lookupScheme(n)
		if err != nil {
			return err
		}
		p, err := MeasureCPU(sc, 200)
		if err != nil {
			return err
		}
		if !p.Measured {
			fmt.Fprintf(w, "%s\t-\t-\t%s\n", p.Scheme, p.Unavailable)
			continue
		}
		verifyFor[sc.Name] = p.Verify
		fmt.Fprintf(w, "%s\t%v\t%v\t\n", p.Scheme, p.Sign.Round(time.Microsecond), p.Verify.Round(time.Microsecond))
	}
	w.Flush()
	fmt.Println()
	fmt.Println("Verification is the side that runs n times per round, and it is the side that")
	fmt.Println("post-quantum handles well. Signing is slower and runs twice.")
	fmt.Println()

	fmt.Printf("ROUND FEASIBILITY — does verification fit the round budget, on %d cores?\n\n", cores)
	fmt.Fprintln(w, "SCHEME\tVALIDATORS\tROUND\tVERIFY TIME\tSHARE OF ROUND\tFITS")
	for _, n := range names {
		sc, err := lookupScheme(n)
		if err != nil {
			return err
		}
		v, ok := verifyFor[sc.Name]
		if !ok {
			continue
		}
		for _, c := range counts {
			for _, rt := range rounds {
				f := AssessRound(c, rt, v, cores)
				verdict := "yes"
				if !f.Fits {
					verdict = "NO"
				}
				fmt.Fprintf(w, "%s\t%d\t%gs\t%v\t%.1f%%\t%s\n",
					sc.Name, c, rt, f.WithCores.Round(time.Millisecond), f.Share*100, verdict)
			}
		}
	}
	w.Flush()
	fmt.Println()
	fmt.Println("Serial verification of 2(n-1) votes, divided by cores. Ignores batching,")
	fmt.Println("proposal and block-part handling, and time spent waiting on the network.")
	fmt.Println()

	fmt.Println("IBC CLIENT UPDATE — what every counterparty downloads per update")
	fmt.Println()
	fmt.Fprintln(w, "SCHEME\tVALIDATORS\tCOMMIT\tVALIDATOR SET\tTOTAL")
	for _, n := range names {
		sc, err := lookupScheme(n)
		if err != nil {
			return err
		}
		for _, c := range counts {
			u, err := MeasureClientUpdate(sc, c)
			if err != nil {
				return err
			}
			fmt.Fprintf(w, "%s\t%d\t%d B\t%d B\t%d B\n",
				sc.Name, c, u.CommitBytes, u.ValidatorSetBytes, u.TotalBytes)
		}
	}
	w.Flush()
	fmt.Println()
	fmt.Println("SignedHeader commit plus the validator set on a set change, measured with")
	fmt.Println("CometBFT's own types. Excludes the IBC envelope, which is small beside these.")
	fmt.Println("Every counterparty chain must be able to verify the scheme before you enable it.")
	fmt.Println()

	fmt.Println("GOSSIP — upper bound versus a suppression model")
	fmt.Println()
	fmt.Fprintln(w, "SCHEME\tVALIDATORS\tPEERS\tUPPER BOUND\tMODELLED\tSUPPRESSION")
	for _, n := range names {
		sc, err := lookupScheme(n)
		if err != nil {
			return err
		}
		sz, err := Measure(sc, counts)
		if err != nil {
			return err
		}
		for _, c := range counts {
			for _, pr := range peers {
				g := EstimateGossip(sz.RoundTripBytes(), c, pr, suppression)
				fmt.Fprintf(w, "%s\t%d\t%d\t%s\t%s\t%.0f%%\n",
					sc.Name, c, pr, humanBytes(g.UpperBoundBytes), humanBytes(g.ModelledBytes), suppression*100)
			}
		}
	}
	w.Flush()
	fmt.Println()
	fmt.Println("CometBFT tracks which votes each peer already holds and skips those, so real")
	fmt.Println("traffic is below the upper bound. The suppression fraction is a PARAMETER, not")
	fmt.Println("a measurement: a capture on a running mesh would replace it. Size against the")
	fmt.Println("upper bound; treat the modelled column as the optimistic end.")
	fmt.Println()

	fmt.Println("MITIGATIONS — what recovers the validator set")
	fmt.Println()
	for _, n := range names {
		sc, err := lookupScheme(n)
		if err != nil {
			return err
		}
		ms, err := Mitigations(sc, 100)
		if err != nil {
			return err
		}
		fmt.Printf("%s:\n", sc.Name)
		w3 := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w3, "  CHANGE\tPER ROUND\tAVAILABLE\tNOTE")
		for _, m := range ms {
			avail := "yes"
			if !m.Applicable {
				avail = "NO"
			}
			fmt.Fprintf(w3, "  %s\t%d B\t%s\t%s\n", m.Name, m.RoundTripCost, avail, m.Note)
		}
		w3.Flush()
		fmt.Println()
	}
	fmt.Println(AggregationIsUnavailable)
	return nil
}
