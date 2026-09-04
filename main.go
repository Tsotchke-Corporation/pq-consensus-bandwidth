package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
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
	)
	flag.Parse()

	if *listOnly {
		printSchemes()
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
		fmt.Printf("  signature length varies; sizes below use the planning figure above\n")
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
