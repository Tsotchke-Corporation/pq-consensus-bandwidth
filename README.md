# pq-consensus-bandwidth

What post-quantum signatures cost a CometBFT chain on the wire, measured rather than estimated.

Signature size is the whole cost model for post-quantum consensus, and it is the number most
migration plans estimate. This tool measures it: it builds real CometBFT `Vote` and `Commit`
structures, marshals them with CometBFT's own generated protobuf code, and reports the wire sizes —
then derives the validator ceiling your link budget implies.

It runs against **stock upstream CometBFT**. No fork, and no implementation of the signature scheme
is required.

## Why it can measure a scheme it doesn't implement

A protobuf field carrying a signature is length-prefixed. The marshaled size of a vote depends on
how many bytes the signature occupies and not at all on what those bytes are. So a scheme is fully
described here by two numbers — signature length and public key length — and any scheme, deployed or
merely proposed, can be measured by supplying them.

## Use

```
go run . --schemes ed25519,ml-dsa-65,composite-ed25519-ml-dsa-65
go run . --list-schemes
go run . --schemes ml-dsa-87 --validators 4,16,64,150 --links 50Mbit,100Mbit,1Gbit --peers 20
```

Known schemes include Ed25519 as a classical baseline, ML-DSA-44/65/87 (FIPS 204),
Falcon-512/1024, SLH-DSA-128s/128f (FIPS 205), and a composite Ed25519 + ML-DSA-65 hybrid.

## What it reports

**Message sizes**, split by whether the vote carries a BlockID. This distinction matters more than
the vote type: a prevote and a precommit of the same kind are byte-identical, because the type is a
one-byte enum. What costs 70 bytes is the BlockID, not the word "precommit".

**Commit size** at each validator count, and its share of your `MaxBytes`. Commits carry one
signature per validator, so this grows linearly with the set and is where post-quantum signatures
are actually felt.

**A validator ceiling** for each link budget, round time and peer count:

```
bytes_per_round(n) = n × (prevote_bytes + precommit_bytes) × peers
```

Every validator originates one prevote and one precommit per round, so a node sees `n` of each and
forwards each to its peers. The largest `n` whose traffic fits in `link × round_time` is the
ceiling.

## What it does not tell you

This is an **upper bound**. CometBFT tracks which votes each peer already holds and skips those, so
a real node transmits at or below this figure. The model excludes protocol framing, retransmission
and latency.

More importantly: it says nothing about **round time on your hardware**. Whether a round can
*complete* in the time budgeted is a separate question requiring separate measurement, and no
bandwidth model answers it. A ceiling from this tool is a necessary condition, never a sufficient
one.

Falcon signatures vary in length; its figures use the published planning average.

## Tests

`go test ./...` pins the measured figures for a composite Ed25519 + ML-DSA-65 profile against
CometBFT v0.40.0. If an upgrade changes vote or commit encoding, the test fails and the published
numbers are known to be stale — which is the point of pinning them.

One test exists because of a bug worth naming: an earlier version of this model searched validator
counts only up to 512, so every cell in the ceiling table read 512 and the table described the
search rather than the network. `TestCeilingIsNotSearchLimited` fails if a reported ceiling is
really the search bound.

## Licence

Apache-2.0.
