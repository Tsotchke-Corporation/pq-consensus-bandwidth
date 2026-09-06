# pq-consensus-bandwidth

[![test](https://github.com/Tsotchke-Corporation/pq-consensus-bandwidth/actions/workflows/test.yml/badge.svg)](https://github.com/Tsotchke-Corporation/pq-consensus-bandwidth/actions/workflows/test.yml)

What post-quantum signatures cost a CometBFT chain, measured with CometBFT's own encoders
rather than estimated.

Cosmos SDK v0.55 and CometBFT v0.40.0 ship ML-DSA-65 as a validator consensus key type. A chain
can opt in today by setting `pub_key_types` to `["ml_dsa_65"]`. This repository measures what
that costs, and documents one thing it does not buy.

---

## The part that surprised us

**Enabling post-quantum consensus keys does not make your peer connections post-quantum.**
It is a different surface, and in CometBFT v0.40.0 that surface is untouched:

- the session key still comes from X25519 alone — `p2p/conn/secret_connection.go`,
  `computeDHSecret` → `curve25519.X25519`
- the node identity key is still generated as Ed25519, with no configuration hook —
  `p2p/key.go`, `LoadOrGenNodeKey` → `ed25519.GenPrivKey()`

That matters because the two surfaces fail on different clocks:

| Property | Comes from | How it fails |
|---|---|---|
| Consensus signature integrity | validator signing key | **Live.** Forging a vote needs a quantum computer at the moment of the attack. |
| Peer transport confidentiality | X25519 shared secret | **Retroactive.** An adversary records the session today and decrypts it once a quantum computer exists. |

Harvest-now-decrypt-later applies to the second and not the first. So the migration that is
available today hardens the surface with the *later* deadline, and leaves the surface with the
*earlier* one exactly as it was.

Run `pq-consensus-bandwidth --handshake` to see it:

| Handshake | Bytes | Key agreement | Safe against **recorded traffic** | Safe against **forged peer identity** once Ed25519 falls |
|---|---:|---|---|---|
| upstream v0.40.0 (X25519 + Ed25519 node key) | 134 | X25519 | no | no |
| PQ node identity only (X25519 + ML-DSA-65 node key) | 5,301 | X25519 | **no** | **yes** |
| hybrid KEM (X25519 + ML-KEM-768, ML-DSA-65 node key) | 7,573 | X25519 + ML-KEM-768, both required | yes | yes |

Outbound bytes, one side of one connection.

**Read the two right-hand columns separately, because they fail on different clocks** — the same
distinction this section opened with, applied inside the handshake.

The middle row costs 5,167 extra bytes and buys **authentication**: once a quantum computer can
forge Ed25519, an ML-DSA node key still stops an attacker impersonating a peer. That is real and
it is not nothing. What it does not buy is **confidentiality**, because the session key is still
derived from X25519 alone — so a packet capture taken today is decrypted later regardless. The
identity signature and the key agreement protect different things.

The third row adds 2,272 bytes for the ML-KEM-768 encapsulation key and ciphertext, and that is
the step that closes the recorded-traffic exposure.

So, precisely rather than pithily: **against a recording adversary the expensive step buys
nothing and the cheap step buys everything. Against a future impersonating adversary the
expensive step is the one that matters.** A chain that cares about both needs both, and the
whole thing costs 7,573 bytes.

One scope note: the `--handshake` figures are *constructed* message sizes — a real
`AuthSigMessage` marshaled with CometBFT's own protobuf, plus FIPS 203 constants for the KEM.
The "safe" columns describe the **key-agreement choice**. They are not a claim about transcript
binding, downgrade resistance, or the AEAD, and nothing here is a patched `SecretConnection`.

This is not a vulnerability in CometBFT and nothing here is exploitable today. It is a scope
observation: [cometbft#5755](https://github.com/cometbft/cometbft/issues/5755), the issue that
led to ML-DSA-65 support, opened by asking about "validator signing keys **and peer identity**",
and was closed in May 2026 after the signature work shipped. The discussion on it is entirely
about signature size and gossip bandwidth. We could not find a follow-up covering the handshake.

---

## Measured sizes

CometBFT v0.40.0, 20-byte consensus addresses, one validator's happy-path round.

| Scheme | Signature | Precommit for a block | Commit @ 100 validators | Share of an 8 MiB block |
|---|---:|---:|---:|---:|
| ed25519 *(classical baseline)* | 64 B | 181 B | 10,578 B | 0.13% |
| falcon-512 | 666 B | 784 B | 70,978 B | 0.85% |
| ml-dsa-44 | 2,420 B | 2,538 B | 246,378 B | 2.94% |
| ml-dsa-65 | 3,309 B | 3,427 B | 335,278 B | 4.00% |
| **composite ed25519 + ml-dsa-65** | 3,381 B | **3,499 B** | 342,478 B | 4.08% |
| ml-dsa-87 | 4,627 B | 4,745 B | 467,078 B | 5.57% |
| slh-dsa-128s | 7,856 B | 7,974 B | 789,978 B | 9.42% |
| **composite ml-dsa-65 + slh-dsa-128s** | 11,173 B | **11,291 B** | 1,121,678 B | **13.37%** |

**The two composites are not the same kind of thing and the difference is expensive.** The
Ed25519 hybrid costs +2.1% over pure ML-DSA. The lattice-plus-hash hedge costs **3.3×**. See
[below](#hybrid-costs-2-not-100) for why only one of them survives a break in the lattice
assumption.

A prevote and a precommit that both carry a BlockID are byte-identical — the vote type is a
one-byte enum. What costs 70 bytes is the BlockID, not the word "precommit". A vote for nil is
70 bytes smaller than a vote for a block.

### Where a vote's bytes go

ML-DSA-65 precommit for a block, by differential measurement:

| Part | Bytes | Share |
|---|---:|---:|
| signature | 3,312 | 96.6% |
| BlockID (hash + part set header) | 70 | 2.0% |
| validator address | 22 | 0.6% |
| type, height, round, timestamp, index, framing | 23 | 0.7% |
| **total** | **3,427** | 100% |

Published so the headline number can be checked against FIPS 204 without trusting this tool.

### Storage

Commit signatures are stored in every block forever. At 100 validators and 6-second blocks:

| Scheme | Per year |
|---|---:|
| ed25519 | 51.8 GiB |
| falcon-512 | 347.4 GiB |
| ml-dsa-44 | 1.2 TiB |
| ml-dsa-65 | 1.6 TiB |
| composite ed25519 + ml-dsa-65 | 1.6 TiB |
| ml-dsa-87 | 2.2 TiB |
| slh-dsa-128s | 3.8 TiB |
| composite ml-dsa-65 + slh-dsa-128s | 5.4 TiB |

1.6 TiB is 1.76 TB, which independently corroborates the ~1.8 TB/year figure in the Cosmos SDK
v0.55 upgrade guide for the same configuration.

### Commit size by validator count

ML-DSA-65, against an 8 MiB `block.max_bytes`:

| Validators | Commit | Share of block |
|---:|---:|---:|
| 4 | 13,486 B | 0.16% |
| 16 | 53,710 B | 0.64% |
| 64 | 214,606 B | 2.56% |
| 100 | 335,278 B | 4.00% |
| 150 | 502,878 B | 5.99% |
| 175 | 586,678 B | 6.99% |

Commit size is not the binding constraint for most chains. Gossip is.

### Validator ceiling

Largest validator set whose per-node **outbound** vote gossip fits the budget. ML-DSA-65:

| Link | 1 s round | 3 s round | 6 s round |
|---|---:|---:|---:|
| **50 Mbit/s**, 10 peers | 91 | 273 | 547 |
| 50 Mbit/s, 20 peers | 45 | 136 | 273 |
| 50 Mbit/s, 50 peers | 18 | 54 | 109 |
| **100 Mbit/s**, 10 peers | 182 | 547 | 1,094 |
| 100 Mbit/s, 20 peers | 91 | 273 | 547 |
| 100 Mbit/s, 50 peers | 36 | 109 | 218 |
| **1 Gbit/s**, 10 peers | 1,823 | 5,471 | 10,942 |
| 1 Gbit/s, 20 peers | 911 | 2,735 | 5,471 |
| 1 Gbit/s, 50 peers | 364 | 1,094 | 2,188 |

Peer count matters more than link speed here: at 100 Mbit/s and 1-second rounds, going from 10
peers to 50 costs you five times the validator headroom. A chain that cannot widen its links can
often narrow its gossip fanout instead.

By scheme, at 100 Mbit/s, 1-second rounds, 50 peers:

| Scheme | Max validators |
|---|---:|
| ed25519 | 690 |
| ml-dsa-44 | 49 |
| ml-dsa-65 | 36 |
| **composite ed25519 + ml-dsa-65** | **35** |
| ml-dsa-87 | 26 |
| slh-dsa-128s | 15 |
| **composite ml-dsa-65 + slh-dsa-128s** | **11** |

---

## Hybrid costs 2%, not 100%

The prevailing expectation is that a composite Ed25519 + ML-DSA signature "would double that
overhead". Measured, it does not: 3,499 B against 3,427 B, **+2.1%**, costing one validator of
headroom at the ceiling above (35 against 36).

The intuition fails because the two limbs are wildly asymmetric. Ed25519 contributes 64 bytes
to a 3,309-byte ML-DSA-65 signature. Doubling would require two limbs of similar size.

This matters for migration posture. Hybrid means a forged signature requires breaking *both*
schemes, which is the conservative stance while ML-DSA is young — and this one turns out to be
nearly free on the wire. Anyone who ruled it out on bandwidth grounds ruled it out on a number
that is wrong by more than an order of magnitude.

### But not every hybrid is cheap, and the cheap one hedges less

The +2.1% figure is specific to **Ed25519 + ML-DSA-65**, and there is a limit to what that
composite protects against. Ed25519 falls to the same quantum computer the migration exists to
survive. So the classical limb hedges a *lattice* weakness only for as long as no quantum
computer exists — which is exactly the window in which a lattice weakness matters least.

A composite that hedges the lattice assumption itself needs two **post-quantum** families:

| | Ed25519 + ML-DSA-65 | ML-DSA-65 + SLH-DSA-128s |
|---|---|---|
| Families | classical + lattice | lattice + hash |
| Precommit | 3,499 B | 11,291 B |
| Cost over pure ML-DSA-65 | **+2.1%** | **3.3×** |
| Validator ceiling | 35 | **11** |
| Storage per year @ 100 vals | 1.6 TiB | 5.4 TiB |
| Survives a lattice break | **no**, once a CRQC exists | **yes** |
| Survives a hash break | yes | no |

Hash-based security rests only on hash-function properties, with no algebraic structure to
attack, which is why CNSA 2.0 mandates LMS/XMSS for firmware signing. It is the most
conservative post-quantum posture available.

It is also the most expensive thing in this repository. Conservatism about cryptographic
assumptions is purchasable, and this is the price: eleven validators instead of thirty-five at
the same link budget. Quote the +2.1% and the 3.3× together, or the cheap number reads as a
general claim about hybrids that it is not.

---

## Use

```
pq-consensus-bandwidth                       # default schemes, vote path
pq-consensus-bandwidth --handshake           # the peer handshake analysis
pq-consensus-bandwidth --migration           # CPU, IBC updates, gossip model, mitigations
pq-consensus-bandwidth --list-schemes
pq-consensus-bandwidth --schemes ml-dsa-65 --validators 4,16,64,150 \
    --links 50Mbit,100Mbit,1Gbit --rounds 1,3,6 --peers 20 \
    --storage-validators 150 --block-seconds 6
```

Schemes: `ed25519`, `ml-dsa-44/65/87` (FIPS 204), `falcon-512/1024`, `slh-dsa-128s/128f`
(FIPS 205), and `composite-ed25519-ml-dsa-65`.

## How it measures

It builds real CometBFT `Vote`, `Commit` and `AuthSigMessage` structures and marshals them with
CometBFT's own generated protobuf code. A protobuf field carrying a signature is length-prefixed,
so the marshaled size depends on how many bytes the signature occupies and not on what they are.
That is why a scheme CometBFT has no implementation of can still be measured exactly: supply the
signature and public key lengths and the encoder does the rest.

Every table above distinguishes what was **measured** from what is a **published constant**.
ML-KEM-768's 1,184-byte encapsulation key and 1,088-byte ciphertext are FIPS 203 parameters, not
measurements. The `--handshake` output labels each leg by source.

Pinned to CometBFT **v0.40.0**. `go test ./...` asserts the figures above; if an upstream bump
changes an encoding, the tests fail and the published numbers are known to be stale.

---

## The rest of a migration

`--migration` covers what vote size does not.

### CPU is not the constraint, and signing is not constant-time

Measured with the implementations CometBFT ships, on an Apple M2 Ultra, sampled across
32 distinct keys because the cost turns out to depend on the key:

| Scheme | Sign p50 | Sign p95 | Verify p50 | Verify p95 | Sign spread (p95/p50) |
|---|---:|---:|---:|---:|---:|
| ed25519 | 16 µs | 17 µs | 28 µs | 28 µs | **1.0×** |
| ml-dsa-65 | 241 µs | 912 µs | 45 µs | 50 µs | **3.8×** |
| composite ed25519 + ml-dsa-65 | 258 µs | 900 µs | 73 µs | 78 µs | 3.5× |

Two results, and the second one is the one worth having.

**Verification is not the problem.** It runs 2(n−1) times per round, it is within 1.6× of
Ed25519, and it is flat. At 100 validators, 1-second rounds, 8 cores, verification is
**1 ms — 0.1% of the round budget**. A chain that rejected ML-DSA on a guess about CPU
rejected it on the wrong axis. Bandwidth is the constraint.

**Signing is variable, and the variance is key-dependent.** ML-DSA signing uses rejection
sampling: it loops, discarding candidate signatures until one falls in range, and the
number of retries depends on the secret polynomial. So the cost is a property of the key,
not just of the sample. Ed25519 sits flat at 1.0×; ML-DSA-65 spreads **3.8×** from median
to p95.

This is reported as percentiles across many keys because a mean over one key is not a
stable statistic — an earlier single-key, mean-based version of this tool returned figures
from 137 µs to 308 µs for the same operation, and produced the incoherent result that a
composite signing *two* limbs looked cheaper than one of them alone. If you see a single
mean signing number quoted for ML-DSA anywhere, including in an earlier version of this
README, distrust it.

The spread is measured at p95/p50 rather than max/p50 on purpose: the maximum is dominated
by OS scheduling, and Ed25519 — which has no data-dependent branch at all — shows a
max/p50 above 2× on this machine purely from being descheduled. Attributing that to the
algorithm would be wrong.

**Why it matters beyond benchmarking.** FIPS 204 signing is not constant-time by
construction, and this is a secret-key operation whose duration varies with the secret. Any
implementation signing with a long-lived validator key deserves a constant-time audit. This
tool measures that the variance exists; it does not attempt to show the variance is
exploitable, and nothing here is a claim that it is.

At 100 validators, 1-second rounds, 8 cores, verification is **1 ms — 0.1% of the round budget**.
A chain that rejected ML-DSA on a guess about CPU rejected it on the wrong axis. Bandwidth is the
constraint; the processor is not close to being one.

The model is serial verification of 2(n−1) votes divided by cores. It ignores batching, proposal
and block-part handling, and time waiting on the network. It is a floor on the CPU question, not a
round-time simulation.

### IBC is what actually blocks a cutover

Every counterparty chain downloads a commit per update, and the validator set whenever it changes.
At 100 validators:

| Scheme | Commit | Validator set | Total per update | vs classical |
|---|---:|---:|---:|---:|
| ed25519 | 10,578 B | 6,405 B | 16,983 B | 1× |
| ml-dsa-65 | 335,278 B | 198,705 B | 533,983 B | **31×** |
| composite ed25519 + ml-dsa-65 | 342,478 B | 202,705 B | 545,183 B | 32× |
| composite ml-dsa-65 + slh-dsa-128s | 1,121,678 B | 202,705 B | **1,324,383 B** | **78×** |

**A 31× increase in what every connected chain must fetch**, and **78×** for the lattice-plus-hash
hedge. That last row is why the hedge is not simply "3.3× on the wire": a client update passes
1 MB, and light-client bandwidth becomes the binding constraint before gossip does. A chain with
many IBC counterparties pays that on every update, to every one of them.

Measured with CometBFT's own `Commit` and `ValidatorSet` types, which is what 07-tendermint wraps.
**Excludes the IBC envelope** — the `Header` wrapper, trusted-height fields and `Any` typing — which
is small beside a set of post-quantum signatures but means the real object is somewhat larger than
these figures, not smaller. Every counterparty must also be able to *verify* the scheme before you
enable it, so this is a coordination problem as much as a bandwidth one.

### Which mitigations exist

| Change | Per round | Available | Why |
|---|---:|---|---|
| none (as shipped) | 6,854 B | yes | one prevote and one precommit, each with a full signature |
| compact votes (BlockID by reference) | 6,722 B | yes | saves 2% — the signature dominates, so trimming around it barely helps |
| BLS-style aggregation | — | **no** | ML-DSA and SLH-DSA have no aggregation or threshold construction |
| signing committee | bounded by committee | yes | the only lever here that scales |

That "no" is the structural fact. BLS lets a classical chain compress *n* signatures into one,
which is why large validator sets are affordable there. **No standardised post-quantum signature
scheme offers that.** So the levers are fewer signers, fewer bytes around the signature, or more
bandwidth — and only the first changes the order of the problem.

---

## What this does not tell you

**The ceiling is an upper bound, and a necessary condition rather than a sufficient one.**
`bytes_per_round(n) = n × (prevote + precommit) × peers` assumes every validator forwards every
vote to every peer. Real CometBFT tracks which votes a peer already holds and skips them, so actual
traffic is below this. `--migration` reports a modelled figure alongside the bound, but the
suppression fraction is a **parameter, not a measurement** — a packet capture on a running mesh
would replace it. Size against the upper bound.

**Nothing here is measured on a running network.** These are message sizes and CPU timings, not a
testnet. The round-feasibility model settles the CPU question and does not model
`timeout_propose`/`timeout_prevote` behaviour, retransmission, or the extra-round probability that
comes from late votes. A set that fits on paper can still miss rounds.

**It does not cover** `block.max_bytes` retuning, mixed validator sets during rotation, or custom
staking modules. The Cosmos SDK v0.55 upgrade guide is the authority on those.

Falcon signature lengths vary. The tables use the published average; the tool also reports the
practical maximum, where a Falcon-512 precommit is 870 B rather than 784 B. Size a link budget on
the maximum — an average under-provisions the tail, and the tail is where rounds are missed.

## Licence

Apache-2.0. Copyright 2026 Tsotchke Corporation.
