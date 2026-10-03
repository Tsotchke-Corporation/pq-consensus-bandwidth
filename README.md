# pq-consensus-bandwidth

pq-consensus-bandwidth is a Go measurement tool that reports what post-quantum signatures cost a CometBFT chain on the wire, computed with CometBFT v0.40.0's own protobuf encoders rather than estimated: vote, commit, light-client-update and peer-handshake sizes for ML-DSA, Falcon, SLH-DSA and two composites, plus the validator-set ceiling those sizes imply for a link budget, measured sign/verify cost, and the protocol levers that do and do not exist. In the Tsotchke ecosystem it is the consensus-bandwidth research sibling of quantum-blockchain (PUC): the independent, upstream-CometBFT reproduction of the vote-size receipt PUC's composite Ed25519 + ML-DSA-65 consensus profile rests on, and the published argument for why a hybrid KEM handshake is needed beside a post-quantum consensus key.

[![test](https://github.com/Tsotchke-Corporation/pq-consensus-bandwidth/actions/workflows/test.yml/badge.svg)](https://github.com/Tsotchke-Corporation/pq-consensus-bandwidth/actions/workflows/test.yml)

## What this is

Cosmos SDK v0.55 and CometBFT v0.40.0 ship ML-DSA-65 as a validator consensus key type; a chain can opt in by setting `pub_key_types` to `["ml_dsa_65"]`. This repository measures what that costs and documents one thing it does not buy.

Inputs: a signature scheme, described only by its serialized signature and public-key lengths (`Scheme` in `schemes.go`), and a budget (validator counts, link speed, round time, peer count). Outputs: the marshaled size of real CometBFT `Vote`, `Commit`, `ValidatorSet` and `AuthSigMessage` structures carrying that scheme, and the models built on those sizes. A protobuf field carrying a signature is length-prefixed, so the encoded size depends on how many bytes the signature occupies and not on what they are; that is why a scheme CometBFT has no implementation of can still be measured exactly.

The headline results (all at CometBFT v0.40.0, 100 validators, 8 MiB blocks unless stated; full tables and reasoning in [docs/RESULTS_20260906.md](docs/RESULTS_20260906.md)):

| Result | Figure |
|---|---|
| ML-DSA-65 precommit for a block | 3,427 B, of which the signature is 3,312 B (96.6%) |
| Composite Ed25519 + ML-DSA-65 precommit | 3,499 B: **+2.1%** over pure ML-DSA-65, not the doubling the public discussion expected |
| Composite ML-DSA-65 + SLH-DSA-128s precommit (the lattice-hedged composite) | 11,291 B: **3.3×** pure ML-DSA-65 |
| Commit at 100 validators, ML-DSA-65 | 335,278 B, 4.00% of an 8 MiB block; 1.6 TiB of commit signatures per year at 6-second blocks |
| IBC client update at 100 validators, ML-DSA-65 | 533,983 B, **31×** Ed25519; 78× for the lattice-hedged composite |
| Validator ceiling at 100 Mbit/s, 1-second rounds, 50 peers | Ed25519 690, ML-DSA-65 36, Ed25519 + ML-DSA-65 35, ML-DSA-65 + SLH-DSA-128s 11 |
| Peer handshake (one side, outbound) | upstream 134 B; PQ node identity only 5,301 B, which buys authentication but not confidentiality; hybrid X25519 + ML-KEM-768 7,573 B, which closes the recorded-traffic exposure |
| Sign/verify, Apple M2 Ultra | ML-DSA-65 verify p50 45 µs (within 1.6× Ed25519, flat); sign p50 241 µs, p95 912 µs (3.8× spread, key-dependent rejection sampling). CPU is not the constraint; bandwidth is |

What it is not: not a running network (message sizes and single-machine CPU timings, not a testnet), not a patched `SecretConnection`, not a claim about transcript binding, downgrade resistance or the AEAD, and not a vulnerability report; CometBFT v0.40.0's peer transport (X25519 key agreement, Ed25519 node identity) is a scope observation, not an exploit. The validator ceiling is an upper bound on gossip, a necessary condition rather than a sufficient one.

## Where it sits in the Tsotchke ecosystem

This repository consumes nothing from the ecosystem and is consumed by one sibling as evidence. Its only code dependency is upstream `github.com/cometbft/cometbft v0.40.0`. The ecosystem map lives in Selene (`ECOSYSTEM_MAP.md`, owned by tsotchke-chan).

- **quantum-blockchain (PUC)** builds its consensus on composite Ed25519 + ML-DSA-65 votes and hybrid X-Wing peer transport over a hardened CometBFT v0.40.0 fork; PUC's README names this repository as the independent reproduction of the vote-bandwidth measurement recorded in its decision register (row F-14), and the handshake analysis here is the argument for the hybrid-KEM transport PUC adopted.
- **Moonlab** implements FIPS 203 ML-KEM (`moonlab_mlkem768_encaps`, `moonlab_mlkem768_decaps`) in C. This tool does not call it: the ML-KEM-768 sizes used in the handshake table are the FIPS 203 constants (1,184-byte encapsulation key, 1,088-byte ciphertext), so the two agree by construction, not by linkage.
- **ICC** indexes this repository under the name `pq-consensus-bandwidth` and has graded its test suite three times (see [docs/EVIDENCE.md](docs/EVIDENCE.md)).

## Status and evidence

**Research, published.** The repository is public on GitHub; `main` is `f7ae59e` (2026-09-06) and every published figure is asserted by `go test ./...`, which the hosted `test` workflow ran green at that commit (run 34068019238, 2026-09-06). Three ICC `test-execution-oracle` traces (`pq_bandwidth_published_figures_v1`, `pq_bandwidth_handshake_and_published_tables_v1`, `pq_migration_cost_model_v1`) recorded PASS on 2026-09-04 at the commits of that day. The per-number receipts, and which numbers are measured, published constants, modelled or single-machine timings, are in [docs/EVIDENCE.md](docs/EVIDENCE.md). The CPU percentiles are from one Apple M2 Ultra and are not portable; everything else is deterministic. No measurement has been taken on a running network.

## Build, run, test

Go 1.25 (`go.mod`); the CI workflow runs on `ubuntu-latest`, and the figures were produced on macOS. Clean checkout:

```
go build .                                   # ./pq-consensus-bandwidth
go test ./...                                # the gate: every published figure is pinned here
go vet ./...
pq-consensus-bandwidth                       # default schemes, vote path
pq-consensus-bandwidth --handshake           # the peer handshake analysis
pq-consensus-bandwidth --migration           # CPU, IBC updates, gossip model, mitigations
pq-consensus-bandwidth --solve               # required byte cost per target validator count
pq-consensus-bandwidth --list-schemes
```

Green means `go vet ./...` and `go test ./...` pass (`.github/workflows/test.yml`, which also runs `go run . --schemes ed25519,ml-dsa-65,composite-ed25519-ml-dsa-65`). Scheme names: `ed25519`, `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`, `falcon-512`, `falcon-1024`, `slh-dsa-128s`, `slh-dsa-128f`, `composite-ed25519-ml-dsa-65`, `composite-ml-dsa-65-slh-dsa-128s`. Every flag and default is in [docs/CLI.md](docs/CLI.md). If an upstream CometBFT bump changes an encoding, the tests fail and the published numbers are known to be stale.

## Architecture

A single `main` package, ten Go files, no sub-packages.

| File | Role | Public entry points |
|---|---|---|
| `main.go` | flag parsing and the five report modes | `main`, `report`, `reportHandshake`, `reportMigration` |
| `schemes.go` | the scheme table: signature and public-key lengths from the standards, Falcon's variable-length maximum | `Scheme`, `lookupScheme` |
| `measure.go` | marshals real `Vote` and `Commit` structures with a fixed timestamp and 20-byte addresses (`AddressWidth`) | `Measure`, `Sizes`, `Sizes.RoundTripBytes` |
| `breakdown.go` | attributes a vote's bytes to its fields by differential marshaling; the yearly storage projection | `Breakdown`, `Field`, `ProjectStorage`, `StorageProjection` |
| `ceiling.go` | the validator-ceiling model `bytes_per_round(n) = n × (prevote + precommit) × peers`, searched up to `searchMax` | `Budget`, `Ceiling`, `DeriveCeiling`, `Tightest` |
| `handshake.go` | the `SecretConnection` handshake as three profiles, each leg marked measured or constant, with the two independent safety properties | `HandshakeProfile`, `HandshakeLeg`, `UpstreamHandshake`, `PQAuthOnlyHandshake`, `HybridKEMHandshake` |
| `cputime.go` | sign/verify percentiles across keys with CometBFT's `ed25519` and `mldsa65` packages; the round-feasibility model | `CPUProfile`, `MeasureCPU`, `RoundFeasibility`, `AssessRound` |
| `migration.go` | IBC 07-tendermint client-update payload, the gossip upper bound and suppression model, the mitigation table | `ClientUpdate`, `MeasureClientUpdate`, `GossipEstimate`, `EstimateGossip`, `Mitigation`, `Mitigations`, `AggregationIsUnavailable` |
| `solve.go` | the ceiling inverted: byte cost required per target validator count, and the catalogue of approaches with what each leaves unsolved | `Target`, `DefaultTargets`, `Requirement`, `Require`, `Assess`, `Approach`, `Approaches`, `SolveReport`, `ApproachTable` |
| `measure_test.go` | the fifteen tests that pin the published figures and the claims built on them | listed in [docs/EVIDENCE.md](docs/EVIDENCE.md) |

## Documentation map

- Curated path: [docs/README.md](docs/README.md). Complete generated list: [INDEX.md](INDEX.md) and [docs/INDEX.md](docs/INDEX.md) (regenerate with `scripts/build_doc_indexes.py`).
- Research results: [docs/RESULTS_20260906.md](docs/RESULTS_20260906.md), the full measurement write-up of 2026-09-06: the handshake surfaces and their two failure clocks, measured sizes, where a vote's bytes go, storage, commit size by validator count, the ceiling grid, the two composites, CPU, IBC updates, mitigations, and what the tool does not tell you.
- Reference: [docs/CLI.md](docs/CLI.md), every mode, flag and scheme.
- Receipts: [docs/EVIDENCE.md](docs/EVIDENCE.md), which test pins which number and which runs confirmed the suite.

## For agents (ICC, tsotchke-chan)

- **ICC repo name:** `pq-consensus-bandwidth` (`bin/icc status --repo pq-consensus-bandwidth`). Reindex serially under `nice` (`bin/icc reindex --repo pq-consensus-bandwidth --full`). ICC's `doc-coverage` does not count Go public symbols, so symbol coverage is unmeasured here; the architecture table above names every entry point by its exact identifier for the symbol graph.
- **Gates:** `go test ./...` is the only gate. ICC `test-execution-oracle` names used so far: `pq_bandwidth_published_figures_v1`, `pq_bandwidth_handshake_and_published_tables_v1`, `pq_migration_cost_model_v1`; their traces sit in `.icc/runtime-traces-oracle-view/` on the indexing workstation and are gitignored, so the hosted `test` workflow is the receipt that travels with the repository.
- **Rules:** nothing goes in `/tmp`; scratch is `.scratch/` (gitignored). Do not edit the tracked figures without re-running the suite; a number in a document that the tests do not pin is labelled as modelled, constant or single-machine in [docs/EVIDENCE.md](docs/EVIDENCE.md). Pushing is owner-run. No AI attribution anywhere. Public text carries no hosts, paths or private names.
- **tsotchke-chan:** she does not run on this repository and nothing she serves depends on it; it is one of the documents she reads to explain the post-quantum consensus work and PUC's choices. Consult her before changing the ecosystem-facing claims about PUC or Moonlab above.

## Related repositories

| Canonical name | Repo | Relationship to pq-consensus-bandwidth |
|---|---|---|
| quantum-blockchain (PUC) | [Tsotchke-Corporation/quantum-blockchain](https://github.com/Tsotchke-Corporation/quantum-blockchain) | the production consumer: composite Ed25519 + ML-DSA-65 votes and hybrid X-Wing transport on a CometBFT v0.40.0 fork; cites this repository as the independent bandwidth reproduction |
| Moonlab | [tsotchke/moonlab](https://github.com/tsotchke/moonlab) | the ecosystem's FIPS 203 ML-KEM implementation; this tool uses the FIPS 203 constants, not the library |
| ICC (Infinite Context Coder) | [Tsotchke-Corporation/infinite_context_coder](https://github.com/Tsotchke-Corporation/infinite_context_coder) | indexes this repository and graded its test suite |
| tsotchke-chan / Selene | [Tsotchke-Corporation/Selene](https://github.com/Tsotchke-Corporation/Selene) | ecosystem map and the documentation campaign ledger |
| upstream | [cometbft/cometbft](https://github.com/cometbft/cometbft) v0.40.0 | the encoders and the `ed25519` / `mldsa65` implementations measured; [cometbft#5755](https://github.com/cometbft/cometbft/issues/5755) and [PR #5875](https://github.com/cometbft/cometbft/pull/5875) are the ML-DSA-65 work this responds to |

## License and contact

Apache-2.0 ([LICENSE](LICENSE)). Copyright 2026 Tsotchke Corporation. Issues and pull requests at [Tsotchke-Corporation/pq-consensus-bandwidth](https://github.com/Tsotchke-Corporation/pq-consensus-bandwidth).
