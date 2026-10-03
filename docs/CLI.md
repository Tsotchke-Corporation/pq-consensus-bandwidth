# Command reference: `pq-consensus-bandwidth`

Reference: every flag, mode and scheme name of the `pq-consensus-bandwidth` binary, taken from `main.go` and `schemes.go` at commit `f7ae59e` (2026-09-06). The measured results the modes print are in [RESULTS_20260906.md](RESULTS_20260906.md).

## Build

```
go build .            # produces ./pq-consensus-bandwidth (gitignored)
go run . [flags]      # or run in place
```

Module `github.com/tsotchke-corporation/pq-consensus-bandwidth`, `go 1.25.0` in `go.mod`, one direct dependency: `github.com/cometbft/cometbft v0.40.0`.

## Modes

The binary has one default mode and four alternatives selected by a boolean flag; the first of `--list-schemes`, `--solve`, `--migration`, `--handshake` that is set wins, in that order (`main.go`, `main`).

| Mode | What it prints | Entry point in code |
|---|---|---|
| (default) | per scheme: vote sizes (prevote and precommit, for nil and for a block), the field breakdown, commit size per validator count and its share of `--block-bytes`, the storage projection, the validator ceiling for every link × round × peers combination, and the tightest cell | `report` → `Measure`, `Breakdown`, `ProjectStorage`, `DeriveCeiling`, `Tightest` |
| `--handshake` | the peer handshake, one side's outbound bytes, for upstream CometBFT and, for every non-`ed25519` scheme requested, the PQ-identity-only and hybrid-KEM profiles with their two safety columns | `reportHandshake` → `UpstreamHandshake`, `PQAuthOnlyHandshake`, `HybridKEMHandshake` |
| `--migration` | sign/verify percentiles measured with the implementations CometBFT ships, the round-feasibility model, the IBC client-update payload, the gossip upper bound and modelled figure, and the mitigation table | `reportMigration` → `MeasureCPU`, `AssessRound`, `MeasureClientUpdate`, `EstimateGossip`, `Mitigations` |
| `--solve` | for each target validator count, the per-validator per-round byte budget it demands, whether each requested scheme meets it, and the table of approaches (`Approaches`) with what each does and does not fix | `SolveReport`, `ApproachTable` → `Require`, `Assess` |
| `--list-schemes` | the known scheme names with signature and public-key sizes | `printSchemes` |

`--solve` was not described in the README of 2026-09-06; its targets are `DefaultTargets` in `solve.go`: pilot (4), small public chain (64), mid public chain (100), Cosmos Hub scale (180), large public set (1000), Ethereum-scale committee (10000). It uses only the first value of each of `--links`, `--rounds` and `--peers`.

## Flags

Defaults are the values in `main.go`.

| Flag | Default | Meaning |
|---|---|---|
| `--schemes` | `ed25519,ml-dsa-65,composite-ed25519-ml-dsa-65` | comma-separated signature schemes to measure |
| `--validators` | `32,64,128` | comma-separated validator set sizes |
| `--block-bytes` | `8388608` (8 MiB) | consensus `MaxBytes`, for reporting commit size as a share of a block |
| `--links` | `100Mbit,1Gbit` | comma-separated link budgets (`Mbit`, `Gbit` suffixes parsed by `parseLinks`) |
| `--rounds` | `1,3` | comma-separated round times in seconds |
| `--peers` | `10,50` | comma-separated peer counts |
| `--block-seconds` | `6` | block interval, for the storage projection |
| `--storage-validators` | `100` | validator count for the storage projection |
| `--cores` | `8` | cores available for signature verification, for the round-feasibility model |
| `--gossip-suppression` | `0.5` | fraction of vote sends CometBFT's duplicate suppression avoids, for the modelled gossip figure (a parameter, not a measurement) |
| `--list-schemes` | off | print the known signature schemes and exit |
| `--handshake` | off | analyse the peer handshake instead of the vote path |
| `--migration` | off | CPU, IBC updates, gossip model, mitigations |
| `--solve` | off | required byte cost per target validator count, and the approaches that could reach it |

## Schemes

`schemes` in `schemes.go`. A scheme is described only by the two numbers that change consensus message size, the serialized signature length and the serialized public-key length; the tool needs no implementation of the algorithm to measure its wire cost (only `--migration` runs real sign/verify, and only for `ed25519`, `ml-dsa-65` and `composite-ed25519-ml-dsa-65`, via `github.com/cometbft/cometbft/crypto/ed25519` and `crypto/mldsa65`).

| Name | Signature bytes | Public key bytes | Note (from code) |
|---|---:|---:|---|
| `ed25519` | 64 | 32 | classical baseline, not post-quantum |
| `ml-dsa-44` | 2,420 | 1,312 | FIPS 204, NIST security category 2 |
| `ml-dsa-65` | 3,309 | 1,952 | FIPS 204, NIST security category 3 |
| `ml-dsa-87` | 4,627 | 2,592 | FIPS 204, NIST security category 5 |
| `falcon-512` | 666 (max 752) | 897 | compressed signatures vary in length; 666 B average, 752 B practical maximum |
| `falcon-1024` | 1,280 (max 1,462) | 1,793 | compressed signatures vary in length; 1280 B average, 1462 B practical maximum |
| `slh-dsa-128s` | 7,856 | 32 | FIPS 205, small variant: tiny keys, very large signatures |
| `slh-dsa-128f` | 17,088 | 32 | FIPS 205, fast variant: signatures larger still |
| `composite-ml-dsa-65-slh-dsa-128s` | 11,173 (3,309 + 7,856 + 8) | 1,992 (1,952 + 32 + 8) | lattice + hash, both required; the only composite here that survives a break in either family |
| `composite-ed25519-ml-dsa-65` | 3,381 | 1,992 | hybrid: both limbs carried and both required, plus an 8-byte algorithm tag on each of the signature and the key |

Sizes are the published serialized lengths from the relevant standard, not measurements; what the tool measures is the CometBFT protobuf encoding around them.

## Examples

```
pq-consensus-bandwidth                       # default schemes, vote path
pq-consensus-bandwidth --handshake           # the peer handshake analysis
pq-consensus-bandwidth --migration           # CPU, IBC updates, gossip model, mitigations
pq-consensus-bandwidth --solve               # what it would take, per target validator count
pq-consensus-bandwidth --list-schemes
pq-consensus-bandwidth --schemes ml-dsa-65 --validators 4,16,64,150 \
    --links 50Mbit,100Mbit,1Gbit --rounds 1,3,6 --peers 20 \
    --storage-validators 150 --block-seconds 6
```

The continuous-integration workflow runs `go run . --schemes ed25519,ml-dsa-65,composite-ed25519-ml-dsa-65` after `go vet ./...` and `go test -v ./...` (`.github/workflows/test.yml`).
