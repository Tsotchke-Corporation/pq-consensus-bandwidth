# Evidence and receipts

Receipt index: where every published number in this repository is asserted, and which runs have confirmed it. Status as of 2026-10-03 at commit `f7ae59e` (2026-09-06), which is `main` and `origin/main`.

## What counts as a receipt here

The published figures are message sizes computed by marshaling real CometBFT v0.40.0 structures, so they are deterministic and the test suite is the receipt: `go test ./...` fails if any pinned figure changes. CPU timings (`--migration`) are the one non-deterministic measurement; they are quoted from a single machine and labelled as such in [RESULTS_20260906.md](RESULTS_20260906.md).

## Test suite (`measure_test.go`, 15 tests)

| Test | What it pins |
|---|---|
| `TestCompositeMatchesPublishedMeasurement` | composite Ed25519 + ML-DSA-65: prevote for nil 3,429 B, precommit for a block 3,499 B, commit at 32/64/128 validators 109,646 / 219,214 / 438,350 B |
| `TestCommitGrowthIsLinearInValidators` | doubling the validator set doubles the ML-DSA-65 commit (ratio within 1.98 to 2.02) |
| `TestLargerSignaturesCostMore` | the ML-DSA-87 commit at 128 validators exceeds the Ed25519 commit |
| `TestCeilingIsNotSearchLimited` | the composite ceiling at 1 Gbit/s, 1 s rounds, 50 peers is a positive bound that did not hit the search limit (`searchMax` = 100,000) |
| `TestHybridIsNotDoubleTheOverhead` | Ed25519 + ML-DSA-65 precommit is at most 1.10× the pure ML-DSA-65 precommit and not smaller |
| `TestSignatureDominatesTheVote` | the signature is the overwhelming majority of a post-quantum vote (`Breakdown`) |
| `TestPQIdentityAloneDoesNotSecureRecordedTraffic` | the two handshake safety columns are independent: the PQ-identity-only profile is safe against forged identity and not against recorded traffic, and the KEM leg costs less than the identity leg |
| `TestVerifyIsNotTheConstraint` | ML-DSA-65 verification is the same order as Ed25519 (`MeasureCPU`, `AssessRound`) |
| `TestIBCUpdateGrowsWithTheScheme` | `MeasureClientUpdate` grows with the signature scheme |
| `TestAggregationIsMarkedUnavailable` | `Mitigations` reports BLS-style aggregation as not applicable (`AggregationIsUnavailable`) |
| `TestGossipModelIsBoundedByTheUpperBound` | `EstimateGossip` never exceeds the upper bound |
| `TestRequirementInvertsTheCeiling` | `Require` is the inverse of `DeriveCeiling` |
| `TestPostQuantumMovesTheThresholdItDoesNotCreateIt` | Ed25519 does not fit 10,000 validators at 100 Mbit/s, 1 s rounds, 50 peers either: scale is a gossip problem before it is a PQ problem |
| `TestEveryApproachDeclaresWhatItLeavesUnsolved` | every entry of `Approaches` names `Fixes`, `Evidence` and `DoesNotFix`, and at least one leaves vote gossip unsolved |
| `TestBothCompositesArePublishable` | the lattice-hedged composite exists, costs at least 2.5× pure ML-DSA-65, and is not confusable with the Ed25519 hybrid |

## Runs that confirm the suite

| Receipt | Commit | Date | Result |
|---|---|---|---|
| GitHub Actions workflow `test` (`.github/workflows/test.yml`: `go vet`, `go test -v`, `go run .` on `ubuntu-latest`), run 34068019238 | `f7ae59e` (HEAD) | 2026-09-06 | success |
| GitHub Actions `test`, runs 34067269815, 34066723137, 34065755158 | `3985488`, `433bb8b`, `09338a1` | 2026-09-06 | success |
| ICC `test-execution-oracle` `pq_migration_cost_model_v1` (`go test ./...`, exit 0, 1.35 s) | `91e2146` | 2026-09-04 | PASS |
| ICC `test-execution-oracle` `pq_bandwidth_handshake_and_published_tables_v1` (`go test ./...`, exit 0, 1.52 s) | `fa04e18` | 2026-09-04 | PASS |
| ICC `test-execution-oracle` `pq_bandwidth_published_figures_v1` (`go test ./...`, exit 0, 1.69 s) | `8ce5dd5` | 2026-09-04 | PASS |

The ICC traces live in `.icc/runtime-traces-oracle-view/*.jsonl` on the indexing workstation and are gitignored (`/.icc/`, `/artifacts/` in `.gitignore`), so they are local receipts, not part of the published repository; the three commits of 2026-09-06 after `91e2146` have the hosted CI receipt only. No oracle trace was taken for this documentation change (no build or test was run on 2026-10-03).

## Labelling of numbers

- **Measured by this tool**: every byte count of a `Vote`, `Commit`, `ValidatorSet` or `AuthSigMessage`, computed by marshaling with CometBFT's generated protobuf code (`measure.go`, `breakdown.go`, `migration.go`, `handshake.go`).
- **Published constants**: signature and public-key lengths per scheme (`schemes.go`), the ML-KEM-768 encapsulation key (1,184 B) and ciphertext (1,088 B) from FIPS 203 (`handshake.go`). The `--handshake` output marks each leg `Measured` or constant (`HandshakeLeg.Measured`).
- **Measured on one machine**: sign/verify percentiles in the `--migration` table, Apple M2 Ultra, as quoted in the results document (which says 32 distinct keys; note that `reportMigration` calls `MeasureCPU(sc, 2000)` and `keyRounds(2000)` yields 20 keys, so the key count behind the published percentiles is not fixed by the code at HEAD). Re-run `--migration` to reproduce on other hardware; the percentiles, not the means, are the stable statistic.
- **Modelled, with stated parameters**: the validator ceiling (`DeriveCeiling`, an upper bound), the storage projection (`ProjectStorage`), the round-feasibility model (`AssessRound`), the gossip estimate (`EstimateGossip`, whose suppression fraction is a parameter), and the mitigation table (`Mitigations`).
- **External, cited**: the Lemur, Quorus, TALUS and Ethereum figures quoted in `Approaches` (`solve.go`) are from the named publications, not measured here.
