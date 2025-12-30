# gnark-simple-verifier

A Gnark (Go) implementation of the Simple Verifier ZK circuit - a multi-handler verifier supporting various data operations with zero-knowledge proofs.

## Overview

This circuit implements a multi-handler verifier that supports:
- **MERKLE16_ORDERED**: 16-ary Merkle tree root computation with mask
- **COUNT**: Count valid rows
- **SUM_COL**: Sum a specific column with row mask
- **SUM_COL_BY**: Sum column X grouped by column Y (returns array of groupSums)

## Project Structure

```
gnark-simple-verifier/
├── main.go              # CLI entry point & benchmark
├── go.mod               # Go module
├── .gitignore           # Git ignore rules
├── README.md            # This file
├── benchmark/           # Benchmark results
│   └── BENCHMARK_REPORT.md
└── pkg/
    ├── lib/             # Library utilities
    │   ├── constants.go # Circuit parameters
    │   ├── utils.go     # Selector, Mask, LessThan
    │   ├── poseidon.go  # Poseidon2 hash (BN254 workaround)
    │   └── ssz.go       # SSZ Key-Value encoding
    ├── operators/       # Circuit operators
    │   ├── count.go     # COUNT operator
    │   ├── merkle16.go  # 16-ary Merkle tree
    │   ├── sum.go       # SUM_COL operator
    │   └── sum_by.go    # SUM_COL_BY + validation
    └── circuit/         # Main circuit
        └── circuit.go   # SimpleVerifierCircuit definition
```

## Configuration

| Parameter | Value | Description |
|:---|:---|:---|
| MAX_ROWS | 256 | Maximum rows in data matrix |
| MAX_COLS | 16 | Maximum columns in data matrix |
| MAX_GROUPS | 32 | Maximum group keys for SUM_BY |
| MAX_OPS | 4 | Operations per handler |
| MAX_HANDLERS | 4 | Number of handlers |
| N_LEVELS | 3 | Merkle tree levels (16^3 = 4096 leaves) |

## Usage

```bash
# Build
go build -o gnark-simple-verifier

# Run benchmark
go run main.go benchmark

# Compile circuit only
go run main.go compile
```

## OpCodes

| Code | Operation | Description |
|:---|:---|:---|
| 0 | NOOP | No operation |
| 1000 | MERKLE16 | 16-ary Merkle root with mask |
| 2000 | COUNT | Count valid rows |
| 2001 | SUM_COL | Sum column with row mask |
| 3000 | SUM_COL_BY | Sum column grouped by another |

## Hash Function

This implementation uses **Poseidon2** with a workaround for BN254 support in gnark v0.14.0:
- In-circuit: `NewPoseidon2FromParameters(api, 2, 6, 50)`
- Off-chain: `bn254/fr/poseidon2.NewMerkleDamgardHasher()`

## Benchmark Results

| Metric | Value |
|:---|:---|
| **Constraints** | 4,426,200 |
| **Proof Time** | ~10.2s |

## Security Features

1. **Strict opcode validation**: Each operation must match exactly one valid opcode
2. **Handler masking**: Inactive handlers are skipped using mask multiplication
3. **GROUP BY validation**: SUM_BY fails if any row doesn't match a public group key
4. **Result verification**: Computed results must match public input results
5. **StartIndex Support**: `HandlerStartIndex` allows processing subsets of columns per handler


## License

MIT
