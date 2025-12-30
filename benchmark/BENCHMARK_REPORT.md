# 📊 Simple Verifier - Gnark Benchmark

> **Generated:** 2025-12-30
> **Hash:** Poseidon2 (BN254 workaround)

## Configuration

| Parameter | Value |
|:---|:---|
| MAX_HANDLERS | 4 |
| MAX_OPS | 4 |
| MAX_ROWS | 256 |
| MAX_COLS | 16 |
| MAX_GROUPS | 32 |

## Results

| Metric | Value |
|:---|:---|
| **Constraints** | 4799224 |
| **Compile** | 7.837074583s |
| **Witness** | 1.006208ms |
| **Setup** | 2m40.053871459s |
| **Proof** | 11.456452041s |

## Comparison with Circom

| Implementation | Hash | Constraints | Ratio |
|:---|:---|:---|:---|
| Circom | Poseidon | 2,075,944 | 1.0x |
| Gnark (Poseidon2) | Poseidon2 | 4799224 | 2.31x |

## Note

gnark v0.14.0 bug workaround: using NewPoseidon2FromParameters directly.
