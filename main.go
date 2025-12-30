package main

import (
	"fmt"
	"math/big"
	"os"
	"time"

	"simple-verifier-gnark/pkg/circuit"
	"simple-verifier-gnark/pkg/lib"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const (
	TEST_NR           = 64
	TEST_NUM_HANDLERS = 2
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Simple Verifier - Gnark Circuit")
		fmt.Println("")
		fmt.Println("Usage: go run main.go <command>")
		fmt.Println("")
		fmt.Println("Commands:")
		fmt.Println("  benchmark  Run full benchmark")
		fmt.Println("  compile    Compile circuit only")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "benchmark":
		runBenchmark()
	case "compile":
		compileCircuit()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func compileCircuit() {
	fmt.Println("📊 Compiling SimpleVerifier circuit...")

	startTime := time.Now()

	var c circuit.SimpleVerifierCircuit

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)

	if err != nil {
		fmt.Printf("❌ Compile error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Compiled in %v\n", time.Since(startTime))
	fmt.Printf("   Constraints: %d\n", cs.GetNbConstraints())
}

func runBenchmark() {
	fmt.Println("")
	fmt.Println("📊 Simple Verifier - Gnark Benchmark (Poseidon2)")
	fmt.Println("")
	fmt.Printf("   Config: MAX_HANDLERS=%d, MAX_OPS=%d, MAX_COLS=%d, MAX_ROWS=%d\n",
		lib.MAX_HANDLERS, lib.MAX_OPS, lib.MAX_COLS, lib.MAX_ROWS)
	fmt.Printf("   Test:   NR=%d, Handlers=%d\n", TEST_NR, TEST_NUM_HANDLERS)
	fmt.Println("")

	fmt.Println("1️⃣  Compiling circuit...")

	startCompile := time.Now()

	var c circuit.SimpleVerifierCircuit

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)

	if err != nil {
		fmt.Printf("❌ Compile error: %v\n", err)
		os.Exit(1)
	}

	compileTime := time.Since(startCompile)

	fmt.Printf("    ✅ Compile: %v | Constraints: %d\n", compileTime, cs.GetNbConstraints())

	fmt.Println("2️⃣  Generating test data...")

	assignment, err := generateTestAssignment()

	if err != nil {
		fmt.Printf("❌ Test data error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("    ✅ Input generated")

	fmt.Println("3️⃣  Generating witness...")

	startWitness := time.Now()

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())

	if err != nil {
		fmt.Printf("❌ Witness error: %v\n", err)
		os.Exit(1)
	}

	witnessTime := time.Since(startWitness)

	fmt.Printf("    ✅ Witness: %v\n", witnessTime)

	fmt.Println("4️⃣  Setup (Groth16)...")

	startSetup := time.Now()

	pk, vk, err := groth16.Setup(cs)

	if err != nil {
		fmt.Printf("❌ Setup error: %v\n", err)
		os.Exit(1)
	}

	setupTime := time.Since(startSetup)

	fmt.Printf("    ✅ Setup: %v\n", setupTime)

	fmt.Println("5️⃣  Proving (Groth16)...")

	startProve := time.Now()

	proof, err := groth16.Prove(cs, pk, witness)

	if err != nil {
		fmt.Printf("❌ Prove error: %v\n", err)
		os.Exit(1)
	}

	proveTime := time.Since(startProve)

	fmt.Printf("    ✅ Proof: %v\n", proveTime)

	fmt.Println("6️⃣  Verifying...")

	publicWitness, _ := witness.Public()

	err = groth16.Verify(proof, vk, publicWitness)

	if err != nil {
		fmt.Printf("❌ Verify error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("    ✅ Proof verified!")

	report := fmt.Sprintf(`# 📊 Simple Verifier - Gnark Benchmark

> **Generated:** %s
> **Hash:** Poseidon2 (BN254)

## Configuration

| Parameter | Value |
|:---|:---|
| MAX_HANDLERS | %d |
| MAX_OPS | %d |
| MAX_ROWS | %d |
| MAX_COLS | %d |
| MAX_GROUPS | %d |

## Results

| Metric | Value |
|:---|:---|
| **Constraints** | %d |
| **Compile** | %v |
| **Witness** | %v |
| **Setup** | %v |
| **Proof** | %v |
`,
		time.Now().Format("2006-01-02"),
		lib.MAX_HANDLERS,
		lib.MAX_OPS,
		lib.MAX_ROWS,
		lib.MAX_COLS,
		lib.MAX_GROUPS,
		cs.GetNbConstraints(),
		compileTime,
		witnessTime,
		setupTime,
		proveTime,
	)

	os.MkdirAll("benchmark", 0755)

	os.WriteFile("benchmark/BENCHMARK_REPORT.md", []byte(report), 0644)

	fmt.Println("")
	fmt.Println("📊 Report saved: benchmark/BENCHMARK_REPORT.md")
}

func generateTestAssignment() (*circuit.SimpleVerifierCircuit, error) {
	var assignment circuit.SimpleVerifierCircuit

	for col := 0; col < lib.MAX_COLS; col++ {
		for row := 0; row < lib.MAX_ROWS; row++ {
			assignment.Items[col][row] = big.NewInt(0)
		}
	}

	for row := 0; row < TEST_NR; row++ {
		assignment.Items[0][row] = big.NewInt(int64(row + 1))

		assignment.Items[1][row] = big.NewInt(int64((row % 10) + 1))

		assignment.Items[2][row] = big.NewInt(int64((row % 5) + 1))

		assignment.Items[3][row] = big.NewInt(int64(row * 2))
	}

	h0NC := 4

	h0FlatItems := make([]*big.Int, lib.TOTAL_ITEMS)

	for col := 0; col < lib.MAX_COLS; col++ {
		for row := 0; row < lib.MAX_ROWS; row++ {
			idx := col*lib.MAX_ROWS + row

			isValid := row < TEST_NR && col < h0NC

			if isValid {
				h0FlatItems[idx] = assignment.Items[col][row].(*big.Int)
			} else {
				h0FlatItems[idx] = big.NewInt(0)
			}
		}
	}

	h0MerkleRoot := computeMerkle16Root(h0FlatItems)

	fmt.Printf("    Handler 0: NC=%d\n", h0NC)
	fmt.Printf("      - MERKLE: %s...\n", truncateStr(h0MerkleRoot.String(), 15))
	fmt.Printf("      - COUNT: %d\n", TEST_NR)

	h1NC := 8

	h1Sum := big.NewInt(0)

	for row := 0; row < TEST_NR; row++ {
		h1Sum.Add(h1Sum, assignment.Items[1][row].(*big.Int))
	}

	fmt.Printf("    Handler 1: NC=%d\n", h1NC)
	fmt.Printf("      - SUM col 1: %s\n", h1Sum.String())

	groupMap := make(map[int64]*big.Int)

	for row := 0; row < TEST_NR; row++ {
		key := assignment.Items[2][row].(*big.Int).Int64()

		val := new(big.Int).Set(assignment.Items[1][row].(*big.Int))

		if existing, ok := groupMap[key]; ok {
			existing.Add(existing, val)
		} else {
			groupMap[key] = val
		}
	}

	sortedKeys := make([]int64, 0, len(groupMap))

	for k := range groupMap {
		sortedKeys = append(sortedKeys, k)
	}

	for i := 0; i < len(sortedKeys); i++ {
		for j := i + 1; j < len(sortedKeys); j++ {
			if sortedKeys[i] > sortedKeys[j] {
				sortedKeys[i], sortedKeys[j] = sortedKeys[j], sortedKeys[i]
			}
		}
	}

	actualNumGroups := len(sortedKeys)

	publicGroupKeys := make([]*big.Int, lib.MAX_GROUPS)

	groupSums := make([]*big.Int, lib.MAX_GROUPS)

	for i := 0; i < lib.MAX_GROUPS; i++ {
		if i < actualNumGroups {
			publicGroupKeys[i] = big.NewInt(sortedKeys[i])

			groupSums[i] = new(big.Int).Set(groupMap[sortedKeys[i]])
		} else {
			publicGroupKeys[i] = big.NewInt(0)

			groupSums[i] = big.NewInt(0)
		}
	}

	fmt.Printf("      - SUM_BY (%d groups):\n", actualNumGroups)

	for i := 0; i < actualNumGroups; i++ {
		fmt.Printf("          [%s]: %s\n", publicGroupKeys[i].String(), groupSums[i].String())
	}

	h1SumBySSZ := computeSSZKeyValue(publicGroupKeys, groupSums)

	fmt.Printf("      - SUM_BY SSZ: %s...\n", truncateStr(h1SumBySSZ.String(), 15))

	assignment.NR = big.NewInt(int64(TEST_NR))

	assignment.NumHandlers = big.NewInt(int64(TEST_NUM_HANDLERS))

	assignment.HandlerNCs[0] = big.NewInt(int64(h0NC))

	assignment.OpCodes[0][0] = big.NewInt(lib.OP_MERKLE16)

	assignment.OpCodes[0][1] = big.NewInt(lib.OP_COUNT)

	assignment.OpCodes[0][2] = big.NewInt(lib.OP_NOOP)

	assignment.OpCodes[0][3] = big.NewInt(lib.OP_NOOP)

	for op := 0; op < lib.MAX_OPS; op++ {
		assignment.OpArgs[0][op] = [2]frontend.Variable{big.NewInt(0), big.NewInt(0)}

		assignment.NumGroups[0][op] = big.NewInt(0)

		for g := 0; g < lib.MAX_GROUPS; g++ {
			assignment.GroupKeys[0][op][g] = big.NewInt(0)
		}
	}

	assignment.Results[0][0] = h0MerkleRoot

	assignment.Results[0][1] = big.NewInt(int64(TEST_NR))

	assignment.Results[0][2] = big.NewInt(0)

	assignment.Results[0][3] = big.NewInt(0)

	assignment.HandlerNCs[1] = big.NewInt(int64(h1NC))

	assignment.OpCodes[1][0] = big.NewInt(lib.OP_SUM_COL)

	assignment.OpCodes[1][1] = big.NewInt(lib.OP_SUM_COL_BY)

	assignment.OpCodes[1][2] = big.NewInt(lib.OP_NOOP)

	assignment.OpCodes[1][3] = big.NewInt(lib.OP_NOOP)

	assignment.OpArgs[1][0] = [2]frontend.Variable{big.NewInt(1), big.NewInt(0)}

	assignment.NumGroups[1][0] = big.NewInt(0)

	for g := 0; g < lib.MAX_GROUPS; g++ {
		assignment.GroupKeys[1][0][g] = big.NewInt(0)
	}

	assignment.OpArgs[1][1] = [2]frontend.Variable{big.NewInt(1), big.NewInt(2)}

	assignment.NumGroups[1][1] = big.NewInt(int64(actualNumGroups))

	for g := 0; g < lib.MAX_GROUPS; g++ {
		assignment.GroupKeys[1][1][g] = publicGroupKeys[g]
	}

	for op := 2; op < lib.MAX_OPS; op++ {
		assignment.OpArgs[1][op] = [2]frontend.Variable{big.NewInt(0), big.NewInt(0)}

		assignment.NumGroups[1][op] = big.NewInt(0)

		for g := 0; g < lib.MAX_GROUPS; g++ {
			assignment.GroupKeys[1][op][g] = big.NewInt(0)
		}
	}

	assignment.Results[1][0] = h1Sum

	assignment.Results[1][1] = h1SumBySSZ

	assignment.Results[1][2] = big.NewInt(0)

	assignment.Results[1][3] = big.NewInt(0)

	for h := 2; h < lib.MAX_HANDLERS; h++ {
		assignment.HandlerNCs[h] = big.NewInt(1)

		for op := 0; op < lib.MAX_OPS; op++ {
			assignment.OpCodes[h][op] = big.NewInt(lib.OP_NOOP)

			assignment.OpArgs[h][op] = [2]frontend.Variable{big.NewInt(0), big.NewInt(0)}

			assignment.Results[h][op] = big.NewInt(0)

			assignment.NumGroups[h][op] = big.NewInt(0)

			for g := 0; g < lib.MAX_GROUPS; g++ {
				assignment.GroupKeys[h][op][g] = big.NewInt(0)
			}
		}
	}

	return &assignment, nil
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}

	return s[:n]
}

func poseidon2Hash(inputs ...*big.Int) *big.Int {
	h := poseidon2.NewMerkleDamgardHasher()

	for _, input := range inputs {
		var elem fr.Element

		elem.SetBigInt(input)

		b := elem.Marshal()

		h.Write(b)
	}

	result := h.Sum(nil)

	var resElem fr.Element

	resElem.SetBytes(result)

	res := new(big.Int)

	resElem.BigInt(res)

	return res
}

func computeMerkle16Root(items []*big.Int) *big.Int {
	currentLevel := make([]*big.Int, len(items))

	copy(currentLevel, items)

	for level := 0; level < lib.N_LEVELS; level++ {
		nextLevelSize := len(currentLevel) / 16

		nextLevel := make([]*big.Int, nextLevelSize)

		for i := 0; i < nextLevelSize; i++ {
			chunk := currentLevel[i*16 : (i+1)*16]

			nextLevel[i] = poseidon2Hash(chunk...)
		}

		currentLevel = nextLevel
	}

	return currentLevel[0]
}

func computeSSZKeyValue(keys, values []*big.Int) *big.Int {
	n := len(keys)

	pairHashes := make([]*big.Int, n)

	for i := 0; i < n; i++ {
		pairHashes[i] = poseidon2Hash(keys[i], values[i])
	}

	return computeSSZEncode(pairHashes)
}

func computeSSZEncode(values []*big.Int) *big.Int {
	n := len(values)

	paddedSize := 1
	levels := 0

	for paddedSize < n {
		paddedSize = paddedSize * 2

		levels++
	}

	if paddedSize == 1 {
		levels = 1

		paddedSize = 2
	}

	padded := make([]*big.Int, paddedSize)

	for i := 0; i < paddedSize; i++ {
		if i < n {
			padded[i] = values[i]
		} else {
			padded[i] = big.NewInt(0)
		}
	}

	currentLevel := padded

	for level := 0; level < levels; level++ {
		nextSize := len(currentLevel) / 2

		nextLevel := make([]*big.Int, nextSize)

		for i := 0; i < nextSize; i++ {
			nextLevel[i] = poseidon2Hash(currentLevel[i*2], currentLevel[i*2+1])
		}

		currentLevel = nextLevel
	}

	return currentLevel[0]
}
