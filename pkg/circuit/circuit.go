package circuit

import (
	"simple-verifier-gnark/pkg/lib"
	"simple-verifier-gnark/pkg/operators"

	"github.com/consensys/gnark/frontend"
)

// SimpleVerifierCircuit is the main circuit definition
// Port of circom SimpleVerifier template
//
// Security Features:
//   - Strict opcode validation (must match exactly 1 valid opcode)
//   - Handler mask for inactive handler skip
//   - GROUP BY validation with numGroups=0 bypass
type SimpleVerifierCircuit struct {
	// =====================================
	// Public Inputs
	// =====================================

	// HandlerNCs: NC (number of columns) per handler
	HandlerNCs [lib.MAX_HANDLERS]frontend.Variable `gnark:",public"`

	// HandlerStartIndex: starting column index per handler
	HandlerStartIndex [lib.MAX_HANDLERS]frontend.Variable `gnark:",public"`

	// OpCodes: ops per handler [handler][op]
	OpCodes [lib.MAX_HANDLERS][lib.MAX_OPS]frontend.Variable `gnark:",public"`

	// OpArgs: [colX, colY] per op [handler][op][2]
	OpArgs [lib.MAX_HANDLERS][lib.MAX_OPS][2]frontend.Variable `gnark:",public"`

	// Results: expected results [handler][op][group]
	Results [lib.MAX_HANDLERS][lib.MAX_OPS][lib.MAX_GROUPS]frontend.Variable `gnark:",public"`

	// GroupKeys: PUBLIC group keys [handler][op][group]
	GroupKeys [lib.MAX_HANDLERS][lib.MAX_OPS][lib.MAX_GROUPS]frontend.Variable `gnark:",public"`

	// NumGroups: groups per SUM_BY op [handler][op]
	NumGroups [lib.MAX_HANDLERS][lib.MAX_OPS]frontend.Variable `gnark:",public"`

	// NumHandlers: actual number of handlers
	NumHandlers frontend.Variable `gnark:",public"`

	// =====================================
	// Private Inputs (SHARED across handlers)
	// =====================================

	// NR: number of rows (shared)
	NR frontend.Variable

	// Items: matrix data (shared) [col][row]
	Items [lib.MAX_COLS][lib.MAX_ROWS]frontend.Variable
}

// Define implements frontend.Circuit
func (c *SimpleVerifierCircuit) Define(api frontend.API) error {
	// Step 1: Create row mask (shared)
	rowMask := lib.RowMask(api, c.NR, lib.MAX_ROWS)

	// Step 2: Create column masks per handler
	colMasks := make([][]frontend.Variable, lib.MAX_HANDLERS)

	for h := 0; h < lib.MAX_HANDLERS; h++ {
		colMasks[h] = lib.ColumnMaskWithStart(api, c.HandlerStartIndex[h], c.HandlerNCs[h], lib.MAX_COLS)
	}

	// Step 3: Handler mask (skip inactive handlers)
	handlerMask := make([]frontend.Variable, lib.MAX_HANDLERS)

	for h := 0; h < lib.MAX_HANDLERS; h++ {
		handlerMask[h] = lib.LessThan(api, frontend.Variable(h), c.NumHandlers, 8)
	}

	// Step 4: MERKLE16 instances per handler
	merkleRoots := make([]frontend.Variable, lib.MAX_HANDLERS)

	for h := 0; h < lib.MAX_HANDLERS; h++ {
		flatItems := lib.FlattenItems(c.Items)

		flatMask := lib.CreateFlatMask(api, rowMask, colMasks[h])

		merkleRoots[h] = operators.Merkle16OrderedWithMask(api, flatItems, flatMask, lib.N_LEVELS)
	}

	// Step 5: COUNT instance (shared)
	countResult := operators.Count(api, rowMask)

	// Step 6: SUM operators per handler per op
	sumResults := make([][]frontend.Variable, lib.MAX_HANDLERS)

	for h := 0; h < lib.MAX_HANDLERS; h++ {
		sumResults[h] = make([]frontend.Variable, lib.MAX_OPS)

		for op := 0; op < lib.MAX_OPS; op++ {
			sumResults[h][op] = operators.SumColumn(api, c.Items, c.OpArgs[h][op][0], rowMask)
		}
	}

	// Step 7: SUM_BY operators per handler per op
	sumByResults := make([][]operators.SumColumnByGroupResult, lib.MAX_HANDLERS)

	for h := 0; h < lib.MAX_HANDLERS; h++ {
		sumByResults[h] = make([]operators.SumColumnByGroupResult, lib.MAX_OPS)

		for op := 0; op < lib.MAX_OPS; op++ {
			sumByResults[h][op] = operators.SumColumnByGroup(
				api,
				c.Items,
				c.OpArgs[h][op][0],
				c.OpArgs[h][op][1],
				rowMask,
				c.GroupKeys[h][op],
				c.NumGroups[h][op],
			)
		}
	}

	// Step 8: OpCode matching and result multiplexing
	for h := 0; h < lib.MAX_HANDLERS; h++ {
		for op := 0; op < lib.MAX_OPS; op++ {
			// OpCode matching
			isNoop := lib.IsEqual(api, c.OpCodes[h][op], frontend.Variable(lib.OP_NOOP))

			isMerkle := lib.IsEqual(api, c.OpCodes[h][op], frontend.Variable(lib.OP_MERKLE16))

			isCount := lib.IsEqual(api, c.OpCodes[h][op], frontend.Variable(lib.OP_COUNT))

			isSum := lib.IsEqual(api, c.OpCodes[h][op], frontend.Variable(lib.OP_SUM_COL))

			isSumBy := lib.IsEqual(api, c.OpCodes[h][op], frontend.Variable(lib.OP_SUM_COL_BY))

			// STRICT: Validate opcode is exactly 1 valid type
			validOpSum := api.Add(
				api.Add(api.Add(api.Add(isNoop, isMerkle), isCount), isSum),
				isSumBy,
			)

			opValidationTerm := api.Mul(api.Sub(validOpSum, 1), handlerMask[h])

			api.AssertIsEqual(opValidationTerm, 0)

			// Result multiplexing (scalar ops go to index 0)
			resultNoop := frontend.Variable(0)

			resultMerkle := api.Mul(merkleRoots[h], isMerkle)

			resultCount := api.Mul(countResult, isCount)

			resultSum := api.Mul(sumResults[h][op], isSum)

			// Per-group comparison for SUM_BY, slot 0 for other ops
			for g := 0; g < lib.MAX_GROUPS; g++ {
				resultSumByG := api.Mul(sumByResults[h][op].GroupSums[g], isSumBy)

				var computedResult frontend.Variable

				if g == 0 {
					// Slot 0: scalar ops OR first group of SUM_BY
					computedResult = api.Add(
						api.Add(
							api.Add(api.Add(resultNoop, resultMerkle), resultCount),
							resultSum,
						),
						resultSumByG,
					)
				} else {
					// Slot 1+: only SUM_BY has values
					computedResult = resultSumByG
				}

				// Verify: (computed - expected) * handlerMask === 0
				resultDiff := api.Mul(api.Sub(computedResult, c.Results[h][op][g]), handlerMask[h])

				api.AssertIsEqual(resultDiff, 0)
			}
		}
	}

	return nil
}
