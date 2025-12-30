package operators

import (
	"simple-verifier-gnark/pkg/lib"

	"github.com/consensys/gnark/frontend"
)

// SumColumnByGroupResult holds the outputs of SumColumnByGroup
type SumColumnByGroupResult struct {
	GroupSums [lib.MAX_GROUPS]frontend.Variable
}

// SumColumnByGroup sums column X grouped by column Y
// Port of circom SumColumnByGroup template
//
// PUBLIC KEYS approach:
//   - Group keys [A, B, C, ...] are PUBLIC input
//   - Each row MUST match one of the public keys
//   - If any row has unknown key => circuit FAILS
//
// Note: When numGroups = 0, validation is DISABLED (for non-SUM_BY ops)
func SumColumnByGroup(
	api frontend.API,
	items [lib.MAX_COLS][lib.MAX_ROWS]frontend.Variable,
	colX frontend.Variable,
	colY frontend.Variable,
	rowMask []frontend.Variable,
	groupKeys [lib.MAX_GROUPS]frontend.Variable,
	numGroups frontend.Variable,
) SumColumnByGroupResult {
	// Create group mask: groupMask[g] = 1 if g < numGroups
	groupMask := make([]frontend.Variable, lib.MAX_GROUPS)

	for g := 0; g < lib.MAX_GROUPS; g++ {
		groupMask[g] = lib.LessThan(api, frontend.Variable(g), numGroups, 8)
	}

	// Select column values
	valuesX := make([]frontend.Variable, lib.MAX_ROWS)

	valuesY := make([]frontend.Variable, lib.MAX_ROWS)

	for row := 0; row < lib.MAX_ROWS; row++ {
		rowData := make([]frontend.Variable, lib.MAX_COLS)

		for col := 0; col < lib.MAX_COLS; col++ {
			rowData[col] = items[col][row]
		}

		valuesX[row] = lib.Selector(api, rowData, colX)

		valuesY[row] = lib.Selector(api, rowData, colY)
	}

	// Initialize group sum accumulators
	groupSumAccum := make([]frontend.Variable, lib.MAX_GROUPS)

	for g := 0; g < lib.MAX_GROUPS; g++ {
		groupSumAccum[g] = frontend.Variable(0)
	}

	// Track row match counts for validation
	rowMatchCount := make([]frontend.Variable, lib.MAX_ROWS)

	// Process all rows
	for row := 0; row < lib.MAX_ROWS; row++ {
		maskedX := api.Mul(valuesX[row], rowMask[row])

		rowMatchAccum := frontend.Variable(0)

		for g := 0; g < lib.MAX_GROUPS; g++ {
			isEq := lib.IsEqual(api, valuesY[row], groupKeys[g])

			matchFlag := api.Mul(isEq, groupMask[g])

			contrib := api.Mul(maskedX, matchFlag)

			groupSumAccum[g] = api.Add(groupSumAccum[g], contrib)

			rowMatchAccum = api.Add(rowMatchAccum, matchFlag)
		}

		rowMatchCount[row] = rowMatchAccum
	}

	// VALIDATION: Each valid row MUST match exactly one group
	for row := 0; row < lib.MAX_ROWS; row++ {
		validationTerm := api.Mul(api.Sub(rowMatchCount[row], rowMask[row]), numGroups)

		api.AssertIsEqual(validationTerm, 0)
	}

	// Build result (only GroupSums, no SSZ encoding)
	var result SumColumnByGroupResult

	for g := 0; g < lib.MAX_GROUPS; g++ {
		result.GroupSums[g] = groupSumAccum[g]
	}

	return result
}
