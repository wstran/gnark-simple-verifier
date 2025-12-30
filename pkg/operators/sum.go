package operators

import (
	"simple-verifier-gnark/pkg/lib"

	"github.com/consensys/gnark/frontend"
)

// SumColumn sums a specific column of items with row mask
// Port of circom SumColumn template
func SumColumn(api frontend.API, items [lib.MAX_COLS][lib.MAX_ROWS]frontend.Variable, colIndex frontend.Variable, rowMask []frontend.Variable) frontend.Variable {
	// Get all values from the selected column
	selectedColumn := make([]frontend.Variable, lib.MAX_ROWS)

	for row := 0; row < lib.MAX_ROWS; row++ {
		// For each row, select the value at colIndex
		rowValues := make([]frontend.Variable, lib.MAX_COLS)

		for col := 0; col < lib.MAX_COLS; col++ {
			rowValues[col] = items[col][row]
		}

		selectedColumn[row] = lib.Selector(api, rowValues, colIndex)
	}

	// Sum with mask
	return lib.MaskedSum(api, selectedColumn, rowMask)
}
