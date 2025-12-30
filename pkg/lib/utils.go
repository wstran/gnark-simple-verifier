package lib

import (
	"github.com/consensys/gnark/frontend"
)

// Selector selects value at index from array
// Returns arr[index] where index is a signal
// Port of circom Selector template
func Selector(api frontend.API, arr []frontend.Variable, index frontend.Variable) frontend.Variable {
	n := len(arr)

	sum := frontend.Variable(0)

	for i := 0; i < n; i++ {
		isEq := api.IsZero(api.Sub(index, i))

		product := api.Mul(arr[i], isEq)

		sum = api.Add(sum, product)
	}

	return sum
}

// RowMask creates mask for valid rows (i < NR)
// mask[i] = 1 if i < NR, else 0
// Port of circom RowMask template
func RowMask(api frontend.API, NR frontend.Variable, maxRows int) []frontend.Variable {
	mask := make([]frontend.Variable, maxRows)

	for i := 0; i < maxRows; i++ {
		mask[i] = LessThan(api, frontend.Variable(i), NR, 16)
	}

	return mask
}

// ColumnMask creates mask for valid columns (i < NC)
// Port of circom ColumnMask template
func ColumnMask(api frontend.API, NC frontend.Variable, maxCols int) []frontend.Variable {
	mask := make([]frontend.Variable, maxCols)

	for i := 0; i < maxCols; i++ {
		mask[i] = LessThan(api, frontend.Variable(i), NC, 8)
	}

	return mask
}

// ColumnMaskWithStart creates mask for valid columns with start offset
// mask[col] = 1 if startIndex <= col < startIndex + NC, else 0
// Port of circom ColumnMaskWithStart template
func ColumnMaskWithStart(api frontend.API, startIndex, NC frontend.Variable, maxCols int) []frontend.Variable {
	mask := make([]frontend.Variable, maxCols)

	for i := 0; i < maxCols; i++ {
		// Check: col >= startIndex (startIndex < col + 1)
		geStart := LessThan(api, startIndex, frontend.Variable(i+1), 8)

		// Check: col < startIndex + NC
		endIndex := api.Add(startIndex, NC)

		ltEnd := LessThan(api, frontend.Variable(i), endIndex, 8)

		// Both conditions must be true
		mask[i] = api.Mul(geStart, ltEnd)
	}

	return mask
}

// MaskedSum sums array values with mask
// Only sums where mask[i] == 1
// Port of circom MaskedSum template
func MaskedSum(api frontend.API, values []frontend.Variable, mask []frontend.Variable) frontend.Variable {
	n := len(values)

	acc := frontend.Variable(0)

	for i := 0; i < n; i++ {
		product := api.Mul(values[i], mask[i])

		acc = api.Add(acc, product)
	}

	return acc
}

// LessThan returns 1 if a < b, else 0 (STRICT less than)
// Uses bit decomposition for comparison
// bits is the bit width for the comparison (must cover max(a, b))
func LessThan(api frontend.API, a, b frontend.Variable, bits int) frontend.Variable {
	powerOfTwo := frontend.Variable(1 << bits)

	diff := api.Add(api.Sub(b, a), api.Sub(powerOfTwo, 1))

	diffBits := api.ToBinary(diff, bits+1)

	return diffBits[bits]
}

// IsEqual returns 1 if a == b, else 0
func IsEqual(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
}

// CreateFlatMask creates a flat mask array for the items matrix
// Combines row mask and column mask: flatMask[col*MAX_ROWS + row] = rowMask[row] * colMask[col]
func CreateFlatMask(api frontend.API, rowMask []frontend.Variable, colMask []frontend.Variable) []frontend.Variable {
	flatMask := make([]frontend.Variable, TOTAL_ITEMS)

	for col := 0; col < MAX_COLS; col++ {
		for row := 0; row < MAX_ROWS; row++ {
			idx := col*MAX_ROWS + row

			flatMask[idx] = api.Mul(rowMask[row], colMask[col])
		}
	}

	return flatMask
}

// FlattenItems converts 2D items matrix to 1D array
// flatItems[col*MAX_ROWS + row] = items[col][row]
func FlattenItems(items [MAX_COLS][MAX_ROWS]frontend.Variable) []frontend.Variable {
	flatItems := make([]frontend.Variable, TOTAL_ITEMS)

	for col := 0; col < MAX_COLS; col++ {
		for row := 0; row < MAX_ROWS; row++ {
			idx := col*MAX_ROWS + row

			flatItems[idx] = items[col][row]
		}
	}

	return flatItems
}

// ApplyMask applies mask to items: maskedItems[i] = items[i] * mask[i]
func ApplyMask(api frontend.API, items []frontend.Variable, mask []frontend.Variable) []frontend.Variable {
	n := len(items)

	masked := make([]frontend.Variable, n)

	for i := 0; i < n; i++ {
		masked[i] = api.Mul(items[i], mask[i])
	}

	return masked
}
