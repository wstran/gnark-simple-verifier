package operators

import (
	"simple-verifier-gnark/pkg/lib"

	"github.com/consensys/gnark/frontend"
)

// Count counts valid rows (where mask[i] == 1)
// Port of circom Count template
func Count(api frontend.API, rowMask []frontend.Variable) frontend.Variable {
	return lib.MaskedSum(api, rowMask, rowMask)
}
