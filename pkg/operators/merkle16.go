package operators

import (
	"simple-verifier-gnark/pkg/lib"

	"github.com/consensys/gnark/frontend"
)

// Merkle16Ordered builds a 16-ary Merkle tree from all items
// Port of circom Merkle16Ordered template
func Merkle16Ordered(api frontend.API, items []frontend.Variable, nLevels int) frontend.Variable {
	branchingFactor := 16
	totalItems := len(items)

	currentLevel := make([]frontend.Variable, totalItems)

	copy(currentLevel, items)

	for level := 0; level < nLevels; level++ {
		levelSize := len(currentLevel)
		nextLevelSize := levelSize / branchingFactor

		nextLevel := make([]frontend.Variable, nextLevelSize)

		for i := 0; i < nextLevelSize; i++ {
			var chunk [16]frontend.Variable

			for j := 0; j < branchingFactor; j++ {
				chunk[j] = currentLevel[i*branchingFactor+j]
			}

			nextLevel[i] = lib.Poseidon2Chunk16(api, chunk)
		}

		currentLevel = nextLevel
	}

	return currentLevel[0]
}

// Merkle16OrderedWithMask builds tree only from valid items
// Port of circom Merkle16OrderedWithMask template
func Merkle16OrderedWithMask(api frontend.API, items []frontend.Variable, mask []frontend.Variable, nLevels int) frontend.Variable {
	maskedItems := lib.ApplyMask(api, items, mask)

	return Merkle16Ordered(api, maskedItems, nLevels)
}
