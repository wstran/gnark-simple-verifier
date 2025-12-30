package lib

import (
	"github.com/consensys/gnark/frontend"
)

// SSZEncode hashes array of felts to a single root using binary Merkle tree
// Port of circom SSZEncode template
func SSZEncode(api frontend.API, values []frontend.Variable) frontend.Variable {
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

	padded := make([]frontend.Variable, paddedSize)

	for i := 0; i < paddedSize; i++ {
		if i < n {
			padded[i] = values[i]
		} else {
			padded[i] = frontend.Variable(0)
		}
	}

	currentLevel := padded

	for level := 0; level < levels; level++ {
		levelSize := len(currentLevel)
		nextSize := levelSize / 2

		nextLevel := make([]frontend.Variable, nextSize)

		for i := 0; i < nextSize; i++ {
			left := currentLevel[i*2]

			right := currentLevel[i*2+1]

			nextLevel[i] = Poseidon2Two(api, left, right)
		}

		currentLevel = nextLevel
	}

	return currentLevel[0]
}

// SSZKeyValue encodes (key, value) pairs into a single root
// Port of circom SSZKeyValue template
func SSZKeyValue(api frontend.API, keys []frontend.Variable, values []frontend.Variable) frontend.Variable {
	n := len(keys)

	pairHashes := make([]frontend.Variable, n)

	for i := 0; i < n; i++ {
		pairHashes[i] = Poseidon2Two(api, keys[i], values[i])
	}

	return SSZEncode(api, pairHashes)
}
