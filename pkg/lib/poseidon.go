package lib

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

// BN254 Poseidon2 default parameters (from gnark-crypto bn254/fr/poseidon2)
// gnark v0.14.0 bug: NewPoseidon2 only supports BLS12_377
// Workaround: Call NewPoseidon2FromParameters directly with BN254 params
const (
	Poseidon2Width         = 2 // compression mode
	Poseidon2FullRounds    = 6
	Poseidon2PartialRounds = 50
)

// NewPoseidon2Hasher creates Poseidon2 hasher for BN254 using the workaround
func NewPoseidon2Hasher(api frontend.API) (hash.FieldHasher, error) {
	perm, err := poseidon2.NewPoseidon2FromParameters(api, Poseidon2Width, Poseidon2FullRounds, Poseidon2PartialRounds)

	if err != nil {
		return nil, err
	}

	return hash.NewMerkleDamgardHasher(api, perm, 0), nil
}

// Poseidon2Hash computes Poseidon2 hash of inputs
func Poseidon2Hash(api frontend.API, inputs ...frontend.Variable) frontend.Variable {
	h, err := NewPoseidon2Hasher(api)

	if err != nil {
		panic("failed to create poseidon2 hasher: " + err.Error())
	}

	for _, input := range inputs {
		h.Write(input)
	}

	return h.Sum()
}

// Poseidon2HashArray computes Poseidon2 hash of an array of inputs
func Poseidon2HashArray(api frontend.API, inputs []frontend.Variable) frontend.Variable {
	h, err := NewPoseidon2Hasher(api)

	if err != nil {
		panic("failed to create poseidon2 hasher: " + err.Error())
	}

	for _, input := range inputs {
		h.Write(input)
	}

	return h.Sum()
}

// Poseidon2Two computes Poseidon2 hash of exactly 2 inputs
func Poseidon2Two(api frontend.API, left, right frontend.Variable) frontend.Variable {
	return Poseidon2Hash(api, left, right)
}

// Poseidon2Chunk16 computes Poseidon2 hash of exactly 16 inputs
func Poseidon2Chunk16(api frontend.API, inputs [16]frontend.Variable) frontend.Variable {
	h, err := NewPoseidon2Hasher(api)

	if err != nil {
		panic("failed to create poseidon2 hasher: " + err.Error())
	}

	for i := 0; i < 16; i++ {
		h.Write(inputs[i])
	}

	return h.Sum()
}
