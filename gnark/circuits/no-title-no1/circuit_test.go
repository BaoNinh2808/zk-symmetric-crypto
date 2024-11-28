package no_titlle_no1

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

func TestCipher(t *testing.T) {
	assert := test.NewAssert(t)

	var myCircuit MyCircuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	assert.NoError(err)
	fmt.Println("Number of constraints: ", r1cs.GetNbConstraints())

	// pk, _, err := groth16.Setup(r1cs)
	// assert.NoError(err)

	// new_witness, _ := frontend.NewWitness(&witness, ecc.BN254.ScalarField())

	// // Measure time for proof generation
	// startProof := time.Now()
	// proof, err := groth16.Prove(r1cs, pk, new_witness)
	// if err != nil {
	// 	fmt.Printf("Proof creation failed: %v\n", err)
	// 	return
	// }
	// elapsedProof := time.Since(startProof)
	// fmt.Printf("Proving Time: %v\n", elapsedProof)

	// fmt.Printf("Proof: %v\n", proof)
}
