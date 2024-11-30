package no_titlle_no1

import (
	"fmt"
	"testing"
	"time"

	"github.com/BaoNinh2808/gnark/std/math/uints"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

func TestCipher(t *testing.T) {
	assert := test.NewAssert(t)

	//create witness
	witness := MyCircuit{}
	data := [n]Block{}

	block0 := NewNumberKeyBlockWithIndex(0)
	block1 := NewNumberValBlockWithIndex(1)
	block2 := NewNumberKeyBlockWithIndex(2)
	block3 := NewNumberValBlockWithIndex(3)

	// "age" = 0x616765
	age_key := uint32(0x61676500)
	block0.Data[0] = uints.NewU32(age_key)

	// 21
	age_val := uint32(21)
	block1.Data[0] = uints.NewU32(age_val)

	// "weight" = 0x776569676874 --> 0x77656967, 0x68740000
	weight_key_1 := uint32(0x77656967)
	weight_key_2 := uint32(0x68740000)

	block2.Data[0] = uints.NewU32(weight_key_1)
	block2.Data[1] = uints.NewU32(weight_key_2)

	// 60
	weight_val := uint32(60)
	block3.Data[0] = uints.NewU32(weight_val)

	data[0] = *block0
	data[1] = *block1
	data[2] = *block2
	data[3] = *block3

	for i := 4; i < split; i += 2 {
		blocki := NewEmptyKeyBlockWithIndex(i)
		data[i] = *blocki
	}

	for i := 5; i < split; i += 2 {
		blocki := NewEmptyValBlockWithIndex(i)
		data[i] = *blocki
	}

	for i := split; i < n; i++ {
		blocki := NewEmptyValBlockWithIndex(i)
		data[i] = *blocki
	}

	witness.Data = data
	for i := 0; i < n; i++ {
		fmt.Printf("Data[%d]: %v\n", i, witness.Data[i].Data[0])
	}

	var myCircuit MyCircuit
	startCompile := time.Now()

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	assert.NoError(err)
	fmt.Println("Number of constraints: ", r1cs.GetNbConstraints())

	elasedCompile := time.Since(startCompile)
	fmt.Printf("Compile Time: %v\n", elasedCompile)

	startSetup := time.Now()
	pk, _, err := groth16.Setup(r1cs)
	assert.NoError(err)
	elasedSetup := time.Since(startSetup)
	fmt.Printf("Setup Time: %v\n", elasedSetup)

	new_witness, _ := frontend.NewWitness(&witness, ecc.BN254.ScalarField())

	// Measure time for proof generation
	startProof := time.Now()
	proof, err := groth16.Prove(r1cs, pk, new_witness)
	if err != nil {
		fmt.Printf("Proof creation failed: %v\n", err)
		return
	}
	// assert.NoError(err)
	elapsedProof := time.Since(startProof)
	fmt.Printf("Proving Time: %v\n", elapsedProof)

	fmt.Printf("Proof: %v\n", proof)
}
