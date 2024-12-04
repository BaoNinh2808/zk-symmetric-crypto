package no_titlle_no1

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/BaoNinh2808/gnark/std/math/uints"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/chacha20"
)

func TestCipher(t *testing.T) {
	assert := test.NewAssert(t)

	//create witness
	witness := MyCircuit{}
	data := [n]Block{}

	block0 := NewObjectKeyBlock()
	block1 := NewObjectValBlock()
	block2 := NewNumberKeyBlock()
	block3 := NewNumberValBlock()

	block0.Ref_index = uints.U8{Val: 0}
	block1.Ref_index = uints.U8{Val: 1}
	block2.Ref_index = uints.U8{Val: 2}
	block3.Ref_index = uints.U8{Val: 3}

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
		blocki := NewEmptyKeyBlock()
		blocki.Ref_index = uints.U8{Val: uint8(i)}
		data[i] = *blocki
	}

	for i := 5; i < split; i += 2 {
		blocki := NewEmptyValBlock()
		blocki.Ref_index = uints.U8{Val: uint8(i)}
		data[i] = *blocki
	}

	for i := split; i < n; i++ {
		blocki := NewEmptyValBlock()
		blocki.Ref_index = uints.U8{Val: uint8(i)}
		data[i] = *blocki
	}

	witness.Data = data

	// criteria_key = weight
	criteria_block_key := NewNumberKeyBlock()
	criteria_block_val := NewNumberValBlock()
	criteria_block_key.Data[0] = uints.NewU32(weight_key_1)
	criteria_block_key.Data[1] = uints.NewU32(weight_key_2)
	criteria_block_val.Data[0] = uints.NewU32(59)

	// witness.Criterias_Keys[0] = *criteria_block_key
	witness.Criterias_Vals[0] = *criteria_block_val

	// fmt.Println("Criteria Key: ", witness.Criterias_Keys[0].Data_type)
	// fmt.Println("Criteria Val: ", witness.Criterias_Vals[0].Data_type)

	// fmt.Println("Row: ", row)
	// fmt.Println("Col: ", col)
	witness.Corresponding_Data_Index[0] = uints.NewU8(2)
	// fmt.Println("Corresponding Data Index: ", witness.Corresponding_Data_Index[0])

	// for i := 0; i < n; i++ {
	// 	fmt.Printf("Data[%d]: %v\n", i, witness.Data[i].Data[0])
	// }

	// set enc_data
	enc_data := [64][16]uints.U32{}
	bKey := []uint8{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}

	bNonce := []uint8{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00}

	counter := uints.NewU32(2)

	cipher, err := chacha20.NewUnauthenticatedCipher(bKey, bNonce)
	assert.NoError(err)
	cipher.SetCounter(2)

	//"age" --> store in big endian
	bPt1 := []byte{
		0x00, 0x00, 0x00, 0x00, 0x61, 0x67, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	bCt1 := make([]byte, 64)
	cipher.XORKeyStream(bCt1, bPt1)

	//21 --> store in big endian
	bPt2 := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	bCt2 := make([]byte, 64)
	cipher.XORKeyStream(bCt2, bPt2)

	//"weight" --> store in big endian
	bPt3 := []byte{
		0x00, 0x00, 0x00, 0x00, 0x77, 0x65, 0x69, 0x67, 0x68, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	bCt3 := make([]byte, 64)
	cipher.XORKeyStream(bCt3, bPt3)

	//60 --> store in big endian
	bPt4 := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	bCt4 := make([]byte, 64)
	cipher.XORKeyStream(bCt4, bPt4)

	copy(enc_data[0][:], BytesToUint32BE(bCt1))
	copy(enc_data[1][:], BytesToUint32BE(bCt2))
	copy(enc_data[2][:], BytesToUint32BE(bCt3))
	copy(enc_data[3][:], BytesToUint32BE(bCt4))

	bPtEmpty := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	for i := 4; i < n; i++ {
		bCtEmpty := make([]byte, 64)
		cipher.XORKeyStream(bCtEmpty, bPtEmpty)
		copy(enc_data[i][:], BytesToUint32BE(bCtEmpty))
	}

	witness.Counter = counter
	witness.Enc_Data = enc_data
	copy(witness.Key[:], BytesToUint32LE(bKey))
	copy(witness.Nonce[:], BytesToUint32LE(bNonce))

	var myCircuit MyCircuit
	startCompile := time.Now()

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	assert.NoError(err)
	fmt.Println("Number of constraints: ", r1cs.GetNbConstraints())

	elasedCompile := time.Since(startCompile)
	fmt.Printf("Compile Time: %v\n", elasedCompile)

	startSetup := time.Now()
	pk, vk, err := groth16.Setup(r1cs)
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

	// fmt.Printf("Proof: %v\n", proof)
	startVerify := time.Now()
	pubWitness, _ := new_witness.Public()
	groth16.Verify(proof, vk, pubWitness)
	elapsedVerify := time.Since(startVerify)
	fmt.Printf("Verify Time: %v\n", elapsedVerify)
}

func BytesToUint32BE(in []uint8) []uints.U32 {

	var res []uints.U32
	for i := 0; i < len(in); i += 4 {
		t := binary.BigEndian.Uint32(in[i:])
		res = append(res, uints.NewU32(t))
	}
	return res
}

func BytesToUint32LE(in []uint8) []uints.U32 {

	var res []uints.U32
	for i := 0; i < len(in); i += 4 {
		t := binary.LittleEndian.Uint32(in[i:])
		res = append(res, uints.NewU32(t))
	}
	return res
}
