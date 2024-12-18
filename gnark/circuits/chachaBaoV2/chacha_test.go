package chacha

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/BaoNinh2808/gnark/std/math/uints"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

// type roundCircuit struct {
// 	In  [16]uints.U32
// 	Out [16]uints.U32 `gnark:",public"`
// }

// func (c *roundCircuit) Define(api frontend.API) error {
// 	uapi, err := uints.New[uints.U32](api)
// 	if err != nil {
// 		return err
// 	}

// 	var workingState [16]uints.U32
// 	copy(workingState[:], c.In[:])

// 	Round(uapi, &workingState)
// 	Serialize(uapi, &workingState)

// 	for i := range c.Out {
// 		uapi.AssertEq(c.Out[i], workingState[i])
// 	}

// 	return nil
// }

// type qrBlock struct {
// 	In  [16]uints.U32
// 	Out [16]uints.U32 `gnark:",public"`
// }

// func (c *qrBlock) Define(api frontend.API) error {
// 	uapi, err := uints.New[uints.U32](api)
// 	if err != nil {
// 		return err
// 	}

// 	var workingState [16]uints.U32
// 	copy(workingState[:], c.In[:])

// 	QR(uapi, &workingState, 0, 1, 2, 3)
// 	for i := range c.Out {
// 		uapi.AssertEq(c.Out[i], workingState[i])
// 	}
// 	return nil
// }

// func TestQR(t *testing.T) {
// 	assert := test.NewAssert(t)
// 	witness := qrBlock{}
// 	witness.In[0] = uints.NewU32(0x11111111)
// 	witness.In[1] = uints.NewU32(0x01020304)
// 	witness.In[2] = uints.NewU32(0x9b8d6f43)
// 	witness.In[3] = uints.NewU32(0x01234567)

// 	witness.Out[0] = uints.NewU32(0xea2a92f4)
// 	witness.Out[1] = uints.NewU32(0xcb1cf8ce)
// 	witness.Out[2] = uints.NewU32(0x4581472e)
// 	witness.Out[3] = uints.NewU32(0x5881c4bb)

// 	err := test.IsSolved(&qrBlock{}, &witness, ecc.BN254.ScalarField())
// 	assert.NoError(err)

// 	assert.CheckCircuit(&qrBlock{}, test.WithValidAssignment(&witness))

// }

// func TestRound(t *testing.T) {
// 	assert := test.NewAssert(t)

// 	in := uints.NewU32Array([]uint32{
// 		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
// 		0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
// 		0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
// 		0x00000001, 0x09000000, 0x4a000000, 0x00000000})

// 	out := BytesToUint32BE([]uint8{
// 		0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
// 		0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
// 		0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
// 		0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e})

// 	witness := roundCircuit{}
// 	copy(witness.In[:], in)
// 	copy(witness.Out[:], out)
// 	err := test.IsSolved(&roundCircuit{}, &witness, ecc.BN254.ScalarField())
// 	assert.NoError(err)

// 	assert.CheckCircuit(&roundCircuit{}, test.WithValidAssignment(&witness))
// }

func TestCipher(t *testing.T) {
	assert := test.NewAssert(t)

	var myCircuit ChaChaCircuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	assert.NoError(err)
	fmt.Println("Number of constraints: ", r1cs.GetNbConstraints())

	// bKey := []uint8{
	// 	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	// 	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}

	// bNonce := []uint8{
	// 	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00}

	// counter := uints.NewU32(2)

	// bPt1 := make([]byte, 64)
	// rand.Read(bPt1)
	// bCt1 := make([]byte, 64)

	// cipher, err := chacha20.NewUnauthenticatedCipher(bKey, bNonce)
	// assert.NoError(err)

	// cipher.SetCounter(2)
	// cipher.XORKeyStream(bCt1, bPt1)

	// bPt2 := make([]byte, 64)
	// rand.Read(bPt2)
	// bCt2 := make([]byte, 64)
	// cipher.XORKeyStream(bCt2, bPt2)

	// bPt3 := make([]byte, 64)
	// copy(bPt3, []byte{0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// 	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// bCt3 := make([]byte, 64)
	// cipher.XORKeyStream(bCt3, bPt3)

	// bPt4 := make([]byte, 64)
	// copy(bPt4, []byte{0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// 	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// bCt4 := make([]byte, 64)
	// cipher.XORKeyStream(bCt4, bPt4)

	// bPt5 := make([]byte, 64)
	// copy(bPt5, []byte{0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// 	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// plaintext1 := BytesToUint32BE(bPt1)
	// ciphertext1 := BytesToUint32BE(bCt1)
	// plaintext2 := BytesToUint32BE(bPt2)
	// ciphertext2 := BytesToUint32BE(bCt2)

	// pt_value1 := BytesToUint32BE(bPt3)
	// ct_value2 := BytesToUint32BE(bCt3)
	// pt_value3 := BytesToUint32BE(bPt4)
	// ct_value4 := BytesToUint32BE(bCt4)

	// criteria_value := BytesToUint32BE(bPt5)

	// witness := ChaChaCircuit{}

	// copy(witness.Key[:], BytesToUint32LE(bKey))
	// copy(witness.Nonce[:], BytesToUint32LE(bNonce))
	// witness.Counter = counter
	// copy(witness.Data_Keys[0][:], plaintext1)
	// copy(witness.Enc_Data_Keys[0][:], ciphertext1)
	// copy(witness.Data_Keys[1][:], plaintext2)
	// copy(witness.Enc_Data_Keys[1][:], ciphertext2)

	// copy(witness.Data_Values[0][:], pt_value1)
	// copy(witness.Data_Values[1][:], pt_value3)
	// copy(witness.Enc_Data_Values[0][:], ct_value2)
	// copy(witness.Enc_Data_Values[1][:], ct_value4)

	// witness.Corrsponding_Data_Index[0] = 2
	// copy(witness.Criterias_Keys[0][:], plaintext2)

	// copy(witness.Criterias_Values[0][:], criteria_value)

	// err = test.IsSolved(&ChaChaCircuit{}, &witness, ecc.BN254.ScalarField())
	// assert.NoError(err)

	// assert.CheckCircuit(&ChaChaCircuit{}, test.WithValidAssignment(&witness))

	// // var myCircuit ChaChaCircuit
	// // r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	// // assert.NoError(err)
	// // fmt.Println("Number of constraints: ", r1cs.GetNbConstraints())

	// pk, _, err := groth16.Setup(r1cs)
	// assert.NoError(err)

	// new_witness, _ := frontend.NewWitness(&witness, ecc.BN254.ScalarField())

	// // Start CPU profiling
	// cpuProfile, err := os.Create("cpu_profile.prof")
	// assert.NoError(err)
	// defer cpuProfile.Close()

	// pprof.StartCPUProfile(cpuProfile)
	// defer pprof.StopCPUProfile()

	// // Measure memory profiling before proof
	// memBeforeProfile, err := os.Create("mem_profile_before.prof")
	// assert.NoError(err)
	// defer memBeforeProfile.Close()

	// // Write initial heap profile
	// pprof.WriteHeapProfile(memBeforeProfile)

	// // Measure time for proof generation
	// startProof := time.Now()
	// proof, err := groth16.Prove(r1cs, pk, new_witness)
	// if err != nil {
	// 	fmt.Printf("Proof creation failed: %v\n", err)
	// 	return
	// }
	// elapsedProof := time.Since(startProof)
	// fmt.Printf("Proving Time: %v\n", elapsedProof)

	// // Measure memory profiling after proof
	// memAfterProfile, err := os.Create("mem_profile_after.prof")
	// assert.NoError(err)
	// defer memAfterProfile.Close()

	// // Write final heap profile
	// pprof.WriteHeapProfile(memAfterProfile)

	// fmt.Printf("Proof: %v\n", proof)
}

func BytesToUint32LE(in []uint8) []uints.U32 {

	var res []uints.U32
	for i := 0; i < len(in); i += 4 {
		t := binary.LittleEndian.Uint32(in[i:])
		res = append(res, uints.NewU32(t))
	}
	return res
}

func BytesToUint32BE(in []uint8) []uints.U32 {

	var res []uints.U32
	for i := 0; i < len(in); i += 4 {
		t := binary.BigEndian.Uint32(in[i:])
		res = append(res, uints.NewU32(t))
	}
	return res
}
