package chacha

import (
	"fmt"
	"math/big"

	"github.com/BaoNinh2808/gnark/std/math/uints"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

const num_of_data_pieces = 2
const num_of_criterias = 1

type ChaChaCircuit struct {
	Key             [8]uints.U32
	Counter         uints.U32    `gnark:",public"`
	Nonce           [3]uints.U32 `gnark:",public"`
	Data_Keys       [num_of_data_pieces][16]uints.U32
	Data_Values     [num_of_data_pieces][16]uints.U32
	Enc_Data_Keys   [num_of_data_pieces][16]uints.U32 `gnark:",public"`
	Enc_Data_Values [num_of_data_pieces][16]uints.U32 `gnark:",public"`

	Criterias_Keys [num_of_criterias][16]uints.U32 `gnark:",public"`
	// omit operator is <=
	Criterias_Values        [num_of_criterias][16]uints.U32 `gnark:",public"`
	Corrsponding_Data_Index [num_of_criterias]frontend.Variable
}

func (c *ChaChaCircuit) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	var state [16]uints.U32
	one := uints.NewU32(1)
	uapi.AssertEq(one, uints.NewU32(1)) //constrain the one value is equal to 1
	counter := c.Counter

	for j := 0; j < num_of_data_pieces; j++ {
		// Fill state. Start with constants
		state[0] = uints.NewU32(0x61707865)
		state[1] = uints.NewU32(0x3320646e)
		state[2] = uints.NewU32(0x79622d32)
		state[3] = uints.NewU32(0x6b206574)

		uapi.AssertEq(state[0], uints.NewU32(0x61707865)) //contrain the value assign to the start state is right
		uapi.AssertEq(state[1], uints.NewU32(0x3320646e)) //contrain the value assign to the start state is right
		uapi.AssertEq(state[2], uints.NewU32(0x79622d32)) //contrain the value assign to the start state is right
		uapi.AssertEq(state[3], uints.NewU32(0x6b206574)) //contrain the value assign to the start state is right

		// set key
		copy(state[4:], c.Key[:])
		// set counter
		state[12] = counter
		// fmt.Printf("counter: %v\n", state[12])

		// set nonce
		copy(state[13:], c.Nonce[:])
		// modify state with round function
		Round(uapi, &state)
		// produce keystream from state
		Serialize(uapi, &state)

		// xor keystream with input
		var ciphertext [16]uints.U32
		for i, s := range state {
			ciphertext[i] = uapi.Xor(c.Data_Keys[j][i], s)
		}

		fmt.Printf("plaintext: %v\n", c.Data_Keys[j][0])
		// check that output matches ciphertext
		for i := 0; i < 16; i++ {
			uapi.AssertEq(c.Enc_Data_Keys[j][i], ciphertext[i])
		}

		// increment counter for next block
		counter = uapi.Add(counter, one)
	}

	for j := 0; j < num_of_data_pieces; j++ {
		// Fill state. Start with constants
		state[0] = uints.NewU32(0x61707865)
		state[1] = uints.NewU32(0x3320646e)
		state[2] = uints.NewU32(0x79622d32)
		state[3] = uints.NewU32(0x6b206574)

		uapi.AssertEq(state[0], uints.NewU32(0x61707865)) //contrain the value assign to the start state is right
		uapi.AssertEq(state[1], uints.NewU32(0x3320646e)) //contrain the value assign to the start state is right
		uapi.AssertEq(state[2], uints.NewU32(0x79622d32)) //contrain the value assign to the start state is right
		uapi.AssertEq(state[3], uints.NewU32(0x6b206574)) //contrain the value assign to the start state is right

		// set key
		copy(state[4:], c.Key[:])
		// set counter
		state[12] = counter
		// fmt.Printf("counter: %v\n", state[12])

		// set nonce
		copy(state[13:], c.Nonce[:])
		// modify state with round function
		Round(uapi, &state)
		// produce keystream from state
		Serialize(uapi, &state)

		// xor keystream with input
		var ciphertext [16]uints.U32
		for i, s := range state {
			ciphertext[i] = uapi.Xor(c.Data_Values[j][i], s)
		}

		// check that output matches ciphertext
		for i := 0; i < 16; i++ {
			uapi.AssertEq(c.Enc_Data_Values[j][i], ciphertext[i])
		}

		// increment counter for next block
		counter = uapi.Add(counter, one)
	}

	for i := 0; i < num_of_criterias; i++ {
		bits := api.ToBinary(c.Corrsponding_Data_Index[i], num_of_data_pieces)
		// fmt.Printf("bits: %v\n", bits)

		var selectValue [16]uints.U32
		var selectKey [16]uints.U32
		selectValue = c.Data_Values[0]
		selectKey = c.Data_Keys[0]
		for j := 0; j < num_of_data_pieces; j++ {
			for k := 0; k < 16; k++ {
				for l := 0; l < 4; l++ {
					selectValue[k][l].Val = api.Select(bits[j], c.Data_Values[j][k][l].Val, selectValue[k][l].Val)
					selectKey[k][l].Val = api.Select(bits[j], c.Data_Keys[j][k][l].Val, selectKey[k][l].Val)
				}
			}
		}

		// Check satisfy the condition
		Satisfy(api, uapi, selectKey, selectValue, c.Criterias_Keys[i], c.Criterias_Values[i])
	}

	return nil
}

func Satisfy(api frontend.API, uapi *uints.BinaryField[uints.U32], selectKey [16]uints.U32, selectValue [16]uints.U32, criteriaKey [16]uints.U32, criteriaValue [16]uints.U32) {
	for i := 0; i < 16; i++ {
		uapi.AssertEq(selectKey[i], criteriaKey[i])
	}

	AssertIsLess(api, uapi, selectValue, criteriaValue)
}

func AssertIsLess(api frontend.API, uapi *uints.BinaryField[uints.U32], selectValue [16]uints.U32, criteriaValue [16]uints.U32) {
	// create a array of frontend.Variable with lenght lenB
	isLess := make([]frontend.Variable, 16)
	isEqual := make([]frontend.Variable, 16)

	isLess[0] = uapi.IsLess(selectValue[0], criteriaValue[0])
	isEqual[0] = uapi.IsEqual(selectValue[0], criteriaValue[0])

	for i := 1; i < 16; i++ {
		isLess[i] = api.Select(isLess[i-1], isLess[i-1], uapi.IsLess(selectValue[i], criteriaValue[i]))
		isEqual[i] = api.Select(api.IsZero(isEqual[i-1]), isEqual[i-1], uapi.IsEqual(selectValue[i], criteriaValue[i]))
	}

	//assert isLess != 0 (because there is a case that a = b ==> isLess = {0, 0, 0, 0, 0, 0, 0, 0} & isEqual = {1, 1, 1, 1, 1, 1, 1, 1} ==> xorValue = {1, 1, 1, 1, 1, 1, 1, 1})
	sum := frontend.Variable(0)
	for i := 0; i < 16; i++ {
		sum = api.Add(sum, isLess[i])
	}
	api.AssertIsDifferent(sum, 0)

	//assert xorValue = xor(isLess, isEqual) = {1, 1, 1, 1, 1, 1, 1, 1}
	xorValue := make([]frontend.Variable, 16)
	for i := 0; i < 16; i++ {
		xorValue[i] = api.Xor(isLess[i], isEqual[i])
	}

	for i := 0; i < 16; i++ {
		api.AssertIsEqual(xorValue[i], 1)
	}
}

// func Satify(comparator_api *cmp.BoundedComparator, uapi *uints.BinaryField[uints.U32], dataKey [16]uints.U32, criteriaKey [16]uints.U32, variable1 *frontend.Variable, variable2 *frontend.Variable) {
// 	for i := 0; i < 16; i++ {
// 		uapi.AssertEq(dataKey[i], criteriaKey[i])
// 	}

// 	comparator_api.AssertIsLessEq(*variable1, *variable2)
// }

func AssertHasOneBit1(api frontend.API, variable frontend.Variable) { //for each n > 0, n & (n - 1) == 0
	comparator_api := cmp.NewBoundedComparator(api, big.NewInt(100000), false)
	comparator_api.AssertIsLess(0, variable) //variable > 0

	subOne := api.Sub(variable, 1)

	bitsVariable := api.ToBinary(variable)
	bitsSubOne := api.ToBinary(subOne)

	bitsZero := make([]frontend.Variable, len(bitsVariable))
	for i := 0; i < len(bitsVariable); i++ {
		bitsZero[i] = api.And(bitsVariable[i], bitsSubOne[i])
	}

	// fmt.Printf("bitsZero: %v\n", bitsZero)
	zero := api.FromBinary(bitsZero[:]...)
	api.AssertIsEqual(zero, 0)
}
