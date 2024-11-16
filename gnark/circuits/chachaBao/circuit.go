package chacha

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

const num_of_data_pieces = 2
const num_of_criterias = 1

type ChaChaCircuit struct {
	Key           [8]uints.U32
	Counter       uints.U32    `gnark:",public"`
	Nonce         [3]uints.U32 `gnark:",public"`
	Data_Keys     [num_of_data_pieces][16]uints.U32
	Enc_Data_Keys [num_of_data_pieces][16]uints.U32 `gnark:",public"`
	Data_Values   [num_of_data_pieces]frontend.Variable

	Criterias_Keys [num_of_criterias][16]uints.U32 `gnark:",public"`
	// omit operator is <=
	Criterias_Values        [num_of_criterias]frontend.Variable `gnark:",public"`
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

	for i := 0; i < num_of_criterias; i++ {
		comparator_api := cmp.NewBoundedComparator(api, big.NewInt(30), false)

		// index := c.Corrsponding_Data_Index[i]

		// // Check : 0 <= Corrsponding_Data_Index[i] < num_of_data_pieces
		// comparator_api.AssertIsLess(index, num_of_data_pieces)
		// comparator_api.AssertIsLessEq(0, index)

		// // fmt.Printf("c: %v\n", index)
		// // Check satisfy the condition
		// Satify(comparator_api, uapi, &c.Data_Keys[index], &c.Criterias_Keys[i], &c.Data_Values[index], &c.Criterias_Values[i])

		bits := api.ToBinary(c.Corrsponding_Data_Index[i], num_of_data_pieces)
		fmt.Printf("bits: %v\n", bits)

		var selectValue frontend.Variable
		var selectKey [16]uints.U32
		selectValue = c.Data_Values[0]
		selectKey = c.Data_Keys[0]
		for j := 1; j < num_of_data_pieces; j++ {
			selectValue = api.Select(bits[j], c.Data_Values[j], selectValue)
			for k := 0; k < 16; k++ {
				for l := 0; l < 4; l++ {
					selectKey[k][l].Val = api.Select(bits[j], c.Data_Keys[j][k][l].Val, selectKey[k][l].Val)
				}
			}
		}

		fmt.Printf("selectValue: %v\n", selectValue)

		// Check satisfy the condition
		Satify(comparator_api, uapi, selectKey, c.Criterias_Keys[i], &selectValue, &c.Criterias_Values[i])
	}

	return nil
}

func Satify(comparator_api *cmp.BoundedComparator, uapi *uints.BinaryField[uints.U32], dataKey [16]uints.U32, criteriaKey [16]uints.U32, variable1 *frontend.Variable, variable2 *frontend.Variable) {
	for i := 0; i < 16; i++ {
		uapi.AssertEq(dataKey[i], criteriaKey[i])
	}

	comparator_api.AssertIsLessEq(*variable1, *variable2)
}

// func Satify(comparator_api *cmp.BoundedComparator, uapi *uints.BinaryField[uints.U32], variable1 *frontend.Variable, variable2 *frontend.Variable) {
// 	comparator_api.AssertIsLessEq(*variable1, *variable2)
// }
