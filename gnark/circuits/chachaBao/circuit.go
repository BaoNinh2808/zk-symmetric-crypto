package chacha

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const num_of_data = 2

type ChaChaCircuit struct {
	Key           [8]uints.U32
	Counter       uints.U32    `gnark:",public"`
	Nonce         [3]uints.U32 `gnark:",public"`
	Data_Keys     [num_of_data][16]uints.U32
	Enc_Data_Keys [num_of_data][16]uints.U32 `gnark:",public"`
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

	for j := 0; j < num_of_data; j++ {
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

		// check that output matches ciphertext
		for i := 0; i < 16; i++ {
			uapi.AssertEq(c.Enc_Data_Keys[j][i], ciphertext[i])
		}

		// increment counter for next block
		counter = uapi.Add(counter, one)
	}
	return nil
}
