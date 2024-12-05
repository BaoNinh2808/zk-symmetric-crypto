package no_titlle_no1

import (
	"math/big"

	"github.com/BaoNinh2808/gnark/std/math/uints"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

func IsHasOneBit1(api frontend.API, valU8 uints.U8) frontend.Variable {

	variable := valU8.Val
	//for each n > 0, n & (n - 1) == 0
	comparator_api := cmp.NewBoundedComparator(api, big.NewInt(0xff), false)
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
	return api.IsZero(zero)
}

func IsHasOneBit0(api frontend.API, valU8 uints.U8) frontend.Variable {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}
	// if not(n) has only one bit 1, then n has only one bit 0
	not_variable := uapi.NotU8(valU8)

	return IsHasOneBit1(api, not_variable)
}

func AssertHasOneBit1(api frontend.API, variable uints.U8) {
	api.AssertIsEqual(IsHasOneBit1(api, variable), 1)
}

func AssertHasOneBit0(api frontend.API, valU8 uints.U8) {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}
	// if not(n) has only one bit 1, then n has only one bit 0
	not_variable := uapi.NotU8(valU8)
	AssertHasOneBit1(api, not_variable)
}
