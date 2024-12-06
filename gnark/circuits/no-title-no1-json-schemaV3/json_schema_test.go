package no_titlle_no1

import (
	"fmt"
	"testing"
	"time"

	"github.com/BaoNinh2808/gnark/std/math/uints"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type DereferencesCircuit struct {
	Data  [64]Block
	Crits [3]Criteria `gnark:",public"`
}

func (c *DereferencesCircuit) Define(api frontend.API) error {
	bapi := NewBlockAPI(api)

	js := NewJsonSchema(c.Data, bapi)

	refBlock := js.Dereferences(&js.data[0], c.Crits[0].Refs, c.Crits[0].IsRefsCheck, c.Crits[0].RefsCheckObj)
	isRef := js.bapi.IsEqual(refBlock, &c.Crits[0].RefObj)
	api.AssertIsEqual(isRef, 1)

	refBlock1 := js.Dereferences(&js.data[1], c.Crits[1].Refs, c.Crits[1].IsRefsCheck, c.Crits[1].RefsCheckObj)
	isRef1 := js.bapi.IsEqual(refBlock1, &c.Crits[1].RefObj)
	api.AssertIsEqual(isRef1, 1)

	refBlock2 := js.Dereferences(&js.data[2], c.Crits[2].Refs, c.Crits[2].IsRefsCheck, c.Crits[2].RefsCheckObj)
	isRef2 := js.bapi.IsEqual(refBlock2, &c.Crits[1].RefObj)
	api.AssertIsEqual(isRef2, 1)

	// refBlock3 := js.Dereferences(&js.data[2], c.Crits[2].Refs, c.Crits[2].IsRefsCheck, c.Crits[2].RefsCheckObj)
	// isRef3 := js.bapi.IsEqual(refBlock3, &c.Crits[1].RefObj)
	// api.AssertIsEqual(isRef3, 1)

	return nil
}

func BTestDereferences(t *testing.T) {
	assert := test.NewAssert(t)

	//create witness
	witness := DereferencesCircuit{}
	data := [64]Block{}

	block0 := NewObjectKeyBlock()
	block1 := NewObjectValBlock()
	fruitKeyBlock := NewArrayKeyBlock()
	fruitValBlock := NewArrayValBlock()
	vegetableKeyBlock := NewArrayKeyBlock()
	vegetableValBlock := NewArrayValBlock()
	block6 := NewStringKeyBlock()
	block7 := NewStringValBlock()
	block8 := NewBoolKeyBlock()
	block9 := NewBoolValBlock()
	block10 := NewStringKeyBlock()
	block11 := NewStringValBlock()
	block12 := NewBoolKeyBlock()
	block13 := NewBoolValBlock()
	block48 := NewStringValBlock()
	block49 := NewStringValBlock()
	block50 := NewObjectValBlock()
	block51 := NewObjectValBlock()

	block0.Ref_index = uints.U8{Val: 0}
	block1.Ref_index = uints.U8{Val: 0}
	fruitKeyBlock.Ref_index = uints.U8{Val: 0}
	fruitValBlock.Ref_index = uints.U8{Val: 0}
	vegetableKeyBlock.Ref_index = uints.U8{Val: 0}
	vegetableValBlock.Ref_index = uints.U8{Val: 0}
	block6.Ref_index = uints.U8{Val: 50}
	block7.Ref_index = uints.U8{Val: 50}
	block8.Ref_index = uints.U8{Val: 50}
	block9.Ref_index = uints.U8{Val: 50}
	block10.Ref_index = uints.U8{Val: 51}
	block11.Ref_index = uints.U8{Val: 51}
	block12.Ref_index = uints.U8{Val: 51}
	block13.Ref_index = uints.U8{Val: 51}
	block48.Ref_index = uints.U8{Val: 3}
	block49.Ref_index = uints.U8{Val: 3}
	block50.Ref_index = uints.U8{Val: 5}
	block51.Ref_index = uints.U8{Val: 5}

	block0.Len = uints.U8{Val: 2}
	fruitValBlock.Len = uints.U8{Val: 2}
	vegetableValBlock.Len = uints.U8{Val: 2}
	block50.Len = uints.U8{Val: 2}
	block51.Len = uints.U8{Val: 2}

	// "root" = 0x726f6f74
	root_key := uint32(0x726f6f74)
	block0.Data[0] = uints.NewU32(root_key)
	block1.Data[0] = uints.NewU32(root_key)

	//"fruit" = 0x6672756974 --> 0x66727569, 0x74000000
	fruit_key_1 := uint32(0x66727569)
	fruit_key_2 := uint32(0x74000000)
	fruitKeyBlock.Data[0] = uints.NewU32(fruit_key_1)
	fruitKeyBlock.Data[1] = uints.NewU32(fruit_key_2)
	fruitValBlock.Data[0] = uints.NewU32(fruit_key_1)
	fruitValBlock.Data[1] = uints.NewU32(fruit_key_2)

	//"vegetable" = 0x766567657461626c65 --> 0x76656765, 0x7461626c, 0x65000000
	vegetable_key_1 := uint32(0x76656765)
	vegetable_key_2 := uint32(0x7461626c)
	vegetable_key_3 := uint32(0x65000000)
	vegetableKeyBlock.Data[0] = uints.NewU32(vegetable_key_1)
	vegetableKeyBlock.Data[1] = uints.NewU32(vegetable_key_2)
	vegetableKeyBlock.Data[2] = uints.NewU32(vegetable_key_3)
	vegetableValBlock.Data[0] = uints.NewU32(vegetable_key_1)
	vegetableValBlock.Data[1] = uints.NewU32(vegetable_key_2)
	vegetableValBlock.Data[2] = uints.NewU32(vegetable_key_3)

	// "apple" = 0x6170706c65 --> 0x6170706c, 0x65000000
	apple_key_1 := uint32(0x6170706c)
	apple_key_2 := uint32(0x65000000)
	block48.Data[0] = uints.NewU32(apple_key_1)
	block48.Data[1] = uints.NewU32(apple_key_2)

	// "banana" = 0x62616e616e61 --> 0x62616e61, 0x6e610000
	banana_key_1 := uint32(0x62616e61)
	banana_key_2 := uint32(0x6e610000)
	block49.Data[0] = uints.NewU32(banana_key_1)
	block49.Data[1] = uints.NewU32(banana_key_2)

	// "veggieName" = 0x7665676769654e616d65 --> 0x76656767, 0x69654e61, 0x6d650000
	veggieName_key_1 := uint32(0x76656767)
	veggieName_key_2 := uint32(0x69654e61)
	veggieName_key_3 := uint32(0x6d650000)
	block6.Data[0] = uints.NewU32(veggieName_key_1)
	block6.Data[1] = uints.NewU32(veggieName_key_2)
	block6.Data[2] = uints.NewU32(veggieName_key_3)
	block10.Data[0] = uints.NewU32(veggieName_key_1)
	block10.Data[1] = uints.NewU32(veggieName_key_2)
	block10.Data[2] = uints.NewU32(veggieName_key_3)

	// "veggieLike" = 0x7665676769654c696b65 --> 0x76656767, 0x69654c69, 0x6b650000
	veggieLike_key_1 := uint32(0x76656767)
	veggieLike_key_2 := uint32(0x69654c69)
	veggieLike_key_3 := uint32(0x6b650000)
	block8.Data[0] = uints.NewU32(veggieLike_key_1)
	block8.Data[1] = uints.NewU32(veggieLike_key_2)
	block8.Data[2] = uints.NewU32(veggieLike_key_3)
	block12.Data[0] = uints.NewU32(veggieLike_key_1)
	block12.Data[1] = uints.NewU32(veggieLike_key_2)
	block12.Data[2] = uints.NewU32(veggieLike_key_3)

	// "broccoli" = 0x62726f63636f6c69 --> 0x62726f63, 0x636f6c69
	broccoli_key_1 := uint32(0x62726f63)
	broccoli_key_2 := uint32(0x636f6c69)
	block7.Data[0] = uints.NewU32(broccoli_key_1)
	block7.Data[1] = uints.NewU32(broccoli_key_2)

	// "potato" = 0x706f7461746f --> 0x706f7461, 0x746f0000
	potato_key_1 := uint32(0x706f7461)
	potato_key_2 := uint32(0x746f0000)
	block11.Data[0] = uints.NewU32(potato_key_1)
	block11.Data[1] = uints.NewU32(potato_key_2)

	// true = 1
	block9.Data[0] = uints.NewU32(1)
	// false = 0
	block13.Data[0] = uints.NewU32(0)

	data[0] = *block0
	data[1] = *block1
	data[2] = *fruitKeyBlock
	data[3] = *fruitValBlock
	data[4] = *vegetableKeyBlock
	data[5] = *vegetableValBlock
	data[6] = *block6
	data[7] = *block7
	data[8] = *block8
	data[9] = *block9
	data[10] = *block10
	data[11] = *block11
	data[12] = *block12
	data[13] = *block13
	data[48] = *block48
	data[49] = *block49
	data[50] = *block50
	data[51] = *block51

	for i := 14; i < split; i += 2 {
		blocki := NewEmptyKeyBlock()
		blocki.Ref_index = uints.U8{Val: uint8(i)}
		data[i] = *blocki
	}

	for i := 15; i < split; i += 2 {
		blocki := NewEmptyValBlock()
		blocki.Ref_index = uints.U8{Val: uint8(i - 1)} // to make it equal to the key
		data[i] = *blocki
	}

	for i := 52; i < 64; i++ {
		blocki := NewEmptyValBlock()
		blocki.Ref_index = uints.U8{Val: uint8(i)}
		data[i] = *blocki
	}

	for i := 0; i < 64; i++ {
		index := uints.NewU8(uint8(i))
		data[i].Self_index = index
	}

	// witness.Data = data

	//////////////CRITERIAS////////////////

	/* crit0 */
	crit0 := NewCriteria()
	crit0.Refs = []int{REF_TO_ARRAY_PART}
	crit0.IsRefsCheck = []bool{true}
	crit0.RefsCheckObj = []Block{*NewBlock()}

	crit0.RefObj = *block0
	crit0.RefObj.Len = uints.NewU8(0)           // set to 0 like real data
	crit0.RefObj.Self_index = uints.NewU8(0xff) // set to 0xff like real data
	crit0.RefObj.Ref_index = uints.NewU8(0xff)  // set to 0xff like real data

	crit0.CritKey = *block0
	crit0.CritKey.Len = uints.NewU8(0)           // set to 0 like real data
	crit0.CritKey.Self_index = uints.NewU8(0xff) // set to 0xff like real data
	crit0.CritKey.Ref_index = uints.NewU8(0xff)  // set to 0xff like real data

	crit0.CritVal = *NewBlock() // dummy

	witness.Crits[0] = *crit0
	witness.Crits[1] = *crit0

	/////////////////////////////////////////////
	var myCircuit DereferencesCircuit
	myCircuit.Crits[0] = *crit0
	myCircuit.Crits[1] = *crit0
	myCircuit.Crits[2] = *crit0

	startCompile := time.Now()
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	assert.NoError(err)
	fmt.Println("Number of constraints: ", r1cs.GetNbConstraints())
	elasedCompile := time.Since(startCompile)
	fmt.Printf("Compile Time: %v\n", elasedCompile)
}
