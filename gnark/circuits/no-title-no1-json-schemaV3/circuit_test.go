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

	for i := 52; i < n; i++ {
		blocki := NewEmptyValBlock()
		blocki.Ref_index = uints.U8{Val: uint8(i)}
		data[i] = *blocki
	}

	for i := 0; i < n; i++ {
		index := uints.NewU8(uint8(i))
		data[i].Self_index = index
	}

	//////////////CRITERIAS////////////////

	/* crit0 */
	witness.Data = data
	crit0 := NewCriteria()
	crit0.Refs = []int{}
	crit0.IsRefsCheck = []bool{}
	crit0.RefsCheckObj = []Block{}

	crit0.RefObj = *block0
	crit0.RefObj.Len = uints.NewU8(0)           // set to 0 like real data
	crit0.RefObj.Self_index = uints.NewU8(0xff) // set to 0xff like real data
	crit0.RefObj.Ref_index = uints.NewU8(0xff)  // set to 0xff like real data

	crit0.CritKey = *block0
	crit0.CritKey.Len = uints.NewU8(0)           // set to 0 like real data
	crit0.CritKey.Self_index = uints.NewU8(0xff) // set to 0xff like real data
	crit0.CritKey.Ref_index = uints.NewU8(0xff)  // set to 0xff like real data

	crit0.CritVal = *NewBlock() // dummy

	/*crit1*/
	crit1 := NewCriteria()
	crit1.Refs = []int{REF_TO_KEY}
	crit1.IsRefsCheck = []bool{false}
	crit1.RefsCheckObj = []Block{*NewBlock()}

	crit1.RefObj = *block0
	crit1.RefObj.Len = uints.NewU8(0)           // set to 0 like real data
	crit1.RefObj.Self_index = uints.NewU8(0xff) // set to 0xff like real data
	crit1.RefObj.Ref_index = uints.NewU8(0xff)  // set to 0xff like real data

	crit1.CritKey = *fruitKeyBlock
	crit1.CritKey.Len = uints.NewU8(0)           // set to 0 like real data
	crit1.CritKey.Self_index = uints.NewU8(0xff) // set to 0xff like real data
	crit1.CritKey.Ref_index = uints.NewU8(0xff)  // set to 0xff like real data

	crit1.CritVal = *NewBlock() // dummy

	/*crit2*/
	crit2 := NewCriteria()
	crit2.Refs = []int{REF_TO_VAL, REF_TO_KEY}
	crit2.IsRefsCheck = []bool{true, false}
	crit2.RefsCheckObj = []Block{*fruitValBlock, *NewBlock()}

	crit2.RefObj = *block0
	crit2.RefObj.Len = uints.NewU8(0)           // set to 0 like real data
	crit2.RefObj.Self_index = uints.NewU8(0xff) // set to 0xff like real data
	crit2.RefObj.Ref_index = uints.NewU8(0xff)  // set to 0xff like real data

	crit2.CritKey = *NewBlock() //dummy

	crit2.CritVal = *NewBlock() // set data_type = STRING_VAL_TYPE
	crit2.CritVal.Data_type = uints.NewU8(STRING_VAL_TYPE)

	/*crit3*/
	crit3 := NewCriteria()
	crit3.Refs = []int{REF_TO_KEY}
	crit3.IsRefsCheck = []bool{false}
	crit3.RefsCheckObj = []Block{*NewBlock()}

	crit3.RefObj = *block0
	crit3.RefObj.Len = uints.NewU8(0)           // set to 0 like real data
	crit3.RefObj.Self_index = uints.NewU8(0xff) // set to 0xff like real data
	crit3.RefObj.Ref_index = uints.NewU8(0xff)  // set to 0xff like real data

	crit3.CritKey = *vegetableKeyBlock
	crit3.CritKey.Len = uints.NewU8(0)           // set to 0 like real data
	crit3.CritKey.Self_index = uints.NewU8(0xff) // set to 0xff like real data
	crit3.CritKey.Ref_index = uints.NewU8(0xff)  // set to 0xff like real data

	crit3.CritVal = *NewBlock() // dummy

	/*crit4*/
	crit4 := NewCriteria()
	crit4.Refs = []int{REF_TO_VAL, REF_TO_KEY}
	crit4.IsRefsCheck = []bool{true, false}
	crit4.RefsCheckObj = []Block{*vegetableValBlock, *NewBlock()}

	crit4.RefObj = *block0
	crit4.RefObj.Len = uints.NewU8(0)           // set to 0 like real data
	crit4.RefObj.Self_index = uints.NewU8(0xff) // set to 0xff like real data
	crit4.RefObj.Ref_index = uints.NewU8(0xff)  // set to 0xff like real data

	crit4.CritKey = *NewBlock() // dummy

	crit4.CritVal = *NewBlock() // set data_type = STRING_VAL_TYPE
	crit4.CritVal.Data_type = uints.NewU8(OBJECT_VAL_TYPE)

	/*crit5*/
	crit5 := NewCriteria()
	crit5.Refs = []int{REF_TO_ARRAY_PART, REF_TO_VAL, REF_TO_KEY}
	crit5.IsRefsCheck = []bool{false, true, false}
	crit5.RefsCheckObj = []Block{*NewBlock(), *vegetableValBlock, *NewBlock()}

	crit5.RefObj = *block0
	crit5.RefObj.Len = uints.NewU8(0)           // set to 0 like real data
	crit5.RefObj.Self_index = uints.NewU8(0xff) // set to 0xff like real data
	crit5.RefObj.Ref_index = uints.NewU8(0xff)  // set to 0xff like real data

	crit5.CritKey = *block6
	crit5.CritKey.Len = uints.NewU8(0)           // set to 0 like real data
	crit5.CritKey.Self_index = uints.NewU8(0xff) // set to 0xff like real data
	crit5.CritKey.Ref_index = uints.NewU8(0xff)  // set to 0xff like real data

	crit5.CritVal = *NewBlock() // dummy

	/*crit6*/
	crit6 := NewCriteria()
	crit6.Refs = []int{REF_TO_ARRAY_PART, REF_TO_VAL, REF_TO_KEY}
	crit6.IsRefsCheck = []bool{false, true, false}
	crit6.RefsCheckObj = []Block{*NewBlock(), *vegetableValBlock, *NewBlock()}

	crit6.RefObj = *block0
	crit6.RefObj.Len = uints.NewU8(0)           // set to 0 like real data
	crit6.RefObj.Self_index = uints.NewU8(0xff) // set to 0xff like real data
	crit6.RefObj.Ref_index = uints.NewU8(0xff)  // set to 0xff like real data

	crit6.CritKey = *block8
	crit6.CritKey.Len = uints.NewU8(0)           // set to 0 like real data
	crit6.CritKey.Self_index = uints.NewU8(0xff) // set to 0xff like real data
	crit6.CritKey.Ref_index = uints.NewU8(0xff)  // set to 0xff like real data

	crit6.CritVal = *NewBlock() // dummy

	/*crit7*/
	crit7 := NewCriteria()
	crit7.Refs = []int{REF_TO_ARRAY_PART, REF_TO_VAL, REF_TO_KEY}
	crit7.IsRefsCheck = []bool{false, true, false}
	crit7.RefsCheckObj = []Block{*NewBlock(), *vegetableValBlock, *NewBlock()}

	crit7.RefObj = *block0
	crit7.RefObj.Len = uints.NewU8(0)           // set to 0 like real data
	crit7.RefObj.Self_index = uints.NewU8(0xff) // set to 0xff like real data
	crit7.RefObj.Ref_index = uints.NewU8(0xff)  // set to 0xff like real data

	crit7.CritKey = *block6
	crit7.CritKey.Len = uints.NewU8(0)           // set to 0 like real data
	crit7.CritKey.Self_index = uints.NewU8(0xff) // set to 0xff like real data
	crit7.CritKey.Ref_index = uints.NewU8(0xff)  // set to 0xff like real data

	crit7.CritVal = *NewBlock() // dummy

	/*crit8*/
	crit8 := NewCriteria()
	crit8.Refs = []int{REF_TO_ARRAY_PART, REF_TO_VAL, REF_TO_KEY}
	crit8.IsRefsCheck = []bool{false, true, false}
	crit8.RefsCheckObj = []Block{*NewBlock(), *vegetableValBlock, *NewBlock()}

	crit8.RefObj = *block0
	crit8.RefObj.Len = uints.NewU8(0)           // set to 0 like real data
	crit8.RefObj.Self_index = uints.NewU8(0xff) // set to 0xff like real data
	crit8.RefObj.Ref_index = uints.NewU8(0xff)  // set to 0xff like real data

	crit8.CritKey = *block8
	crit8.CritKey.Len = uints.NewU8(0)           // set to 0 like real data
	crit8.CritKey.Self_index = uints.NewU8(0xff) // set to 0xff like real data
	crit8.CritKey.Ref_index = uints.NewU8(0xff)  // set to 0xff like real data

	crit8.CritVal = *NewBlock() // dummy

	witness.Crits[0] = *crit0
	witness.Crits[1] = *crit1
	witness.Crits[2] = *crit2
	witness.Crits[3] = *crit3
	witness.Crits[4] = *crit4
	witness.Crits[5] = *crit5
	witness.Crits[6] = *crit6
	witness.Crits[7] = *crit7
	witness.Crits[8] = *crit8

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
	myCircuit.Crits[0] = *crit0
	myCircuit.Crits[1] = *crit1
	myCircuit.Crits[2] = *crit2
	myCircuit.Crits[3] = *crit3
	myCircuit.Crits[4] = *crit4
	myCircuit.Crits[5] = *crit5
	myCircuit.Crits[6] = *crit6
	myCircuit.Crits[7] = *crit7
	myCircuit.Crits[8] = *crit8

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

	witness.Crits[0].RefsCheckObj = []Block{}
	witness.Crits[1].RefsCheckObj = []Block{*NewBlock()}
	witness.Crits[2].RefsCheckObj = []Block{*fruitValBlock, *NewBlock()}
	witness.Crits[3].RefsCheckObj = []Block{*NewBlock()}
	witness.Crits[4].RefsCheckObj = []Block{*vegetableValBlock, *NewBlock()}
	witness.Crits[5].RefsCheckObj = []Block{*NewBlock(), *vegetableValBlock, *NewBlock()}
	witness.Crits[6].RefsCheckObj = []Block{*NewBlock(), *vegetableValBlock, *NewBlock()}
	witness.Crits[7].RefsCheckObj = []Block{*NewBlock(), *vegetableValBlock, *NewBlock()}
	witness.Crits[8].RefsCheckObj = []Block{*NewBlock(), *vegetableValBlock, *NewBlock()}

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
