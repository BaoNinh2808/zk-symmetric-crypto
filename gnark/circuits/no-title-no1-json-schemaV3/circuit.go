package no_titlle_no1

import (
	"github.com/BaoNinh2808/gnark/std/math/uints"
	"github.com/consensys/gnark/frontend"
)

// NULL
const NULL_KEY_TYPE uint8 = 0x01 //0x 0000 0001
const NULL_VAL_TYPE uint8 = 0xfe //0x 1111 1110

// BOOLEAN
const BOOL_KEY_TYPE uint8 = 0x02 //0x 0000 0010
const BOOL_VAL_TYPE uint8 = 0xfd //0x 1111 1101

// STRING
const STRING_KEY_TYPE uint8 = 0x04 //0x 0000 0100
const STRING_VAL_TYPE uint8 = 0xfb //0x 1111 1011

// NUMBER
const NUMBER_KEY_TYPE uint8 = 0x08 //0x 0000 1000
const NUMBER_VAL_TYPE uint8 = 0xf7 //0x 1111 0111

// ARRAY
const ARRAY_KEY_TYPE uint8 = 0x10 //0x 0001 0000
const ARRAY_VAL_TYPE uint8 = 0xef //0x 1110 1111

// OBJECT
const OBJECT_KEY_TYPE uint8 = 0x20 //0x 0010 0000
const OBJECT_VAL_TYPE uint8 = 0xdf //0x 1101 1111

// EMPTY
const EMPTY_KEY_TYPE uint8 = 0x40 //0x 0100 0000
const EMPTY_VAL_TYPE uint8 = 0xbf //0x 1011 1111

// ARRAY_POINTER_VAL_TYPE
const ARRAY_POINTER_VAL_TYPE uint8 = 0xee //0x 1110 1110

const n = 64
const split = 48

type MyCircuit struct {
	//encryption
	Key     [8]uints.U32
	Counter uints.U32    `gnark:",public"`
	Nonce   [3]uints.U32 `gnark:",public"`

	Data     [n]Block
	Enc_Data [n][16]uints.U32 `gnark:",public"`

	//criteria
	Crits [1]Criteria `gnark:",public"`
}

func (c *MyCircuit) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	bapi := NewBlockAPI(api)

	js := NewJsonSchema(c.Data, bapi)

	// fmt.Println("Define", js.data[0].Data_type)

	// check valid KeyType & self_index correct
	for i := 0; i < split; i += 2 {
		AssertHasOneBit1(api, c.Data[i].Data_type)
		uapi.ByteAssertIsLess(c.Data[i].Data_type, uints.NewU8(0x80)) //0x 1000 0000

		//check self_index
		self_index := uints.NewU8(uint8(i))
		correctSelfIndex := uapi.IsEqualU8(c.Data[i].Self_index, self_index)
		api.AssertIsEqual(correctSelfIndex, 1)
	}

	// check valid ValType & self_index correct
	for i := 1; i < split; i += 2 {
		AssertHasOneBit0(api, c.Data[i].Data_type)
		uapi.ByteAssertIsLess(uints.NewU8(0x7f), c.Data[i].Data_type) //0x 0111 1111

		//check self_index
		self_index := uints.NewU8(uint8(i))
		correctSelfIndex := uapi.IsEqualU8(c.Data[i].Self_index, self_index)
		api.AssertIsEqual(correctSelfIndex, 1)
	}

	// check consistency between KeyType and ValType
	for i := 0; i < split; i += 2 {
		//KeyType + DataType = 0xff
		sum_key_val_type := uapi.AddU8(c.Data[i].Data_type, c.Data[i+1].Data_type)
		uapi.ByteAssertEq(sum_key_val_type, uints.NewU8(0xff)) //0x 1111 1111
	}

	// check valid val type in array part & self_index correct
	for i := split; i < n; i++ {
		isHasOneBit0 := IsHasOneBit0(api, c.Data[i].Data_type)
		uapi.ByteAssertIsLess(uints.NewU8(0x7f), c.Data[i].Data_type)                      //0x 0111 1111
		is0xee := uapi.IsEqualU8(c.Data[i].Data_type, uints.NewU8(ARRAY_POINTER_VAL_TYPE)) //0x 1110 1110
		isPass := api.Xor(isHasOneBit0, is0xee)                                            //is true (1) if one of them is true
		api.AssertIsEqual(isPass, 1)

		//check self_index
		self_index := uints.NewU8(uint8(i))
		correctSelfIndex := uapi.IsEqualU8(c.Data[i].Self_index, self_index)
		api.AssertIsEqual(correctSelfIndex, 1)
	}

	// check continous elements in array part
	for i := split; i < n-1; i++ {
		isLessEq := uapi.IsLessEqualU8(c.Data[i].Ref_index, c.Data[i+1].Ref_index)
		api.AssertIsEqual(isLessEq, 1) //the ref_index must be in increasing order
	}

	// check correct Lenght of obj key (if not object, then len = 0)
	for i := 0; i < split; i = i + 2 {
		key_index := uints.NewU8(uint8(i))
		total_Refs := frontend.Variable(0)
		for j := i + 2; j < split; j = j + 2 { //check the key index in the key-val part
			isRef := uapi.IsEqualU8(c.Data[j].Ref_index, key_index)
			total_Refs = api.Add(total_Refs, isRef)
		}
		api.AssertIsEqual(total_Refs, c.Data[i].Len.Val)
	}

	// check correct Lenght of array val (if not array, then len = 0)
	for i := 1; i < split; i += 2 {
		val_index := uints.NewU8(uint8(i))
		total_Refs := frontend.Variable(0)
		for j := split; j < n; j++ { //check the value in the array part
			isRef := uapi.IsEqualU8(c.Data[j].Ref_index, val_index)
			total_Refs = api.Add(total_Refs, isRef)
		}
		api.AssertIsEqual(total_Refs, c.Data[i].Len.Val)
	}

	// check some criterias
	js.ANONYMOUS_KEYCHECK_Type(&c.Crits[0])
	js.KEYCHECK_Type(&c.Crits[0])

	// js.VALCHECK_Maximum(&c.Crits[1])

	return nil
}

func BitAtPosition(pos uint8) uints.U8 {
	if pos > 7 {
		panic("position out of range")
	}
	return uints.NewU8(1 << pos)
}

func PositionToRowCol(index int) (uint8, uint8) {
	if index < 0 || index > 63 {
		panic("index out of range")
	}
	row := uint8(index / 8)
	col := uint8(index % 8)
	return row, col
}
