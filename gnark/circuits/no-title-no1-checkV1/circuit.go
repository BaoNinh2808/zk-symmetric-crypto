package no_titlle_no1

import (
	"github.com/BaoNinh2808/gnark/std/math/uints"
	"github.com/consensys/gnark/frontend"
)

// NULL
var NULL_KEY_TYPE = uints.NewU8(0x01) //0x 0000 0001
var NULL_VAL_TYPE = uints.NewU8(0xfe) //0x 1111 1110

// BOOLEAN
var BOOL_KEY_TYPE = uints.NewU8(0x02) //0x 0000 0010
var BOOL_VAL_TYPE = uints.NewU8(0xfd) //0x 1111 1101

// STRING
var STRING_KEY_TYPE = uints.NewU8(0x04) //0x 0000 0100
var STRING_VAL_TYPE = uints.NewU8(0xfb) //0x 1111 1011

// NUMBER
var NUMBER_KEY_TYPE = uints.NewU8(0x08) //0x 0000 1000
var NUMBER_VAL_TYPE = uints.NewU8(0xf7) //0x 1111 0111

// ARRAY
var ARRAY_KEY_TYPE = uints.NewU8(0x10) //0x 0001 0000
var ARRAY_VAL_TYPE = uints.NewU8(0xef) //0x 1110 1111

// OBJECT
var OBJECT_KEY_TYPE = uints.NewU8(0x20) //0x 0010 0000
var OBJECT_VAL_TYPE = uints.NewU8(0xdf) //0x 1101 1111

// EMPTY
var EMPTY_KEY_TYPE = uints.NewU8(0x40) //0x 0100 0000
var EMPTY_VAL_TYPE = uints.NewU8(0xbf) //0x 1011 1111

// ARRAY_POINTER_VAL_TYPE
var ARRAY_POINTER_VAL_TYPE = uints.NewU8(0xee) //0x 1110 1110

const n = 64
const split = 48

type MyCircuit struct {
	Data [n]Block

	//criteria for the circuit
	Criterias_Keys [1]Block `gnark:",public"`
	Criterias_Vals [1]Block `gnark:",public"`
	// omit operator is <=

	//index of data that correspond to the criteria
	Corresponding_Data_Index [1]Index
}

func (c *MyCircuit) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	// check valid KeyType
	for i := 0; i < split; i += 2 {
		AssertHasOneBit1(api, c.Data[i].Data_type)
		uapi.ByteAssertIsLess(c.Data[i].Data_type, uints.NewU8(0x80)) //0x 1000 0000
	}

	// check valid ValType
	for i := 1; i < split; i += 2 {
		AssertHasOneBit0(api, c.Data[i].Data_type)
		uapi.ByteAssertIsLess(uints.NewU8(0x7f), c.Data[i].Data_type) //0x 0111 1111
	}

	// check consistency between KeyType and ValType
	for i := 0; i < split; i += 2 {
		//KeyType + DataType = 0xff
		total := uapi.AddU8(c.Data[i].Data_type, c.Data[i+1].Data_type)
		uapi.ByteAssertEq(total, uints.NewU8(0xff)) //0x 1111 1111
	}

	// check valid val type in array part
	for i := split; i < n; i++ {
		isHasOneBit0 := IsHasOneBit0(api, c.Data[i].Data_type)
		uapi.ByteAssertIsLess(uints.NewU8(0x7f), c.Data[i].Data_type)         //0x 0111 1111
		is0xee := uapi.IsEqualU8(c.Data[i].Data_type, ARRAY_POINTER_VAL_TYPE) //0x 1110 1110
		isPass := api.Xor(isHasOneBit0, is0xee)
		api.AssertIsEqual(isPass, 1)
	}

	// check continous elements in array part
	for i := split; i < n-1; i++ {
		compare := Compare(uapi, &api, c.Data[i].Ref_index, c.Data[i+1].Ref_index)
		api.AssertIsDifferent(compare, 1) //only 0 or -1 (equal or less)
	}

	// check correct Lenght of obj key
	for i := 0; i < split; i = i + 2 {
		row, col := PositionToRowCol(i)
		index := NewIndex(api, row, col)
		total_Refs := frontend.Variable(0)
		for j := i + 2; j < split; j = j + 2 {
			isRef := IsEqualIndex(uapi, &api, &index, &c.Data[j].Ref_index)
			// fmt.Println("j : ", j, "isRef :", isRef)
			total_Refs = api.Add(total_Refs, isRef)
		}
		api.AssertIsEqual(total_Refs, c.Data[i].Len.Val)
	}

	// check correct Lenght of array val
	for i := 1; i < split; i += 2 {
		row, col := PositionToRowCol(i)
		index := NewIndex(api, row, col)
		total_Refs := frontend.Variable(0)
		for j := split; j < n; j++ {
			isRef := IsEqualIndex(uapi, &api, &index, &c.Data[j].Ref_index)
			total_Refs = api.Add(total_Refs, isRef)
		}
		api.AssertIsEqual(total_Refs, c.Data[i].Len.Val)
	}

	// check criteria
	for i := 0; i < 1; i++ {
		index := c.Corresponding_Data_Index[i]
		AssertHasOneBit1(api, index.Row)
		AssertHasOneBit1(api, index.Col)

		// choose the key & data
		key := c.Data[0]
		val := c.Data[1]

		for j := 0; j < split; j += 2 {
			row, col := PositionToRowCol(j)
			j_index := NewIndex(api, row, col)
			isChosenKey := IsEqualIndex(uapi, &api, &index, &j_index)
			key = *SelectBlock(api, &c.Data[j], &key, isChosenKey)
			val = *SelectBlock(api, &c.Data[j+1], &val, isChosenKey)
		}

		// check key equal
		AssertEqualBlock(uapi, &key, &c.Criterias_Keys[i])
		// check val less
		AssertIsLessBlock(uapi, api, &val, &c.Criterias_Vals[i])
	}
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
