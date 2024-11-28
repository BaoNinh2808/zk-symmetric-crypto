package no_titlle_no1

import (
	"github.com/BaoNinh2808/gnark/std/math/uints"
	"github.com/consensys/gnark/frontend"
)

type Index struct {
	Row uints.U8
	Col uints.U8
}

// constructor of Index
func NewIndex(api frontend.API, Row, Col uint8) Index {
	r := uints.NewU8(Row)
	c := uints.NewU8(Col)
	AssertHasOneBit1(api, r)
	AssertHasOneBit1(api, c)
	return Index{
		Row: r,
		Col: c,
	}
}

func Compare(bf *uints.BinaryField[uints.U32], api *frontend.API, a, b Index) frontend.Variable {
	// 1 if a > b
	// 0 if a = b
	// -1 if a < b

	isEqualRow := bf.IsEqualU8(a.Row, b.Row)
	isEqualCol := bf.IsEqualU8(a.Col, b.Col)
	isLessRow := bf.IsLessU8(a.Row, b.Row)
	isLessCol := bf.IsLessU8(a.Col, b.Col)

	isEqual := (*api).And(isEqualRow, isEqualCol)
	isLess := (*api).Select(isEqualRow, (*api).Select(isLessCol, 1, 0), isLessRow)

	return (*api).Select(isEqual, 0, (*api).Select(isLess, -1, 1))
}

func IsEqualIndex(bf *uints.BinaryField[uints.U32], api *frontend.API, a, b Index) frontend.Variable {
	return (*api).And(bf.IsEqualU8(a.Row, b.Row), bf.IsEqualU8(a.Col, b.Col))
}
