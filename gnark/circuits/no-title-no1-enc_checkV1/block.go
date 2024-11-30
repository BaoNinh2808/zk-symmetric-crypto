package no_titlle_no1

import (
	"github.com/BaoNinh2808/gnark/std/math/uints"
	"github.com/consensys/gnark/frontend"
)

type Block struct {
	Data_type uints.U8
	Len       uints.U8
	Ref_index Index
	Data      [15]uints.U32
}

// constructor of Block
func NewBlock() *Block {
	return &Block{
		Data_type: uints.NewU8(0x01),
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: uints.NewU8(0x80), Col: uints.NewU8(0x80)},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

func SelectBlock(api frontend.API, a, b *Block, cond frontend.Variable) *Block {
	return &Block{
		Data_type: uints.U8{Val: api.Select(cond, a.Data_type.Val, b.Data_type.Val)},
		Len:       uints.U8{Val: api.Select(cond, a.Len.Val, b.Len.Val)},
		Ref_index: *SelectIndex(api, a.Ref_index, b.Ref_index, cond),
		Data:      SelectData(api, a.Data, b.Data, cond),
	}
}

func SelectData(api frontend.API, u1, u2 [15]uints.U32, cond frontend.Variable) [15]uints.U32 {
	var res [15]uints.U32
	for i := 0; i < 15; i++ {
		for j := 0; j < 4; j++ {
			res[i][j].Val = api.Select(cond, u1[i][j].Val, u2[i][j].Val)
		}
	}
	return res
}

func SelectIndex(api frontend.API, index1, index2 Index, cond frontend.Variable) *Index {
	return &Index{
		Row: uints.U8{Val: api.Select(cond, index1.Row.Val, index2.Row.Val)},
		Col: uints.U8{Val: api.Select(cond, index1.Col.Val, index2.Col.Val)},
	}
}

func AssertIsLessBlock(bf *uints.BinaryField[uints.U32], api frontend.API, block1 *Block, block2 *Block) {
	bf.ByteAssertEq(block1.Data_type, block2.Data_type)
	lenB := 15
	// create a array of frontend.Variable with lenght lenB
	isLess := make([]frontend.Variable, lenB)
	isEqual := make([]frontend.Variable, lenB)

	isLess[0] = bf.IsLess(block1.Data[0], block2.Data[0])
	isEqual[0] = bf.IsEqual(block1.Data[0], block2.Data[0])

	for i := 1; i < lenB; i++ {
		isLess[i] = api.Select(isLess[i-1], isLess[i-1], bf.IsLess(block1.Data[i], block2.Data[i]))
		isEqual[i] = api.Select(api.IsZero(isEqual[i-1]), 0, bf.IsEqual(block1.Data[i], block2.Data[i]))
	}

	//assert isLess != 0 (because there is a case that a = b ==> isLess = {0, 0, 0, 0, 0, 0, 0, 0} & isEqual = {1, 1, 1, 1, 1, 1, 1, 1} ==> xorValue = {1, 1, 1, 1, 1, 1, 1, 1})
	sum := frontend.Variable(0)
	for i := 0; i < len(isLess); i++ {
		sum = api.Add(sum, isLess[i])
	}
	api.AssertIsDifferent(sum, 0)

	//assert xorValue = xor(isLess, isEqual) = {1, 1, 1, 1, 1, 1, 1, 1}
	xorValue := make([]frontend.Variable, lenB)
	for i := 0; i < lenB; i++ {
		xorValue[i] = api.Xor(isLess[i], isEqual[i])
	}

	for i := 0; i < lenB; i++ {
		api.AssertIsEqual(xorValue[i], 1)
	}
}

func AssertEqualBlock(bf *uints.BinaryField[uints.U32], block1 *Block, block2 *Block) {
	bf.ByteAssertEq(block1.Data_type, block2.Data_type)

	for i := 0; i < 15; i++ {
		bf.AssertEq(block1.Data[i], block2.Data[i])
	}
}

// setter Set Len of Block
func (b *Block) SetLen(v uint8) {
	b.Len = uints.NewU8(v)
}

// setter Set Ref_index of Block
func (b *Block) SetRef_index(v Index) {
	b.Ref_index = v
}

// setter Set Ref_index of Block from index (int)
func (b *Block) SetRef_indexFromIndex(index int) {
	v_row, v_col := PositionToRowCol(index)
	row := BitAtPosition(v_row)
	col := BitAtPosition(v_col)
	b.Ref_index = Index{Row: row, Col: col}
}

// setter Set Data of Block
func (b *Block) SetData(v [15]uint32) {
	for i := 0; i < 15; i++ {
		b.Data[i] = uints.NewU32(v[i])
	}
}

// setter Set Data at index of Block
func (b *Block) SetDataAtIndex(v uint32, index int) {
	if index < 0 || index >= 15 {
		panic("index out of range")
	}
	b.Data[index] = uints.NewU32(v)
}

// constructor of empty key Block
func NewEmptyKeyBlock() *Block {
	return &Block{
		Data_type: EMPTY_KEY_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: uints.NewU8(0x80), Col: uints.NewU8(0x80)},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of empty value Block
func NewEmptyValBlock() *Block {
	return &Block{
		Data_type: EMPTY_VAL_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: uints.NewU8(0x80), Col: uints.NewU8(0x80)},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Null key Block
func NewNullKeyBlock() *Block {
	return &Block{
		Data_type: NULL_KEY_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: uints.NewU8(0x80), Col: uints.NewU8(0x80)},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Null value Block
func NewNullValBlock() *Block {
	return &Block{
		Data_type: NULL_VAL_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: uints.NewU8(0x80), Col: uints.NewU8(0x80)},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Boolean key Block
func NewBoolKeyBlock() *Block {
	return &Block{
		Data_type: BOOL_KEY_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: uints.NewU8(0x80), Col: uints.NewU8(0x80)},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Boolean value Block
func NewBoolValBlock() *Block {
	return &Block{
		Data_type: BOOL_VAL_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: uints.NewU8(0x80), Col: uints.NewU8(0x80)},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of String key Block
func NewStringKeyBlock() *Block {
	return &Block{
		Data_type: STRING_KEY_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: uints.NewU8(0x80), Col: uints.NewU8(0x80)},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of String value Block
func NewStringValBlock() *Block {
	return &Block{
		Data_type: STRING_VAL_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: uints.NewU8(0x80), Col: uints.NewU8(0x80)},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Number key Block
func NewNumberKeyBlock() *Block {
	return &Block{
		Data_type: NUMBER_KEY_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: uints.NewU8(0x80), Col: uints.NewU8(0x80)},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Number value Block
func NewNumberValBlock() *Block {
	return &Block{
		Data_type: NUMBER_VAL_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: uints.NewU8(0x80), Col: uints.NewU8(0x80)},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Array key Block
func NewArrayKeyBlock() *Block {
	return &Block{
		Data_type: ARRAY_KEY_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: uints.NewU8(0x80), Col: uints.NewU8(0x80)},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Array value Block
func NewArrayValBlock() *Block {
	return &Block{
		Data_type: ARRAY_VAL_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: uints.NewU8(0x80), Col: uints.NewU8(0x80)},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Object key Block
func NewObjectKeyBlock() *Block {
	return &Block{
		Data_type: OBJECT_KEY_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: uints.NewU8(0x80), Col: uints.NewU8(0x80)},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Object value Block
func NewObjectValBlock() *Block {
	return &Block{
		Data_type: OBJECT_VAL_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: uints.NewU8(0x80), Col: uints.NewU8(0x80)},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Array pointer value Block
func NewArrayPointerValBlock() *Block {
	return &Block{
		Data_type: ARRAY_POINTER_VAL_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: uints.NewU8(0x80), Col: uints.NewU8(0x80)},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor with Data of Block
func NewBlockWithData(api frontend.API, v_Data_type uint8, v_Len uint8, v_Row uint8, v_Col uint8, v_Data [15]uint32) *Block {
	Data := [15]uints.U32{}
	for i := 0; i < 15; i++ {
		Data[i] = uints.NewU32(v_Data[i])
	}

	return &Block{
		Data_type: uints.NewU8(v_Data_type),
		Len:       uints.NewU8(v_Len),
		Ref_index: NewIndex(api, v_Row, v_Col),
		Data:      Data,
	}
}

// constructor of empty key Block with index (int)
func NewEmptyKeyBlockWithIndex(index int) *Block {
	v_row, v_col := PositionToRowCol(index)
	row := BitAtPosition(v_row)
	col := BitAtPosition(v_col)
	return &Block{
		Data_type: EMPTY_KEY_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: row, Col: col},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of empty value Block with index (int)
func NewEmptyValBlockWithIndex(index int) *Block {
	v_row, v_col := PositionToRowCol(index)
	row := BitAtPosition(v_row)
	col := BitAtPosition(v_col)
	return &Block{
		Data_type: EMPTY_VAL_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: row, Col: col},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Null key Block with index (int)
func NewNullKeyBlockWithIndex(index int) *Block {
	v_row, v_col := PositionToRowCol(index)
	row := BitAtPosition(v_row)
	col := BitAtPosition(v_col)
	return &Block{
		Data_type: NULL_KEY_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: row, Col: col},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Null value Block with index (int)
func NewNullValBlockWithIndex(index int) *Block {
	v_row, v_col := PositionToRowCol(index)
	row := BitAtPosition(v_row)
	col := BitAtPosition(v_col)
	return &Block{
		Data_type: NULL_VAL_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: row, Col: col},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Boolean key Block with index (int)
func NewBoolKeyBlockWithIndex(index int) *Block {
	v_row, v_col := PositionToRowCol(index)
	row := BitAtPosition(v_row)
	col := BitAtPosition(v_col)
	return &Block{
		Data_type: BOOL_KEY_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: row, Col: col},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Boolean value Block with index (int)
func NewBoolValBlockWithIndex(index int) *Block {
	v_row, v_col := PositionToRowCol(index)
	row := BitAtPosition(v_row)
	col := BitAtPosition(v_col)
	return &Block{
		Data_type: BOOL_VAL_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: row, Col: col},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of String key Block with index (int)
func NewStringKeyBlockWithIndex(index int) *Block {
	v_row, v_col := PositionToRowCol(index)
	row := BitAtPosition(v_row)
	col := BitAtPosition(v_col)
	return &Block{
		Data_type: STRING_KEY_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: row, Col: col},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of String value Block with index (int)
func NewStringValBlockWithIndex(index int) *Block {
	v_row, v_col := PositionToRowCol(index)
	row := BitAtPosition(v_row)
	col := BitAtPosition(v_col)
	return &Block{
		Data_type: STRING_VAL_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: row, Col: col},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Number key Block with index (int)
func NewNumberKeyBlockWithIndex(index int) *Block {
	v_row, v_col := PositionToRowCol(index)
	row := BitAtPosition(v_row)
	col := BitAtPosition(v_col)
	return &Block{
		Data_type: NUMBER_KEY_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: row, Col: col},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Number value Block with index (int)
func NewNumberValBlockWithIndex(index int) *Block {
	v_row, v_col := PositionToRowCol(index)
	row := BitAtPosition(v_row)
	col := BitAtPosition(v_col)
	return &Block{
		Data_type: NUMBER_VAL_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: row, Col: col},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Array key Block with index (int)
func NewArrayKeyBlockWithIndex(index int) *Block {
	v_row, v_col := PositionToRowCol(index)
	row := BitAtPosition(v_row)
	col := BitAtPosition(v_col)
	return &Block{
		Data_type: ARRAY_KEY_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: row, Col: col},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Array value Block with index (int)
func NewArrayValBlockWithIndex(index int) *Block {
	v_row, v_col := PositionToRowCol(index)
	row := BitAtPosition(v_row)
	col := BitAtPosition(v_col)
	return &Block{
		Data_type: ARRAY_VAL_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: row, Col: col},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Object key Block with index (int)
func NewObjectKeyBlockWithIndex(index int) *Block {
	v_row, v_col := PositionToRowCol(index)
	row := BitAtPosition(v_row)
	col := BitAtPosition(v_col)
	return &Block{
		Data_type: OBJECT_KEY_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: row, Col: col},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Object value Block with index (int)
func NewObjectValBlockWithIndex(index int) *Block {
	v_row, v_col := PositionToRowCol(index)
	row := BitAtPosition(v_row)
	col := BitAtPosition(v_col)
	return &Block{
		Data_type: OBJECT_VAL_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: row, Col: col},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}

// constructor of Array pointer value Block with index (int)
func NewArrayPointerValBlockWithIndex(index int) *Block {
	v_row, v_col := PositionToRowCol(index)
	row := BitAtPosition(v_row)
	col := BitAtPosition(v_col)
	return &Block{
		Data_type: ARRAY_POINTER_VAL_TYPE,
		Len:       uints.NewU8(0),
		Ref_index: Index{Row: row, Col: col},
		Data:      [15]uints.U32{uints.NewU32(0)},
	}
}
