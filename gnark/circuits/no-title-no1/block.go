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
