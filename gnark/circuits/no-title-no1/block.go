package no_titlle_no1

import (
	"github.com/BaoNinh2808/gnark/std/math/uints"
	"github.com/consensys/gnark/frontend"
)

type Block struct {
	Data      [15]uints.U32
	Len       uints.U8
	Data_type uints.U8
	Ref_index Index
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
