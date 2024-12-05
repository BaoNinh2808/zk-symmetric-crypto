package no_titlle_no1

import (
	"github.com/BaoNinh2808/gnark/std/math/uints"
	"github.com/consensys/gnark/frontend"
)

type Block struct {
	Data_type  uints.U8
	Len        uints.U8
	Ref_index  uints.U8
	Self_index uints.U8
	Data       [15]uints.U32
}

type BlockAPI struct {
	uapi *uints.BinaryField[uints.U32]
	api  frontend.API
}

func NewBlockAPI(api frontend.API) *BlockAPI {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}
	return &BlockAPI{
		uapi: uapi,
		api:  api,
	}
}

func (bapi *BlockAPI) IsEqual(block1, block2 *Block) frontend.Variable {
	isEqual := bapi.uapi.IsEqualU8(block1.Data_type, block2.Data_type) //check equal type

	//don't concern about len, ref_index, self_index

	//check equal data
	for i := 0; i < 15; i++ {
		isEqualData := bapi.uapi.IsEqual(block1.Data[i], block2.Data[i])
		isEqual = bapi.api.And(isEqual, isEqualData)
	}

	return isEqual
}

func (bapi *BlockAPI) IsLess(block1, block2 *Block) frontend.Variable {
	//check equal type & assert type is number
	isEqualType := bapi.uapi.IsEqualU8(block1.Data_type, block2.Data_type)
	isNumberVal := bapi.uapi.IsEqualU8(block1.Data_type, uints.NewU8(NUMBER_VAL_TYPE))

	//check less value
	isLessArr := make([]frontend.Variable, 15)
	isEqualArr := make([]frontend.Variable, 15)

	isLessArr[0] = bapi.uapi.IsLess(block1.Data[14], block2.Data[14])
	isEqualArr[0] = bapi.uapi.IsEqual(block1.Data[14], block2.Data[14])

	for i := 1; i < 15; i++ {
		isLessArr[i] = bapi.api.Select(isLessArr[i-1], 1, bapi.uapi.IsLess(block1.Data[14-i], block2.Data[14-i]))
		isEqualArr[i] = bapi.api.Select(bapi.api.IsZero(isEqualArr[i-1]), 0, bapi.uapi.IsEqual(block1.Data[14-i], block2.Data[14-i]))
	}

	sumIsLess := frontend.Variable(0)
	for i := 0; i < 15; i++ {
		sumIsLess = bapi.api.Add(sumIsLess, isLessArr[i])
	}
	isSumLessDiffZero := bapi.api.Xor(bapi.api.IsZero(sumIsLess), 1)

	xorLessEqual := make([]frontend.Variable, 15)
	for i := 0; i < 15; i++ {
		xorLessEqual[i] = bapi.api.Xor(isLessArr[i], isEqualArr[i])
	}
	andXorLessEqual := frontend.Variable(1)
	for i := 0; i < 15; i++ {
		andXorLessEqual = bapi.api.And(andXorLessEqual, xorLessEqual[i])
	}

	isPass := bapi.api.And(isSumLessDiffZero, andXorLessEqual)
	isPass = bapi.api.And(isPass, isEqualType)
	isPass = bapi.api.And(isPass, isNumberVal)
	return isPass
}

func (bapi *BlockAPI) IsLessNumberU8(block1, block2 *Block) frontend.Variable {
	return bapi.uapi.IsLessU8(block1.Data[0][0], block2.Data[0][0])
}

func (bapi *BlockAPI) IsLessNumberU32(block1, block2 *Block) frontend.Variable {
	return bapi.uapi.IsLess(block1.Data[0], block2.Data[0])
}

// constructor of Block
func NewBlock() *Block {
	return &Block{
		Data_type:  uints.NewU8(EMPTY_KEY_TYPE),
		Len:        uints.NewU8(0),
		Ref_index:  uints.NewU8(0xff),
		Self_index: uints.NewU8(0xff),
		Data: [15]uints.U32{uints.NewU32(0), uints.NewU32(0), uints.NewU32(0), uints.NewU32(0), uints.NewU32(0),
			uints.NewU32(0), uints.NewU32(0), uints.NewU32(0), uints.NewU32(0), uints.NewU32(0),
			uints.NewU32(0), uints.NewU32(0), uints.NewU32(0), uints.NewU32(0), uints.NewU32(0)},
	}
}

func (b *Block) SelectBlock(api frontend.API, choseFirstBlock frontend.Variable, block1 *Block, block2 *Block) *Block {
	b.Data_type.Val = api.Select(choseFirstBlock, block1.Data_type.Val, block2.Data_type.Val)
	b.Len.Val = api.Select(choseFirstBlock, block1.Len.Val, block2.Len.Val)
	b.Ref_index.Val = api.Select(choseFirstBlock, block1.Ref_index.Val, block2.Ref_index.Val)
	b.Self_index.Val = api.Select(choseFirstBlock, block1.Self_index.Val, block2.Self_index.Val)
	for i := 0; i < 15; i++ {
		for j := 0; j < 4; j++ {
			b.Data[i][j].Val = api.Select(choseFirstBlock, block1.Data[i][j].Val, block2.Data[i][j].Val)
		}
	}
	return b
}

// another constructor of Block with specific type
func NewEmptyKeyBlock() *Block {
	block := NewBlock()
	block.Data_type = uints.NewU8(EMPTY_KEY_TYPE)
	return block
}

func NewEmptyValBlock() *Block {
	block := NewBlock()
	block.Data_type = uints.NewU8(EMPTY_VAL_TYPE)
	return block
}

func NewNullKeyBlock() *Block {
	block := NewBlock()
	block.Data_type = uints.NewU8(NULL_KEY_TYPE)
	return block
}

func NewNullValBlock() *Block {
	block := NewBlock()
	block.Data_type = uints.NewU8(NULL_VAL_TYPE)
	return block
}

func NewBoolKeyBlock() *Block {
	block := NewBlock()
	block.Data_type = uints.NewU8(BOOL_KEY_TYPE)
	return block
}

func NewBoolValBlock() *Block {
	block := NewBlock()
	block.Data_type = uints.NewU8(BOOL_VAL_TYPE)
	return block
}

func NewStringKeyBlock() *Block {
	block := NewBlock()
	block.Data_type = uints.NewU8(STRING_KEY_TYPE)
	return block
}

func NewStringValBlock() *Block {
	block := NewBlock()
	block.Data_type = uints.NewU8(STRING_VAL_TYPE)
	return block
}

func NewNumberKeyBlock() *Block {
	block := NewBlock()
	block.Data_type = uints.NewU8(NUMBER_KEY_TYPE)
	return block
}

func NewNumberValBlock() *Block {
	block := NewBlock()
	block.Data_type = uints.NewU8(NUMBER_VAL_TYPE)
	return block
}

func NewArrayKeyBlock() *Block {
	block := NewBlock()
	block.Data_type = uints.NewU8(ARRAY_KEY_TYPE)
	return block
}

func NewArrayValBlock() *Block {
	block := NewBlock()
	block.Data_type = uints.NewU8(ARRAY_VAL_TYPE)
	return block
}

func NewObjectKeyBlock() *Block {
	block := NewBlock()
	block.Data_type = uints.NewU8(OBJECT_KEY_TYPE)
	return block
}

func NewObjectValBlock() *Block {
	block := NewBlock()
	block.Data_type = uints.NewU8(OBJECT_VAL_TYPE)
	return block
}

func NewArrayPointerValBlock() *Block {
	block := NewBlock()
	block.Data_type = uints.NewU8(ARRAY_POINTER_VAL_TYPE)
	return block
}
