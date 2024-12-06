package no_titlle_no1

import (
	"github.com/consensys/gnark/frontend"
)

type JsonSchema struct {
	data [n]Block
	bapi *BlockAPI
}

func NewJsonSchema(data [n]Block, bapi *BlockAPI) *JsonSchema {
	return &JsonSchema{
		data: data,
		bapi: bapi,
	}
}

func (js *JsonSchema) Dereferences(DerefBlock *Block, refs []int, isRefCheck []bool, refsCheckObj []Block) *Block {
	if refs == nil {
		panic("Dereferences: refs slice is nil")
	}
	if isRefCheck == nil {
		panic("Dereferences: isRefCheck slice is nil")
	}
	if refsCheckObj == nil {
		panic("Dereferences: refsCheckObj slic is nil")
	}

	if len(refs) != len(isRefCheck) || len(refs) != len(refsCheckObj) {
		panic("Dereferences: length of slices is not equal")
	}

	result := NewBlock()
	derefBlock := DerefBlock
	for i, ref := range refs {
		refBlock := NewBlock()
		if ref == REF_TO_KEY {
			js.Deref_TOKEY(derefBlock, refBlock, isRefCheck[i], refsCheckObj[i])
		} else if ref == REF_TO_VAL {
			js.Deref_TOVAL(derefBlock, refBlock, isRefCheck[i], refsCheckObj[i])
		} else if ref == REF_TO_ARRAY_PART {
			js.Deref_TOARRAYPART(derefBlock, refBlock, isRefCheck[i], refsCheckObj[i])
		} else {
			panic("Dereferences: ref is not valid")
		}

		derefBlock = refBlock
		result = refBlock
	}
	return result
}

func (js *JsonSchema) Deref_TOKEY(DerefBlock *Block, RefBlock *Block, IsRefCheck bool, refsCheckObj Block) *Block {
	result := NewBlock()
	for i := 0; i < split; i += 2 {
		isSelect := js.bapi.uapi.IsEqualU8(js.data[i].Self_index, DerefBlock.Ref_index)
		result.SelectBlock(js.bapi.api, isSelect, &js.data[i], result)
	}

	isEqualRefObj := frontend.Variable(1)
	if IsRefCheck {
		isEqualRefObj = js.bapi.IsEqual(result, &refsCheckObj)
	}
	return RefBlock.SelectBlock(js.bapi.api, isEqualRefObj, result, RefBlock)
}

func (js *JsonSchema) Deref_TOVAL(DerefBlock *Block, RefBlock *Block, IsRefCheck bool, refsCheckObj Block) *Block {
	result := NewBlock()
	for i := 1; i < split; i += 2 {
		isSelect := js.bapi.uapi.IsEqualU8(js.data[i].Self_index, DerefBlock.Ref_index)
		result.SelectBlock(js.bapi.api, isSelect, &js.data[i], result)
	}

	isEqualRefObj := frontend.Variable(1)
	if IsRefCheck {
		isEqualRefObj = js.bapi.IsEqual(result, &refsCheckObj)
	}
	return RefBlock.SelectBlock(js.bapi.api, isEqualRefObj, result, RefBlock)
}

func (js *JsonSchema) Deref_TOARRAYPART(DerefBlock *Block, RefBlock *Block, IsRefCheck bool, refsCheckObj Block) *Block {
	result := NewBlock()
	for i := split; i < n; i++ {
		isSelect := js.bapi.uapi.IsEqualU8(js.data[i].Self_index, DerefBlock.Ref_index)
		result.SelectBlock(js.bapi.api, isSelect, &js.data[i], result)
	}

	isEqualRefObj := frontend.Variable(1)
	if IsRefCheck {
		isEqualRefObj = js.bapi.IsEqual(result, &refsCheckObj)
	}
	return RefBlock.SelectBlock(js.bapi.api, isEqualRefObj, result, RefBlock)
}

func (js *JsonSchema) IsReference(block *Block, crit *Criteria) frontend.Variable {
	refBlock := js.Dereferences(block, crit.Refs, crit.IsRefsCheck, crit.RefsCheckObj)
	isRef := js.bapi.IsEqual(refBlock, &crit.RefObj)
	return isRef
}

//-----------TYPE----------//

func (js *JsonSchema) Type_AnonymousKey(block *Block, crit *Criteria) (frontend.Variable, frontend.Variable) {
	isRef := js.IsReference(block, crit)
	isEqualType := js.bapi.uapi.IsEqualU8(block.Data_type, crit.CritKey.Data_type)

	isPass := js.bapi.api.And(isRef, isEqualType)
	return isRef, isPass
}

func (js *JsonSchema) Type_AnonymousVal(block *Block, crit *Criteria) (frontend.Variable, frontend.Variable) {
	isRef := js.IsReference(block, crit)
	isEqualType := js.bapi.uapi.IsEqualU8(block.Data_type, crit.CritVal.Data_type)

	isPass := js.bapi.api.And(isRef, isEqualType)
	return isRef, isPass
}

func (js *JsonSchema) Type_Key(block *Block, crit *Criteria) (frontend.Variable, frontend.Variable) {
	isRef := js.IsReference(block, crit)
	isEqualType := js.bapi.uapi.IsEqualU8(block.Data_type, crit.CritKey.Data_type)
	isEqualKey := js.bapi.IsEqual(block, &crit.CritKey)

	isPass := js.bapi.api.And(isRef, isEqualType)
	isPass = js.bapi.api.And(isPass, isEqualKey)
	return isRef, isPass
}

func (js *JsonSchema) Type_Val(block *Block, crit *Criteria) (frontend.Variable, frontend.Variable) {
	isRef := js.IsReference(block, crit)
	isEqualType := js.bapi.uapi.IsEqualU8(block.Data_type, crit.CritVal.Data_type)
	isEqualVal := js.bapi.IsEqual(block, &crit.CritVal)

	isPass := js.bapi.api.And(isRef, isEqualType)
	isPass = js.bapi.api.And(isPass, isEqualVal)
	return isRef, isPass
}

func (js *JsonSchema) ANONYMOUS_KEYCHECK_Type(crit *Criteria) {
	for i := 2; i < split; i += 2 {
		isRef, isSatisfy := js.Type_AnonymousKey(&js.data[i], crit)
		isOne := js.bapi.api.Select(isRef, isSatisfy, 1)
		js.bapi.api.AssertIsEqual(isOne, 1)
	}
}

func (js *JsonSchema) ANONYMOUS_VALCHECK_Type(crit *Criteria) {
	for i := 3; i < split; i += 2 {
		isRef, isSatisfy := js.Type_AnonymousVal(&js.data[i], crit)
		isOne := js.bapi.api.Select(isRef, isSatisfy, 1)
		js.bapi.api.AssertIsEqual(isOne, 1)
	}
}

func (js *JsonSchema) ANONYMOUS_ARRAYPART_VALCHECK_Type(crit *Criteria) {
	for i := split; i < n; i++ {
		isRef, isSatisfy := js.Type_AnonymousVal(&js.data[i], crit)
		isOne := js.bapi.api.Select(isRef, isSatisfy, 1)
		js.bapi.api.AssertIsEqual(isOne, 1)
	}
}

func (js *JsonSchema) KEYCHECK_Type(crit *Criteria) {
	sumCheck := frontend.Variable(0)

	for i := 2; i < split; i += 2 {
		isRef, isSatisfy := js.Type_Key(&js.data[i], crit)
		isSatisfy = js.bapi.api.And(isRef, isSatisfy) //only check if isRef is true --> only one key is satisfied

		RefLen := js.Dereferences(&js.data[i], []int{crit.Refs[0]}, []bool{crit.IsRefsCheck[0]}, []Block{crit.RefsCheckObj[0]}).Len.Val
		// RefLen := frontend.Variable(2)
		addAmount := js.bapi.api.Select(isSatisfy, RefLen, 0)

		sumCheck = js.bapi.api.Add(sumCheck, addAmount) //must change to Add (refObj.Len - 1)

		isPenalty := js.bapi.api.Select(isRef, -1, 0)
		sumCheck = js.bapi.api.Add(sumCheck, isPenalty)
	}
	js.bapi.api.AssertIsEqual(sumCheck, 0)
}

func (js *JsonSchema) VALCHECK_Type(crit *Criteria) {
	sumCheck := frontend.Variable(0)
	for i := 3; i < split; i += 2 {
		isRef, isSatisfy := js.Type_Val(&js.data[i], crit)
		isSatisfy = js.bapi.api.And(isRef, isSatisfy) //only check if isRef is true --> only one val is satisfied

		RefLen := js.Dereferences(&js.data[i], []int{crit.Refs[0]}, []bool{crit.IsRefsCheck[0]}, []Block{crit.RefsCheckObj[0]}).Len.Val
		// RefLen := frontend.Variable(2)
		addAmount := js.bapi.api.Select(isSatisfy, RefLen, 0)

		sumCheck = js.bapi.api.Add(sumCheck, addAmount) //must change to Add (refObj.Len - 1)

		isPenalty := js.bapi.api.Select(isRef, -1, 0)
		sumCheck = js.bapi.api.Add(sumCheck, isPenalty)
	}
	js.bapi.api.AssertIsEqual(sumCheck, 0)
}

func (js *JsonSchema) ARRAYPART_VALCHECK_Type(crit *Criteria) {
	isPass := frontend.Variable(0)
	for i := split; i < n; i++ {
		isRef, isSatisfy := js.Type_Val(&js.data[i], crit)
		isSatisfy = js.bapi.api.And(isRef, isSatisfy) //only check if isRef is true --> only one val is satisfied
		isPass = js.bapi.api.Xor(isPass, isSatisfy)
	}
	js.bapi.api.AssertIsEqual(isPass, 1)
}

func (js *JsonSchema) ROOT_KEYCHECK_Type(crit *Criteria) {
	isPass := js.bapi.uapi.IsEqualU8(js.data[0].Data_type, crit.CritKey.Data_type)
	js.bapi.api.AssertIsEqual(isPass, 1)
}

func (js *JsonSchema) ROOT_VALCHECK_Type(crit *Criteria) {
	isPass := js.bapi.uapi.IsEqualU8(js.data[1].Data_type, crit.CritVal.Data_type)
	js.bapi.api.AssertIsEqual(isPass, 1)
}

//------------NUMBER: MAX---------//

func (js *JsonSchema) Maximum(key_block *Block, val_block *Block, crit *Criteria) frontend.Variable {
	isRef := js.IsReference(key_block, crit)
	isEqualKey := js.bapi.IsEqual(key_block, &crit.CritKey)
	isLessVal := js.bapi.IsLess(val_block, &crit.CritVal)

	isPass := js.bapi.api.And(isRef, isEqualKey)
	isPass = js.bapi.api.And(isPass, isLessVal)

	return js.bapi.api.Select(isRef, isPass, 1)
}

func (js *JsonSchema) Maximum_Val(val_block *Block, crit *Criteria) frontend.Variable {
	isRef := js.IsReference(val_block, crit)
	isLessVal := js.bapi.IsLess(val_block, &crit.CritVal)

	isPass := js.bapi.api.And(isRef, isLessVal)
	return js.bapi.api.Select(isRef, isPass, 1)
}

func (js *JsonSchema) VALCHECK_Maximum(crit *Criteria) {
	for i := 3; i < split; i += 2 {
		isSatisfy := js.Maximum(&js.data[i-1], &js.data[i], crit)
		js.bapi.api.AssertIsEqual(isSatisfy, 1)
	}
}

func (js *JsonSchema) ARRAYPART_VALCHECK_Maximum(crit *Criteria) {
	for i := split; i < n; i++ {
		isSatisfy := js.Maximum_Val(&js.data[i], crit)
		js.bapi.api.AssertIsEqual(isSatisfy, 1)
	}
}

//------------NUMBER: MIN---------//

func (js *JsonSchema) Minimum(key_block *Block, val_block *Block, crit *Criteria) frontend.Variable {
	isRef := js.IsReference(key_block, crit)
	isEqualKey := js.bapi.IsEqual(key_block, &crit.CritKey)
	isLessVal := js.bapi.IsLess(&crit.CritVal, val_block)

	isPass := js.bapi.api.And(isRef, isEqualKey)
	isPass = js.bapi.api.And(isPass, isLessVal)

	return js.bapi.api.Select(isRef, isPass, 1)
}

func (js *JsonSchema) Minimum_Val(val_block *Block, crit *Criteria) frontend.Variable {
	isRef := js.IsReference(val_block, crit)
	isLessVal := js.bapi.IsLess(&crit.CritVal, val_block)

	isPass := js.bapi.api.And(isRef, isLessVal)
	return js.bapi.api.Select(isRef, isPass, 1)
}

func (js *JsonSchema) VALCHECK_Minimum(crit *Criteria) {
	for i := 3; i < split; i += 2 {
		isSatisfy := js.Minimum(&js.data[i-1], &js.data[i], crit)
		js.bapi.api.AssertIsEqual(isSatisfy, 1)
	}
}

func (js *JsonSchema) ARRAYPART_VALCHECK_Minimum(crit *Criteria) {
	for i := split; i < n; i++ {
		isSatisfy := js.Minimum_Val(&js.data[i], crit)
		js.bapi.api.AssertIsEqual(isSatisfy, 1)
	}
}

// ------------OBJECT: REQUIRE---------//
func (js *JsonSchema) KEYCHECK_Require(crit *Criteria) {
	sumCheck := frontend.Variable(0)
	for i := 2; i < split; i += 2 {
		isRef := js.IsReference(&js.data[i], crit)
		// isEqualData := frontend.Variable(1)
		isEqualData := js.bapi.IsEqual_NOTCHECKTYPE(&js.data[i], &crit.CritKey)
		isSatisfy := js.bapi.api.And(isRef, isEqualData)

		RefLen := js.Dereferences(&js.data[i], []int{crit.Refs[0]}, []bool{crit.IsRefsCheck[0]}, []Block{crit.RefsCheckObj[0]}).Len.Val
		// RefLen := frontend.Variable(2)
		addAmount := js.bapi.api.Select(isSatisfy, RefLen, 0)

		sumCheck = js.bapi.api.Add(sumCheck, addAmount) //must change to Add (refObj.Len - 1)

		isPenalty := js.bapi.api.Select(isRef, -1, 0)
		sumCheck = js.bapi.api.Add(sumCheck, isPenalty)
	}
	js.bapi.api.AssertIsEqual(sumCheck, 0)
}
