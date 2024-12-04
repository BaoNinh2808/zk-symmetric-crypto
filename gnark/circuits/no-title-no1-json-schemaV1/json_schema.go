package no_titlle_no1

import (
	"github.com/BaoNinh2808/gnark/std/math/uints"
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

func (js *JsonSchema) Require(requireKey *Block, index uints.U8) {
	isPass := frontend.Variable(0)
	for i := 0; i < split; i += 2 {
		key_index := uints.NewU8(uint8(i))
		isCorrectIndex := js.bapi.uapi.IsEqualU8(key_index, index)
		isEqualKey := js.bapi.IsEqual(requireKey, &js.data[i])
		isCorrect := js.bapi.api.And(isCorrectIndex, isEqualKey)
		isPass = js.bapi.api.Xor(isPass, isCorrect)
	}
	js.bapi.api.AssertIsEqual(isPass, 1) //there is only 1 position is correct
}

func (js *JsonSchema) Maximum(criteriaKey *Block, criteriaVal *Block, index uints.U8) {
	// pass if:
	// 1. key = criteriaKey & val < criteriaVal
	// 2. index = 0xff & for all key : key != criteriaKey

	isCase1Pass := frontend.Variable(0)
	is0xff := js.bapi.uapi.IsEqualU8(index, uints.NewU8(0xff))
	isAllKeyDiff := frontend.Variable(1)
	for i := 0; i < split; i += 2 {
		key_index := uints.NewU8(uint8(i))
		isCorrectIndex := js.bapi.uapi.IsEqualU8(key_index, index)

		isNumberKeyType := js.bapi.uapi.IsEqualU8(js.data[i].Data_type, uints.NewU8(NUMBER_KEY_TYPE))
		isEqualKey := js.bapi.IsEqual(&js.data[i], criteriaKey)
		isLessVal := js.bapi.IsLess(&js.data[i+1], criteriaVal)

		isCorrect := js.bapi.api.And(isEqualKey, isLessVal)
		isCorrect = js.bapi.api.And(isCorrect, isCorrectIndex)
		isCorrect = js.bapi.api.And(isCorrect, isNumberKeyType)

		isCase1Pass = js.bapi.api.Xor(isCase1Pass, isCorrect)

		isDiffKey := js.bapi.api.Xor(isEqualKey, 1)
		isAllKeyDiff = js.bapi.api.And(isAllKeyDiff, isDiffKey)
		isAllKeyDiff = js.bapi.api.Or(isAllKeyDiff, isNumberKeyType)
	}

	isCase2Pass := js.bapi.api.And(isAllKeyDiff, is0xff)
	isPass := js.bapi.api.Or(isCase1Pass, isCase2Pass)

	js.bapi.api.AssertIsEqual(isPass, 1)
}

func (js *JsonSchema) MaximumU8(criteriaKey *Block, criteriaVal *Block, index uints.U8) {
	// pass if:
	// 1. key = criteriaKey & val < criteriaVal
	// 2. index = 0xff & for all key : key != criteriaKey

	isCase1Pass := frontend.Variable(0)
	is0xff := js.bapi.uapi.IsEqualU8(index, uints.NewU8(0xff))
	isAllKeyDiff := frontend.Variable(1)
	for i := 0; i < split; i += 2 {
		key_index := uints.NewU8(uint8(i))
		isCorrectIndex := js.bapi.uapi.IsEqualU8(key_index, index)

		isNumberKeyType := js.bapi.uapi.IsEqualU8(js.data[i].Data_type, uints.NewU8(NUMBER_KEY_TYPE))
		isEqualKey := js.bapi.IsEqual(&js.data[i], criteriaKey)
		isLessVal := js.bapi.IsLessNumberU8(&js.data[i+1], criteriaVal)

		isCorrect := js.bapi.api.And(isEqualKey, isLessVal)
		isCorrect = js.bapi.api.And(isCorrect, isCorrectIndex)
		isCorrect = js.bapi.api.And(isCorrect, isNumberKeyType)

		isCase1Pass = js.bapi.api.Xor(isCase1Pass, isCorrect)

		isDiffKey := js.bapi.api.Xor(isEqualKey, 1)
		isAllKeyDiff = js.bapi.api.And(isAllKeyDiff, isDiffKey)
		isAllKeyDiff = js.bapi.api.Or(isAllKeyDiff, isNumberKeyType)
	}

	isCase2Pass := js.bapi.api.And(isAllKeyDiff, is0xff)
	isPass := js.bapi.api.Or(isCase1Pass, isCase2Pass)

	js.bapi.api.AssertIsEqual(isPass, 1)
}

func (js *JsonSchema) MaximumU32(criteriaKey *Block, criteriaVal *Block, index uints.U8) {
	// pass if:
	// 1. key = criteriaKey & val < criteriaVal
	// 2. index = 0xff & for all key : key != criteriaKey

	isCase1Pass := frontend.Variable(0)
	is0xff := js.bapi.uapi.IsEqualU8(index, uints.NewU8(0xff))
	isAllKeyDiff := frontend.Variable(1)
	for i := 0; i < split; i += 2 {
		key_index := uints.NewU8(uint8(i))
		isCorrectIndex := js.bapi.uapi.IsEqualU8(key_index, index)

		isNumberKeyType := js.bapi.uapi.IsEqualU8(js.data[i].Data_type, uints.NewU8(NUMBER_KEY_TYPE))
		isEqualKey := js.bapi.IsEqual(&js.data[i], criteriaKey)
		isLessVal := js.bapi.IsLessNumberU32(&js.data[i+1], criteriaVal)

		isCorrect := js.bapi.api.And(isEqualKey, isLessVal)
		isCorrect = js.bapi.api.And(isCorrect, isCorrectIndex)
		isCorrect = js.bapi.api.And(isCorrect, isNumberKeyType)

		isCase1Pass = js.bapi.api.Xor(isCase1Pass, isCorrect)

		isDiffKey := js.bapi.api.Xor(isEqualKey, 1)
		isAllKeyDiff = js.bapi.api.And(isAllKeyDiff, isDiffKey)
		isAllKeyDiff = js.bapi.api.Or(isAllKeyDiff, isNumberKeyType)
	}

	isCase2Pass := js.bapi.api.And(isAllKeyDiff, is0xff)
	isPass := js.bapi.api.Or(isCase1Pass, isCase2Pass)

	js.bapi.api.AssertIsEqual(isPass, 1)
}

func (js *JsonSchema) Minimum(criteriaKey *Block, criteriaVal *Block, index uints.U8) {
	// pass if:
	// 1. key = criteriaKey & val > criteriaVal
	// 2. index = 0xff & for all key : key != criteriaKey

	isCase1Pass := frontend.Variable(0)
	is0xff := js.bapi.uapi.IsEqualU8(index, uints.NewU8(0xff))
	isAllKeyDiff := frontend.Variable(1)
	for i := 0; i < split; i += 2 {
		key_index := uints.NewU8(uint8(i))
		isCorrectIndex := js.bapi.uapi.IsEqualU8(key_index, index)

		isNumberKeyType := js.bapi.uapi.IsEqualU8(js.data[i].Data_type, uints.NewU8(NUMBER_KEY_TYPE))
		isEqualKey := js.bapi.IsEqual(&js.data[i], criteriaKey)
		isGreaterVal := js.bapi.IsLess(criteriaVal, &js.data[i+1])

		isCorrect := js.bapi.api.And(isEqualKey, isGreaterVal)
		isCorrect = js.bapi.api.And(isCorrect, isCorrectIndex)
		isCorrect = js.bapi.api.And(isCorrect, isNumberKeyType)

		isCase1Pass = js.bapi.api.Xor(isCase1Pass, isCorrect)

		isDiffKey := js.bapi.api.Xor(isEqualKey, 1)
		isAllKeyDiff = js.bapi.api.And(isAllKeyDiff, isDiffKey)
		isAllKeyDiff = js.bapi.api.Or(isAllKeyDiff, isNumberKeyType)
	}

	isCase2Pass := js.bapi.api.And(isAllKeyDiff, is0xff)
	isPass := js.bapi.api.Or(isCase1Pass, isCase2Pass)

	js.bapi.api.AssertIsEqual(isPass, 1)
}

func (js *JsonSchema) MinimumU8(criteriaKey *Block, criteriaVal *Block, index uints.U8) {
	// pass if:
	// 1. key = criteriaKey & val > criteriaVal
	// 2. index = 0xff & for all key : key != criteriaKey

	isCase1Pass := frontend.Variable(0)
	is0xff := js.bapi.uapi.IsEqualU8(index, uints.NewU8(0xff))
	isAllKeyDiff := frontend.Variable(1)
	for i := 0; i < split; i += 2 {
		key_index := uints.NewU8(uint8(i))
		isCorrectIndex := js.bapi.uapi.IsEqualU8(key_index, index)

		isNumberKeyType := js.bapi.uapi.IsEqualU8(js.data[i].Data_type, uints.NewU8(NUMBER_KEY_TYPE))
		isEqualKey := js.bapi.IsEqual(&js.data[i], criteriaKey)
		isGreaterVal := js.bapi.IsLessNumberU8(criteriaVal, &js.data[i+1])

		isCorrect := js.bapi.api.And(isEqualKey, isGreaterVal)
		isCorrect = js.bapi.api.And(isCorrect, isCorrectIndex)
		isCorrect = js.bapi.api.And(isCorrect, isNumberKeyType)

		isCase1Pass = js.bapi.api.Xor(isCase1Pass, isCorrect)

		isDiffKey := js.bapi.api.Xor(isEqualKey, 1)
		isAllKeyDiff = js.bapi.api.And(isAllKeyDiff, isDiffKey)
		isAllKeyDiff = js.bapi.api.Or(isAllKeyDiff, isNumberKeyType)
	}

	isCase2Pass := js.bapi.api.And(isAllKeyDiff, is0xff)
	isPass := js.bapi.api.Or(isCase1Pass, isCase2Pass)

	js.bapi.api.AssertIsEqual(isPass, 1)
}

func (js *JsonSchema) MinimumU32(criteriaKey *Block, criteriaVal *Block, index uints.U8) {
	// pass if:
	// 1. key = criteriaKey & val > criteriaVal
	// 2. index = 0xff & for all key : key != criteriaKey

	isCase1Pass := frontend.Variable(0)
	is0xff := js.bapi.uapi.IsEqualU8(index, uints.NewU8(0xff))
	isAllKeyDiff := frontend.Variable(1)
	for i := 0; i < split; i += 2 {
		key_index := uints.NewU8(uint8(i))
		isCorrectIndex := js.bapi.uapi.IsEqualU8(key_index, index)

		isNumberKeyType := js.bapi.uapi.IsEqualU8(js.data[i].Data_type, uints.NewU8(NUMBER_KEY_TYPE))
		isEqualKey := js.bapi.IsEqual(&js.data[i], criteriaKey)
		isGreaterVal := js.bapi.IsLessNumberU32(criteriaVal, &js.data[i+1])

		isCorrect := js.bapi.api.And(isEqualKey, isGreaterVal)
		isCorrect = js.bapi.api.And(isCorrect, isCorrectIndex)
		isCorrect = js.bapi.api.And(isCorrect, isNumberKeyType)

		isCase1Pass = js.bapi.api.Xor(isCase1Pass, isCorrect)

		isDiffKey := js.bapi.api.Xor(isEqualKey, 1)
		isAllKeyDiff = js.bapi.api.And(isAllKeyDiff, isDiffKey)
		isAllKeyDiff = js.bapi.api.Or(isAllKeyDiff, isNumberKeyType)
	}

	isCase2Pass := js.bapi.api.And(isAllKeyDiff, is0xff)
	isPass := js.bapi.api.Or(isCase1Pass, isCase2Pass)

	js.bapi.api.AssertIsEqual(isPass, 1)
}

func (js *JsonSchema) Type(index uints.U8, allowTypes []uint8) {
	isPass := frontend.Variable(0)
	for i := 0; i < split; i += 2 {
		key_index := uints.NewU8(uint8(i))
		isCorrectIndex := js.bapi.uapi.IsEqualU8(key_index, index)
		isCorrectKeyType := frontend.Variable(0)

		for _, allowType := range allowTypes {
			isEqualType := js.bapi.uapi.IsEqualU8(js.data[i].Data_type, uints.NewU8(allowType))
			isCorrectKeyType = js.bapi.api.Xor(isCorrectKeyType, isEqualType)
		}

		isCorrect := js.bapi.api.And(isCorrectIndex, isCorrectKeyType)
		isPass = js.bapi.api.Xor(isCorrect, isPass)
	}
	js.bapi.api.AssertIsEqual(isPass, 1)
}

func (js *JsonSchema) MaxLength(max uints.U8, index uints.U8) {
	isPass := frontend.Variable(0)
	for i := 1; i < split; i += 2 {
		arr_val_index := uints.NewU8(uint8(i))

		isCorrectIndex := js.bapi.uapi.IsEqualU8(arr_val_index, index)
		isCorrectValType := js.bapi.uapi.IsEqualU8(js.data[i].Data_type, uints.NewU8(ARRAY_VAL_TYPE))
		isLenLessThanMax := js.bapi.uapi.IsLessU8(js.data[i].Len, max)

		isSatisfy := js.bapi.api.And(isCorrectIndex, isLenLessThanMax)
		isSatisfy = js.bapi.api.And(isSatisfy, isCorrectValType)

		isPass = js.bapi.api.Xor(isSatisfy, isPass)
	}
	js.bapi.api.AssertIsEqual(isPass, 1)
}

func (js *JsonSchema) MinLength(min uints.U8, index uints.U8) {
	isPass := frontend.Variable(0)
	for i := 1; i < split; i += 2 {
		arr_val_index := uints.NewU8(uint8(i))

		isCorrectIndex := js.bapi.uapi.IsEqualU8(arr_val_index, index)
		isCorrectValType := js.bapi.uapi.IsEqualU8(js.data[i].Data_type, uints.NewU8(ARRAY_VAL_TYPE))
		isLenGreaterThanMin := js.bapi.uapi.IsLessU8(min, js.data[i].Len)

		isSatisfy := js.bapi.api.And(isCorrectIndex, isLenGreaterThanMin)
		isSatisfy = js.bapi.api.And(isSatisfy, isCorrectValType)

		isPass = js.bapi.api.Xor(isSatisfy, isPass)
	}
	js.bapi.api.AssertIsEqual(isPass, 1)
}

func (js *JsonSchema) MaxProperties(max uints.U8, index uints.U8) {
	isPass := frontend.Variable(0)
	for i := 0; i < split; i += 2 {
		obj_key_index := uints.NewU8(uint8(i))

		isCorrectIndex := js.bapi.uapi.IsEqualU8(obj_key_index, index)
		isCorrectKeyType := js.bapi.uapi.IsEqualU8(js.data[i].Data_type, uints.NewU8(OBJECT_KEY_TYPE))
		isLenLessThanMax := js.bapi.uapi.IsLessU8(js.data[i].Len, max)

		isSatisfy := js.bapi.api.And(isCorrectIndex, isLenLessThanMax)
		isSatisfy = js.bapi.api.And(isSatisfy, isCorrectKeyType)

		isPass = js.bapi.api.Xor(isSatisfy, isPass)
	}
	js.bapi.api.AssertIsEqual(isPass, 1)
}

func (js *JsonSchema) MinProperties(min uints.U8, index uints.U8) {
	isPass := frontend.Variable(0)
	for i := 0; i < split; i += 2 {
		obj_key_index := uints.NewU8(uint8(i))

		isCorrectIndex := js.bapi.uapi.IsEqualU8(obj_key_index, index)
		isCorrectKeyType := js.bapi.uapi.IsEqualU8(js.data[i].Data_type, uints.NewU8(OBJECT_KEY_TYPE))
		isLenGreaterThanMin := js.bapi.uapi.IsLessU8(min, js.data[i].Len)

		isSatisfy := js.bapi.api.And(isCorrectIndex, isLenGreaterThanMin)
		isSatisfy = js.bapi.api.And(isSatisfy, isCorrectKeyType)

		isPass = js.bapi.api.Xor(isSatisfy, isPass)
	}
	js.bapi.api.AssertIsEqual(isPass, 1)
}

func (js *JsonSchema) UniqueItems(index uints.U8) {
	ref_index := uints.NewU8(0xff)
	for i := 1; i < split; i += 2 {
		arr_val_index := uints.NewU8(uint8(i))

		isCorrectIndex := js.bapi.uapi.IsEqualU8(arr_val_index, index)
		ref_index.Val = js.bapi.api.Select(isCorrectIndex, js.data[i].Ref_index.Val, ref_index.Val)
	}

	js.bapi.api.AssertIsDifferent(ref_index.Val, 0xff)
	for i := split; i < n; i++ {
		isSatisfy := frontend.Variable(1)
		isRef_i := js.bapi.uapi.IsEqualU8(js.data[i].Ref_index, ref_index)
		for j := i + 1; j < n; j++ {
			isRef_j := js.bapi.uapi.IsEqualU8(js.data[j].Ref_index, ref_index)
			isEqual := js.bapi.IsEqual(&js.data[i], &js.data[j])
			isSameRefToConsiderArr := js.bapi.api.And(isRef_i, isRef_j)
			isThisPairSatisfy := js.bapi.api.Xor(js.bapi.api.And(isEqual, isSameRefToConsiderArr), 1)
			isSatisfy = js.bapi.api.And(isSatisfy, isThisPairSatisfy)
		}
		js.bapi.api.AssertIsEqual(isSatisfy, 1)
	}
}
