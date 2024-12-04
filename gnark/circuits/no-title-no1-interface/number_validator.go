package no_titlle_no1

import "github.com/BaoNinh2808/gnark/std/math/uints"

type NumberMinU8 struct {
	bapi        *BlockAPI
	blockVal    *Block
	criteriaVal uints.U8 `gnark:",public"`
}

func (n *NumberMinU8) Validate() {

}
