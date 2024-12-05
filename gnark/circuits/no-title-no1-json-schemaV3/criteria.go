package no_titlle_no1

const REF_TO_KEY = 1
const REF_TO_VAL = 2
const REF_TO_ARRAY_PART = 3

type Criteria struct {
	Refs         []int
	IsRefsCheck  []bool
	RefsCheckObj []Block `gnark:",public"`
	RefObj       Block   `gnark:",public"`
	CritKey      Block   `gnark:",public"`
	CritVal      Block   `gnark:",public"`
}

func NewCriteria() *Criteria {
	return &Criteria{
		Refs:         []int{},
		IsRefsCheck:  []bool{},
		RefsCheckObj: []Block{},
		RefObj:       *NewBlock(),
		CritKey:      *NewBlock(),
		CritVal:      *NewBlock(),
	}
}
