package encoders

import (
	"fmt"

	pr "github.com/Morwran/nft-go/pkg/protocols"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

var registry = map[string]encoderFn{}

func register(e expr.Any, fn encoderFn) {
	registry[fmt.Sprintf("%T", e)] = fn
}

type (
	regID  uint32
	regVal struct {
		HumanExpr string
		Len       int
		Expr      expr.Any
		Data      any
		Op        string
	}
	regHolder struct {
		cache map[regID]regVal
	}
)

func (r *regHolder) Get(id regID) (regVal, bool) { v, ok := r.cache[id]; return v, ok }

func (r *regHolder) Set(id regID, v regVal) {
	r.ensureInit()
	r.cache[id] = v
}

func (r *regHolder) ensureInit() {
	if r.cache == nil {
		r.cache = make(map[regID]regVal)
	}
}

type ctx struct {
	reg  regHolder
	hdr  *pr.ProtoDescPtr
	sets setCache
	rule *nft.Rule
}
