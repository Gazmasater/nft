package encoders

import (
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
)

func init() {
	register(&expr.Hash{}, func(e expr.Any) encoder {
		return &hashEncoder{hash: e.(*expr.Hash)}
	})
}

type hashEncoder struct {
	hash *expr.Hash
}

func (b *hashEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	var exp string
	sb := strings.Builder{}
	hash := b.hash
	sb.WriteString("symhash")
	if hash.Type != expr.HashTypeSym {
		srcReg, ok := ctx.reg.Get(regID(hash.SourceRegister))
		if !ok {
			return nil, errors.Errorf("%T statement has no expression", hash)
		}
		exp = srcReg.HumanExpr

		sb.WriteString(fmt.Sprintf("jhash %s", exp))
	}
	sb.WriteString(fmt.Sprintf(" mod %d seed 0x%x", hash.Modulus, hash.Seed))
	if hash.Offset > 0 {
		sb.WriteString(fmt.Sprintf(" offset %d", hash.Offset))
	}

	if hash.DestRegister == 0 {
		return nil, errors.Errorf("%T expression has invalid destination register %d", hash, hash.DestRegister)
	}

	ctx.reg.Set(regID(hash.DestRegister),
		regVal{
			Expr:      hash,
			HumanExpr: sb.String(),
		})

	return nil, ErrNoIR
}

func (b *hashEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	var exp any
	hash := b.hash
	if hash.Type != expr.HashTypeSym {
		srcReg, ok := ctx.reg.Get(regID(hash.SourceRegister))
		if !ok || srcReg.Data == nil {
			return nil, errors.Errorf("%T statement has no expression", hash)
		}
		exp = srcReg.Data
	}

	hashJson := map[string]interface{}{
		HashType(hash.Type).String(): struct {
			Mod    uint32 `json:"mod,omitempty"`
			Seed   uint32 `json:"seed,omitempty"`
			Offset uint32 `json:"offset,omitempty"`
			Expr   any    `json:"expr,omitempty"`
		}{
			Mod:    hash.Modulus,
			Seed:   hash.Seed,
			Offset: hash.Offset,
			Expr:   exp,
		},
	}

	if hash.DestRegister == 0 {
		return nil, errors.Errorf("%T expression has invalid destination register %d", hash, hash.DestRegister)
	}

	ctx.reg.Set(regID(hash.DestRegister),
		regVal{
			Data: hashJson,
		})
	return nil, ErrNoJSON
}

type HashType expr.HashType

func (h HashType) String() string {
	if h == HashType(expr.HashTypeSym) {
		return "symhash"
	}
	return "jhash"
}
