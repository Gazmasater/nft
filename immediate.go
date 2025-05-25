package encoders

import (
	"github.com/Morwran/nft-go/internal/bytes"

	"github.com/google/nftables/expr"
)

func init() {
	register(&expr.Immediate{}, func(e expr.Any) encoder {
		return &immediateEncoder{immediate: e.(*expr.Immediate)}
	})
}

type immediateEncoder struct {
	immediate *expr.Immediate
}

func (b *immediateEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	ctx.reg.Set(regID(b.immediate.Register),
		regVal{
			HumanExpr: bytes.RawBytes((b.immediate.Data)).String(),
			Expr:      b.immediate,
		})
	return nil, ErrNoIR
}
func (b *immediateEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	ctx.reg.Set(regID(b.immediate.Register),
		regVal{Data: bytes.RawBytes((b.immediate.Data))})
	return nil, ErrNoJSON
}
