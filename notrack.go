package encoders

import (
	"github.com/google/nftables/expr"
)

func init() {
	register(&expr.Notrack{}, func(e expr.Any) encoder {
		return &notrackEncoder{notrack: e.(*expr.Notrack)}
	})
}

type notrackEncoder struct {
	notrack *expr.Notrack
}

func (b *notrackEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	return simpleIR("notrack"), nil
}

func (b *notrackEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	return []byte(`{"notrack":null}`), nil
}
