package encoders

import (
	"github.com/google/nftables/expr"
)

func init() {
	register(&expr.Masq{}, func(e expr.Any) encoder {
		return &masqEncoder{masq: e.(*expr.Masq)}
	})
}

type masqEncoder struct {
	masq *expr.Masq
}

func (b *masqEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	nb := natEncoder{
		nat: &expr.NAT{
			Type:        NATTypeMASQ,
			Persistent:  b.masq.Persistent,
			Random:      b.masq.Random,
			FullyRandom: b.masq.FullyRandom,
			RegProtoMin: b.masq.RegProtoMin,
			RegProtoMax: b.masq.RegProtoMax,
		},
	}

	return nb.EncodeIR(ctx)
}

func (b *masqEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	nb := natEncoder{
		nat: &expr.NAT{
			Type:        NATTypeMASQ,
			Persistent:  b.masq.Persistent,
			Random:      b.masq.Random,
			FullyRandom: b.masq.FullyRandom,
			RegProtoMin: b.masq.RegProtoMin,
			RegProtoMax: b.masq.RegProtoMax,
		},
	}
	return nb.EncodeJSON(ctx)
}
