package encoders

import (
	"github.com/google/nftables/expr"
)

func init() {
	register(&expr.Redir{}, func(e expr.Any) encoder {
		return &redirectEncoder{redir: e.(*expr.Redir)}
	})
}

type redirectEncoder struct {
	redir *expr.Redir
}

func (b *redirectEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	nb := natEncoder{
		nat: &expr.NAT{
			Type:        NATTypeRedir,
			Persistent:  (b.redir.Flags & expr.NF_NAT_RANGE_PERSISTENT) != 0,
			Random:      (b.redir.Flags & expr.NF_NAT_RANGE_PROTO_RANDOM) != 0,
			FullyRandom: (b.redir.Flags & expr.NF_NAT_RANGE_PROTO_RANDOM_FULLY) != 0,
			RegProtoMin: b.redir.RegisterProtoMin,
			RegProtoMax: b.redir.RegisterProtoMax,
		},
	}

	return nb.EncodeIR(ctx)
}

func (b *redirectEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	nb := natEncoder{
		nat: &expr.NAT{
			Type:        NATTypeRedir,
			Persistent:  (b.redir.Flags & expr.NF_NAT_RANGE_PERSISTENT) != 0,
			Random:      (b.redir.Flags & expr.NF_NAT_RANGE_PROTO_RANDOM) != 0,
			FullyRandom: (b.redir.Flags & expr.NF_NAT_RANGE_PROTO_RANDOM_FULLY) != 0,
			RegProtoMin: b.redir.RegisterProtoMin,
			RegProtoMax: b.redir.RegisterProtoMax,
		},
	}

	return nb.EncodeJSON(ctx)
}
