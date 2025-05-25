//nolint:dupl
package encoders

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func init() {
	register(&expr.Match{}, func(e expr.Any) encoder {
		return &matchEncoder{match: e.(*expr.Match)}
	})
}

type matchEncoder struct {
	match *expr.Match
}

func (b *matchEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	return simpleIR(fmt.Sprintf(`xt match %q`, b.match.Name)), nil
}

func (b *matchEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	return []byte(fmt.Sprintf(`{"xt":{"type":"match","name":%q}}`, b.match.Name)), nil
}
