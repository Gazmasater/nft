//nolint:dupl
package encoders

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func init() {
	register(&expr.Target{}, func(e expr.Any) encoder {
		return &targetEncoder{target: e.(*expr.Target)}
	})
}

type targetEncoder struct {
	target *expr.Target
}

func (b *targetEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	return simpleIR(fmt.Sprintf(`xt target %q`, b.target.Name)), nil
}

func (b *targetEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	return []byte(fmt.Sprintf(`{"xt":{"type":"target","name":%q}}`, b.target.Name)), nil
}
