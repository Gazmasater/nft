package encoders

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func init() {
	register(&expr.FlowOffload{}, func(e expr.Any) encoder {
		return &flowOffloadEncoder{flowOffload: e.(*expr.FlowOffload)}
	})
}

type flowOffloadEncoder struct {
	flowOffload *expr.FlowOffload
}

func (b *flowOffloadEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	f := b.flowOffload
	return simpleIR(fmt.Sprintf("flow add @%s", f.Name)), nil
}

func (b *flowOffloadEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	f := b.flowOffload
	return []byte(fmt.Sprintf(`{"flow":{"op":"add","flowtable":%q}}`, f.Name)), nil
}
