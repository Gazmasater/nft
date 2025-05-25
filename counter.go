package encoders

import (
	"fmt"

	"github.com/google/nftables/expr"
)

func init() {
	register(&expr.Counter{}, func(e expr.Any) encoder {
		return &counterEncoder{counter: e.(*expr.Counter)}
	})
}

type counterEncoder struct {
	counter *expr.Counter
}

func (b *counterEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	return simpleIR("counter packets 0 bytes 0"), nil
}

func (b *counterEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	return []byte(fmt.Sprintf(`{"counter":{"bytes":%d,"packets":%d}}`, b.counter.Bytes, b.counter.Packets)), nil
}
