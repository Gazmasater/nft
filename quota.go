package encoders

import (
	"encoding/json"
	"fmt"

	"github.com/google/nftables/expr"
)

func init() {
	register(&expr.Quota{}, func(e expr.Any) encoder {
		return &quotaEncoder{quota: e.(*expr.Quota)}
	})
}

type quotaEncoder struct {
	quota *expr.Quota
}

func (b *quotaEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	val, u := b.Rate()
	return simpleIR(fmt.Sprintf("quota %s%d %s",
		map[bool]string{true: "over ", false: ""}[b.quota.Over],
		val, u)), nil
}

func (b *quotaEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	val, u := b.Rate()
	quota := map[string]interface{}{
		"quota": struct {
			Val  uint64 `json:"val"`
			Unit string `json:"val_unit"`
		}{
			Val:  val,
			Unit: u,
		},
	}

	return json.Marshal(quota)
}

func (b *quotaEncoder) Rate() (val uint64, unit string) {
	return getRate(b.quota.Bytes)
}
