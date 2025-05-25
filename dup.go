package encoders

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
)

func init() {
	register(&expr.Dup{}, func(e expr.Any) encoder {
		return &dupEncoder{dup: e.(*expr.Dup)}
	})
}

type dupEncoder struct {
	dup *expr.Dup
}

func (b *dupEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	var addr, dev string
	sb := strings.Builder{}
	sb.WriteString("dup")
	dup := b.dup
	if dup.RegAddr != 0 {
		srcRegAddr, ok := ctx.reg.Get(regID(dup.RegAddr))
		if !ok {
			return nil, errors.Errorf("%T statement has no destination expression", dup)
		}
		addr = srcRegAddr.HumanExpr
		if addr != "" {
			sb.WriteString(fmt.Sprintf(" to %s", addr))
		}
	}
	if dup.RegDev != 0 {
		srcRegDev, ok := ctx.reg.Get(regID(dup.RegDev))
		if !ok {
			return nil, errors.Errorf("%T statement has no destination expression", dup)
		}
		dev = srcRegDev.HumanExpr

		if addr != "" && dev != "" {
			sb.WriteString(fmt.Sprintf(" device %s", dev))
		}
	}
	return simpleIR(sb.String()), nil
}

func (b *dupEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	var addr, dev any
	dup := b.dup
	if dup.RegAddr != 0 {
		srcRegAddr, ok := ctx.reg.Get(regID(dup.RegAddr))
		if !ok || srcRegAddr.Data == nil {
			return nil, errors.Errorf("%T statement has no destination expression", dup)
		}
		addr = srcRegAddr.Data
	}
	if dup.RegDev != 0 {
		srcRegDev, ok := ctx.reg.Get(regID(dup.RegDev))
		if !ok || srcRegDev.Data == nil {
			return nil, errors.Errorf("%T statement has no destination expression", dup)
		}
		dev = srcRegDev.Data
	}

	dupJson := map[string]interface{}{
		"dup": struct {
			RegAddr any `json:"addr,omitempty"`
			RegDev  any `json:"dev,omitempty"`
		}{
			RegAddr: addr,
			RegDev:  dev,
		},
	}
	return json.Marshal(dupJson)
}
