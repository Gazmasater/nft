package encoders

import (
	"encoding/json"
	"fmt"
	"strings"

	rb "github.com/Morwran/nft-go/internal/bytes"

	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
)

func init() {
	register(&expr.Range{}, func(e expr.Any) encoder {
		return &rangeEncoder{rn: e.(*expr.Range)}
	})
}

type (
	rangeEncoder struct {
		rn *expr.Range
	}
	rangeIR struct {
		*expr.Range
		left string
	}
)

func (b *rangeEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	r := b.rn
	srcReg, ok := ctx.reg.Get(regID(r.Register))
	if !ok {
		return nil, errors.Errorf("%T sexpression has no left hand side", r)
	}
	left := srcReg.HumanExpr
	return &rangeIR{Range: r, left: left}, nil
}

func (b *rangeEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	r := b.rn
	srcReg, ok := ctx.reg.Get(regID(r.Register))
	if !ok || srcReg.Data == nil {
		return nil, errors.Errorf("%T sexpression has no left hand side", r)
	}
	op := CmpOp(r.Op).String()
	if op == "" {
		op = "in"
	}
	match := map[string]interface{}{
		"match": struct {
			Op    string `json:"op"`
			Left  any    `json:"left"`
			Right any    `json:"right"`
		}{
			Op:   op,
			Left: srcReg.Data,
			Right: map[string]interface{}{
				"range": [2]rb.RawBytes{rb.RawBytes(r.FromData), rb.RawBytes(r.ToData)},
			},
		},
	}
	return json.Marshal(match)
}

func (r *rangeIR) Format() string {
	sb := strings.Builder{}
	sb.WriteString(r.left)
	op := CmpOp(r.Op).String()
	if op != "" && r.Op != expr.CmpOpEq {
		sb.WriteString(fmt.Sprintf(" %s ", op))
	} else {
		sb.WriteByte(' ')
	}
	sb.WriteString(fmt.Sprintf("%s-%s", rb.RawBytes(r.FromData).String(), rb.RawBytes(r.ToData).String()))
	return sb.String()
}
