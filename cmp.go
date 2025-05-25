package encoders

import (
	"bytes"
	"encoding/json"
	"fmt"

	rb "github.com/Morwran/nft-go/internal/bytes"

	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func init() {
	register(&expr.Cmp{}, func(e expr.Any) encoder {
		return &cmpEncoder{cmp: e.(*expr.Cmp)}
	})
}

type (
	cmpEncoder struct {
		cmp *expr.Cmp
	}
	cmpIR struct{ L, Op, R string }
)

func (b *cmpEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	cmp := b.cmp
	srcReg, ok := ctx.reg.Get(regID(cmp.Register))
	if !ok {
		return nil, errors.Errorf("%T expression has no left hand side", cmp)
	}
	left := srcReg.HumanExpr
	right := ""
	l, r := b.formatCmpLR(ctx, srcReg)
	if l != "" {
		left = l
	}
	if r != "" {
		right = r
	}

	op := CmpOp(cmp.Op).String()
	if cmp.Op == expr.CmpOpEq {
		op = ""
	}
	return cmpIR{L: left, Op: op, R: right}, nil
}

func (b *cmpEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	cmp := b.cmp
	srcReg, ok := ctx.reg.Get(regID(cmp.Register))
	if !ok || srcReg.Data == nil {
		return nil, errors.Errorf("%T expression has no left hand side", cmp)
	}
	var right any
	switch t := srcReg.Expr.(type) {
	case *expr.Meta:
		switch t.Key {
		case expr.MetaKeyL4PROTO:
			switch rb.RawBytes(cmp.Data).Uint64() {
			case unix.IPPROTO_TCP:
				right = "tcp"
			case unix.IPPROTO_UDP:
				right = "udp"
			default:
				right = "unknown" //nolint:goconst
			}
		case expr.MetaKeyIIFNAME, expr.MetaKeyOIFNAME:
			right = string(bytes.TrimRight(cmp.Data, "\x00"))
		case expr.MetaKeyNFTRACE:
			right = rb.RawBytes(cmp.Data).Uint64()
		default:
			right = rb.RawBytes(cmp.Data)
		}
	default:
		right = rb.RawBytes(cmp.Data)
	}

	cmpJson := map[string]interface{}{
		"match": struct {
			Op    string `json:"op"`
			Left  any    `json:"left"`
			Right any    `json:"right"`
		}{
			Op:    CmpOp(cmp.Op).String(),
			Left:  srcReg.Data,
			Right: right,
		},
	}

	return json.Marshal(cmpJson)
}

func (b *cmpEncoder) formatCmpLR(ctx *ctx, srcReg regVal) (left, right string) {
	cmp := b.cmp
	switch t := srcReg.Expr.(type) {
	case *expr.Meta:
		metaBuilder := &metaEncoder{t}
		right = metaBuilder.buildFromCmpData(ctx, cmp)
	case *expr.Bitwise:
		bitwiseBuilder := &bitwiseEncoder{t}
		right = bitwiseBuilder.buildFromCmpData(ctx, cmp)
	case *expr.Ct:
		right = CtDesk[t.Key](cmp.Data)
	case *expr.Payload:
		payloadBuilder := &payloadEncoder{t}
		left, right = payloadBuilder.buildLRFromCmpData(ctx, cmp)
	default:
		right = rb.RawBytes(cmp.Data).Text(rb.BaseDec)
	}
	return left, right
}

func (n cmpIR) Format() (res string) {
	if n.Op != "" && n.R != "" {
		return fmt.Sprintf("%s %s %s", n.L, n.Op, n.R)
	} else if n.R != "" {
		return fmt.Sprintf("%s %s", n.L, n.R)
	}
	return n.L
}

type CmpOp expr.CmpOp

func (c CmpOp) String() string {
	switch expr.CmpOp(c) {
	case expr.CmpOpEq:
		return "=="
	case expr.CmpOpNeq:
		return "!="
	case expr.CmpOpLt:
		return "<"
	case expr.CmpOpLte:
		return "<="
	case expr.CmpOpGt:
		return ">"
	case expr.CmpOpGte:
		return ">="
	}
	return ""
}
