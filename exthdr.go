package encoders

import (
	"encoding/json"
	"fmt"

	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func init() {
	register(&expr.Exthdr{}, func(e expr.Any) encoder {
		return &exthdrEncoder{extdhdr: e.(*expr.Exthdr)}
	})
}

type exthdrEncoder struct {
	extdhdr *expr.Exthdr
}

func (b *exthdrEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	exthdr := b.extdhdr
	exp := ""
	op := "exthdr"
	switch exthdr.Op {
	case expr.ExthdrOpTcpopt:
		op = "tcp option"
	case expr.ExthdrOpIpv6:
		op = "ip option"
	}
	if exthdr.Offset == 0 && exthdr.Flags == unix.NFT_EXTHDR_F_PRESENT {
		exp = fmt.Sprintf("%s %d", op, exthdr.Type)
	} else {
		exp = fmt.Sprintf("%s @%d,%d,%d", op, exthdr.Type, exthdr.Offset, exthdr.Len)
	}

	if exthdr.DestRegister != 0 {
		ctx.reg.Set(regID(exthdr.DestRegister),
			regVal{
				HumanExpr: exp,
				Expr:      exthdr,
			})
		return nil, ErrNoIR
	}

	if exthdr.SourceRegister != 0 {
		srcReg, ok := ctx.reg.Get(regID(exthdr.SourceRegister))
		if !ok {
			return nil, errors.Errorf("%T statement has no expression", exthdr)
		}
		rhs := srcReg.HumanExpr

		return simpleIR(fmt.Sprintf("%s set %s", exp, rhs)), nil
	}

	return simpleIR(fmt.Sprintf("reset %s", exp)), nil
}

func (b *exthdrEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	exthdr := b.extdhdr
	op := "exthdr"
	switch exthdr.Op {
	case expr.ExthdrOpTcpopt:
		op = "tcp option"
	case expr.ExthdrOpIpv6:
		op = "ip option"
	}

	hdr := map[string]interface{}{
		op: struct {
			Base   uint8  `json:"base"`
			Offset uint32 `json:"offset"`
			Len    uint32 `json:"len"`
		}{
			Base:   exthdr.Type,
			Offset: exthdr.Offset,
			Len:    exthdr.Len,
		},
	}

	if exthdr.DestRegister != 0 {
		ctx.reg.Set(regID(exthdr.DestRegister), regVal{Data: hdr})
		return nil, ErrNoJSON
	}

	if exthdr.SourceRegister != 0 {
		srcReg, ok := ctx.reg.Get(regID(exthdr.SourceRegister))
		if !ok || srcReg.Data == nil {
			return nil, errors.Errorf("%T statement has no expression", exthdr)
		}
		mangle := map[string]interface{}{
			"mangle": struct {
				Key any `json:"key"`
				Val any `json:"value"`
			}{
				Key: hdr,
				Val: srcReg.Data,
			},
		}
		return json.Marshal(mangle)
	}

	return json.Marshal(hdr)
}
