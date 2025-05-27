package encoders

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func init() {
	register(&expr.Exthdr{}, func(e expr.Any) encoder {
		return &exthdrEncoder{exthdr: e.(*expr.Exthdr)}
	})
}

type exthdrEncoder struct {
	exthdr *expr.Exthdr
}

// Функция преобразования type в строку
func exthdrTypeToString(t uint8) string {
	switch t {
	case 60:
		return "dst"
	case 0:
		return "hop"
	case 43:
		return "routing"
	case 44:
		return "frag"
	case 50:
		return "esp"
	case 51:
		return "auth"
	case 135:
		return "mh"
	default:
		return fmt.Sprint(t)
	}
}

func (b *exthdrEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	exthdr := b.exthdr
	op := "exthdr"

	// определяем строковый тип
	typ := exthdrTypeToString(exthdr.Type)
	exp := op + " " + typ

	// добавляем exists если стоит флаг
	var flagStrs []string
	if exthdr.Flags&unix.NFT_EXTHDR_F_PRESENT != 0 {
		flagStrs = append(flagStrs, "exists")
	}
	knownFlags := uint32(unix.NFT_EXTHDR_F_PRESENT)
	unknown := exthdr.Flags &^ knownFlags
	if unknown != 0 {
		flagStrs = append(flagStrs, fmt.Sprintf("flags=0x%x", unknown))
	}
	if len(flagStrs) > 0 {
		exp += " " + strings.Join(flagStrs, ",")
	}

	// если явно задан offset/len — выводим подробный exp
	if exthdr.Offset != 0 || exthdr.Len != 0 {
		exp = fmt.Sprintf("%s @%d,%d,%d", op, exthdr.Type, exthdr.Offset, exthdr.Len)
		if len(flagStrs) > 0 {
			exp += " " + strings.Join(flagStrs, ",")
		}
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

	return simpleIR(exp), nil
}

func (b *exthdrEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	exthdr := b.exthdr
	op := "exthdr"
	switch exthdr.Op {
	case expr.ExthdrOpTcpopt:
		op = "tcp option"
	case expr.ExthdrOpIpv6:
		op = "ip option"
	}

	hdr := map[string]interface{}{
		op: struct {
			Type   uint8  `json:"type"`
			Offset uint32 `json:"offset"`
			Len    uint32 `json:"len"`
			Flags  uint32 `json:"flags,omitempty"`
		}{
			Type:   exthdr.Type,
			Offset: exthdr.Offset,
			Len:    exthdr.Len,
			Flags:  exthdr.Flags,
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
