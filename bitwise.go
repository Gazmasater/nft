package encoders

import (
	"fmt"
	"math/big"
	"regexp"

	rb "github.com/Morwran/nft-go/internal/bytes"
	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func init() {
	register(&expr.Bitwise{}, func(e expr.Any) encoder {
		return &bitwiseEncoder{bitwise: e.(*expr.Bitwise)}
	})
}

type (
	bitwiseEncoder struct {
		bitwise *expr.Bitwise
	}
)

func (b *bitwiseEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	var human string
	bw := b.bitwise
	if bw.DestRegister == unix.NFT_REG_VERDICT {
		return nil, fmt.Errorf("bitwise: invalid dest register %d", bw.DestRegister)
	}

	src, ok := ctx.reg.Get(regID(bw.SourceRegister))
	if !ok {
		return nil, fmt.Errorf("bitwise: source reg %d empty", bw.SourceRegister)
	}

	mask, xor, or := evalBitwise(bw.Mask, bw.Xor, int(bw.Len))

	switch t := src.Expr.(type) {
	case *expr.Ct:
		ctBuilder := &ctEncoder{t}
		human = ctBuilder.buildCtWithMask(src.HumanExpr, bw.Mask)
	case *expr.Payload:
		plBuilder := &payloadEncoder{t}
		human = plBuilder.buildPlWithMask(ctx, bw.Mask)
	default:
		human = buildBitwiseExpr(src.HumanExpr, mask, xor, or)
	}

	ctx.reg.Set(regID(bw.DestRegister), regVal{
		HumanExpr: human,
		Len:       src.Len,
		Expr:      bw,
	})
	return nil, ErrNoIR
}

func (b *bitwiseEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	type exprCmp struct {
		Op    string `json:"op"`
		Left  any    `json:"left"`
		Right any    `json:"right"`
	}
	bw := b.bitwise
	srcReg, ok := ctx.reg.Get(regID(bw.SourceRegister))
	if !ok {
		return nil, errors.Errorf("%T expression has no left side", bw)
	}

	if bw.DestRegister == unix.NFT_REG_VERDICT {
		return nil, errors.Errorf("%T expression has invalid destination register %d", bw, bw.DestRegister)
	}

	mask, xor, or := evalBitwise(bw.Mask, bw.Xor, int(bw.Len))

	exp := srcReg.Data

	if !(srcReg.Len > 0 && scan0(mask, 0) >= srcReg.Len) {
		exp = exprCmp{
			Op:    LogicAND.String(),
			Left:  exp,
			Right: mask.Uint64(),
		}
	}

	if xor.Uint64() != 0 {
		exp = exprCmp{
			Op:    LogicXOR.String(),
			Left:  exp,
			Right: xor.Uint64(),
		}
	}

	if or.Uint64() != 0 {
		exp = exprCmp{
			Op:    LogicOR.String(),
			Left:  exp,
			Right: or.Uint64(),
		}
	}

	ctx.reg.Set(regID(bw.DestRegister), regVal{
		Data: exp,
		Len:  srcReg.Len,
	})

	return nil, ErrNoJSON
}

func (b *bitwiseEncoder) buildFromCmpData(ctx *ctx, cmp *expr.Cmp) (res string) {
	if rb.RawBytes(cmp.Data).Uint64() != 0 {
		res = fmt.Sprintf("0x%s", rb.RawBytes(cmp.Data).Text(rb.BaseHex))
	}
	hdrDesc := *ctx.hdr
	if hdrDesc != nil {
		if desc, ok := hdrDesc.Offsets[hdrDesc.CurrentOffset]; ok {
			res = desc.Desc(cmp.Data)
		}
	}
	return res
}

func evalBitwise(maskB, xorB []byte, length int) (mask, xor, or *big.Int) {
	mask = new(big.Int).SetBytes(maskB)
	xor = new(big.Int).SetBytes(xorB)
	or = big.NewInt(0)

	if scan0(mask, 0) != length || xor.Uint64() != 0 {
		or = new(big.Int).And(mask, xor)
		or = new(big.Int).Xor(or, xor)
		xor = new(big.Int).And(xor, mask)
		mask = new(big.Int).Or(mask, or)
	}
	return
}

func buildBitwiseExpr(base string, mask, xor, or *big.Int) string {
	needPar := regexp.MustCompile(`[()&|^<> ]`).MatchString
	cur := base

	if !(scan0(mask, 0) >= len(base)) {
		if needPar(cur) {
			cur = fmt.Sprintf("(%s)", cur)
		}
		cur = fmt.Sprintf("%s & 0x%x", cur, mask)
	}
	if xor.Uint64() != 0 {
		if needPar(cur) {
			cur = fmt.Sprintf("(%s)", cur)
		}
		cur = fmt.Sprintf("%s ^ 0x%x", cur, xor)
	}
	if or.Uint64() != 0 {
		if needPar(cur) {
			cur = fmt.Sprintf("(%s)", cur)
		}
		cur = fmt.Sprintf("%s | 0x%x", cur, or)
	}
	return cur
}

const (
	LogicAND LogicOp = iota
	LogicOR
	LogicXOR
	LogicLShift
	LogicRShift
)

type (
	LogicOp    uint32
	BitwiseOps uint32
)

func (l LogicOp) String() string {
	switch l {
	case LogicAND:
		return "&"
	case LogicOR:
		return "|"
	case LogicXOR:
		return "^"
	case LogicLShift:
		return "<<"
	case LogicRShift:
		return ">>"
	}
	return ""
}

func scan0(x *big.Int, start int) int {
	for i := start; i < x.BitLen(); i++ {
		if x.Bit(i) == 0 {
			return i
		}
	}
	return -1
}
