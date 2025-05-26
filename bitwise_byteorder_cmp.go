package encoders

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"

	rb "github.com/Morwran/nft-go/internal/bytes"
	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

//bitwise

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

//byteorder

func init() {
	register(&expr.Byteorder{}, func(e expr.Any) encoder {
		return &byteorderEncoder{bo: e.(*expr.Byteorder)}
	})
}

type (
	ByteorderOp expr.ByteorderOp

	byteorderEncoder struct {
		bo *expr.Byteorder
	}
)

func (b ByteorderOp) String() string {
	switch expr.ByteorderOp(b) {
	case expr.ByteorderNtoh:
		return "ntoh"
	case expr.ByteorderHton:
		return "hton"
	}
	return ""
}

func (b *byteorderEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	bo := b.bo
	srcReg, ok := ctx.reg.Get(regID(bo.SourceRegister))
	if !ok {
		return nil, errors.Errorf("%T expression has no left hand side", bo)
	}
	op := ByteorderOp(bo.Op).String()
	if op == "" {
		return nil, errors.Errorf("invalid byteorder operation: %d", bo.Op)
	}
	if bo.DestRegister == unix.NFT_REG_VERDICT {
		return nil, errors.Errorf("invalid destination register %d", bo.DestRegister)
	}
	ctx.reg.Set(regID(bo.DestRegister), regVal{
		HumanExpr: srcReg.HumanExpr,
		Expr:      bo,
		Len:       srcReg.Len,
		Op:        op,
	})
	return nil, ErrNoIR
}

func (b *byteorderEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	bo := b.bo
	srcReg, ok := ctx.reg.Get(regID(bo.SourceRegister))
	if !ok {
		return nil, errors.Errorf("%T expression has no left hand side", bo)
	}

	op := ByteorderOp(bo.Op).String()
	if op == "" {
		return nil, errors.Errorf("invalid byteorder operation: %d", bo.Op)
	}

	if bo.DestRegister == unix.NFT_REG_VERDICT {
		return nil, errors.Errorf("invalid destination register %d", bo.DestRegister)
	}

	ctx.reg.Set(regID(bo.DestRegister), regVal{
		Expr: srcReg.Expr,
		Data: srcReg.Data,
		Len:  srcReg.Len,
		Op:   op,
	})

	return nil, ErrNoJSON
}

//cmp

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
