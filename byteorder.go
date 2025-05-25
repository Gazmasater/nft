package encoders

import (
	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

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
