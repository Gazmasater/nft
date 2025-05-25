package encoders

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

var containExpressionRe = regexp.MustCompile(`[()&|^<>]`)

func init() {
	register(&expr.Lookup{}, func(e expr.Any) encoder {
		return &lookupEncoder{lookup: e.(*expr.Lookup)}
	})
}

type (
	lookupEncoder struct {
		lookup *expr.Lookup
	}
	lookupIR struct {
		left, right string
		invert      bool
	}
)

func (b *lookupEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	lk := b.lookup
	if ctx.rule == nil {
		return nil, errors.New("ctx has no rule")
	}
	set, ok := ctx.sets.Get(setKey{
		tableName: ctx.rule.Table.Name,
		setName:   lk.SetName,
		setId:     lk.SetID,
	})
	if !ok {
		if err := ctx.sets.RefreshFromTable(ctx.rule.Table); err != nil {
			return nil, err
		}
		if set, ok = ctx.sets.Get(setKey{
			tableName: ctx.rule.Table.Name,
			setName:   lk.SetName,
			setId:     lk.SetID,
		}); !ok {
			return nil, fmt.Errorf("set %s not found", lk.SetName)
		}
	}
	srcReg, ok := ctx.reg.Get(regID(lk.SourceRegister))
	if !ok {
		return nil, fmt.Errorf("%T expression has no left hand side", lk)
	}
	left := srcReg.HumanExpr
	setB := &setEncoder{set: set}
	sIR, err := setB.EncodeIR(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build IR for set: %w", err)
	}
	right := sIR.Format()

	if lk.IsDestRegSet {
		mType := "vmap"
		if lk.DestRegister != unix.NFT_REG_VERDICT {
			mType = "map"
			ctx.reg.Set(regID(lk.DestRegister), regVal{
				HumanExpr: fmt.Sprintf("%s %s %s", left, mType, right),
			})
			return nil, ErrNoIR
		}
		return simpleIR(fmt.Sprintf("%s %s %s", left, mType, right)), nil
	}
	return &lookupIR{left: left, right: right, invert: lk.Invert}, nil
}

func (b *lookupEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	lk := b.lookup
	srcReg, ok := ctx.reg.Get(regID(lk.SourceRegister))
	if !ok {
		return nil, fmt.Errorf("%T expression has no left hand side", lk)
	}
	setName := fmt.Sprintf(`@%s`, lk.SetName)
	if lk.IsDestRegSet {
		mapExp := struct {
			Key  any    `json:"key"`
			Data string `json:"data"`
		}{
			Key:  srcReg.Data,
			Data: setName,
		}

		if lk.DestRegister != unix.NFT_REG_VERDICT {
			m := map[string]interface{}{
				"map": mapExp,
			}
			ctx.reg.Set(regID(lk.DestRegister), regVal{Data: m})
			return nil, ErrNoJSON
		}
		m := map[string]interface{}{
			"vmap": mapExp,
		}
		return json.Marshal(m)
	}
	op := expr.CmpOpEq
	if lk.Invert {
		op = expr.CmpOpNeq
	}
	match := map[string]interface{}{
		"match": struct {
			Op    string `json:"op"`
			Left  any    `json:"left"`
			Right any    `json:"right"`
		}{
			Op:    CmpOp(op).String(),
			Left:  srcReg.Data,
			Right: setName,
		},
	}
	return json.Marshal(match)
}

func (l *lookupIR) Format() string {
	left := l.left
	right := l.right
	if containExpressionRe.MatchString(left) {
		op := CmpOp(expr.CmpOpEq)
		if l.invert {
			op = CmpOp(expr.CmpOpNeq)
		}
		left = fmt.Sprintf("(%s) %s", left, op)
	}

	return fmt.Sprintf("%s %s", left, right)
}
