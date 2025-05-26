package encoders

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

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

//fib

func init() {
	register(&expr.Fib{}, func(e expr.Any) encoder {
		return &fibEncoder{fib: e.(*expr.Fib)}
	})
}

type fibEncoder struct {
	fib *expr.Fib
}

func (b *fibEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	fib := b.fib
	if fib.Register == 0 {
		return nil, errors.Errorf("%T expression has invalid destination register %d", fib, fib.Register)
	}
	ctx.reg.Set(regID(fib.Register),
		regVal{
			HumanExpr: fmt.Sprintf("fib %s %s", strings.Join(b.FlagsToString(), ", "), b.ResultToString()),
			Expr:      fib,
		})
	return nil, ErrNoIR
}
func (b *fibEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	fib := map[string]interface{}{
		"fib": struct {
			Result string   `json:"result"`
			Flags  []string `json:"flags"`
		}{
			Result: b.ResultToString(),
			Flags:  b.FlagsToString(),
		},
	}
	if b.fib.Register == 0 {
		return nil, errors.Errorf("%T expression has invalid destination register %d", b.fib, b.fib.Register)
	}
	ctx.reg.Set(regID(b.fib.Register), regVal{Data: fib})
	return nil, ErrNoJSON
}

func (b *fibEncoder) ResultToString() string {
	f := b.fib
	if f.ResultOIF {
		return "oif"
	}
	if f.ResultOIFNAME {
		return "oifname"
	}
	if f.ResultADDRTYPE {
		return "type"
	}
	return "unknown"
}

func (b *fibEncoder) FlagsToString() (flags []string) {
	f := b.fib
	if f.FlagSADDR {
		flags = append(flags, "saddr")
	}
	if f.FlagDADDR {
		flags = append(flags, "daddr")
	}
	if f.FlagMARK {
		flags = append(flags, "mark")
	}
	if f.FlagIIF {
		flags = append(flags, "iif")
	}
	if f.FlagOIF {
		flags = append(flags, "oif")
	}
	return flags
}

//flow_offload

func init() {
	register(&expr.FlowOffload{}, func(e expr.Any) encoder {
		return &flowOffloadEncoder{flowOffload: e.(*expr.FlowOffload)}
	})
}

type flowOffloadEncoder struct {
	flowOffload *expr.FlowOffload
}

func (b *flowOffloadEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	f := b.flowOffload
	return simpleIR(fmt.Sprintf("flow add @%s", f.Name)), nil
}

func (b *flowOffloadEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	f := b.flowOffload
	return []byte(fmt.Sprintf(`{"flow":{"op":"add","flowtable":%q}}`, f.Name)), nil
}

//hash

func init() {
	register(&expr.Hash{}, func(e expr.Any) encoder {
		return &hashEncoder{hash: e.(*expr.Hash)}
	})
}

type hashEncoder struct {
	hash *expr.Hash
}

func (b *hashEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	var exp string
	sb := strings.Builder{}
	hash := b.hash
	sb.WriteString("symhash")
	if hash.Type != expr.HashTypeSym {
		srcReg, ok := ctx.reg.Get(regID(hash.SourceRegister))
		if !ok {
			return nil, errors.Errorf("%T statement has no expression", hash)
		}
		exp = srcReg.HumanExpr

		sb.WriteString(fmt.Sprintf("jhash %s", exp))
	}
	sb.WriteString(fmt.Sprintf(" mod %d seed 0x%x", hash.Modulus, hash.Seed))
	if hash.Offset > 0 {
		sb.WriteString(fmt.Sprintf(" offset %d", hash.Offset))
	}

	if hash.DestRegister == 0 {
		return nil, errors.Errorf("%T expression has invalid destination register %d", hash, hash.DestRegister)
	}

	ctx.reg.Set(regID(hash.DestRegister),
		regVal{
			Expr:      hash,
			HumanExpr: sb.String(),
		})

	return nil, ErrNoIR
}

func (b *hashEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	var exp any
	hash := b.hash
	if hash.Type != expr.HashTypeSym {
		srcReg, ok := ctx.reg.Get(regID(hash.SourceRegister))
		if !ok || srcReg.Data == nil {
			return nil, errors.Errorf("%T statement has no expression", hash)
		}
		exp = srcReg.Data
	}

	hashJson := map[string]interface{}{
		HashType(hash.Type).String(): struct {
			Mod    uint32 `json:"mod,omitempty"`
			Seed   uint32 `json:"seed,omitempty"`
			Offset uint32 `json:"offset,omitempty"`
			Expr   any    `json:"expr,omitempty"`
		}{
			Mod:    hash.Modulus,
			Seed:   hash.Seed,
			Offset: hash.Offset,
			Expr:   exp,
		},
	}

	if hash.DestRegister == 0 {
		return nil, errors.Errorf("%T expression has invalid destination register %d", hash, hash.DestRegister)
	}

	ctx.reg.Set(regID(hash.DestRegister),
		regVal{
			Data: hashJson,
		})
	return nil, ErrNoJSON
}

type HashType expr.HashType

func (h HashType) String() string {
	if h == HashType(expr.HashTypeSym) {
		return "symhash"
	}
	return "jhash"
}

//lookup

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
