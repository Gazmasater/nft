package encoders

import (
	"encoding/json"
	"fmt"
	"strings"

	pr "github.com/Morwran/nft-go/pkg/protocols"
	"golang.org/x/sys/unix"

	nft "github.com/google/nftables"

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

//redirect

func init() {
	register(&expr.Redir{}, func(e expr.Any) encoder {
		return &redirectEncoder{redir: e.(*expr.Redir)}
	})
}

type redirectEncoder struct {
	redir *expr.Redir
}

func (b *redirectEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	nb := natEncoder{
		nat: &expr.NAT{
			Type:        NATTypeRedir,
			Persistent:  (b.redir.Flags & expr.NF_NAT_RANGE_PERSISTENT) != 0,
			Random:      (b.redir.Flags & expr.NF_NAT_RANGE_PROTO_RANDOM) != 0,
			FullyRandom: (b.redir.Flags & expr.NF_NAT_RANGE_PROTO_RANDOM_FULLY) != 0,
			RegProtoMin: b.redir.RegisterProtoMin,
			RegProtoMax: b.redir.RegisterProtoMax,
		},
	}

	return nb.EncodeIR(ctx)
}

func (b *redirectEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	nb := natEncoder{
		nat: &expr.NAT{
			Type:        NATTypeRedir,
			Persistent:  (b.redir.Flags & expr.NF_NAT_RANGE_PERSISTENT) != 0,
			Random:      (b.redir.Flags & expr.NF_NAT_RANGE_PROTO_RANDOM) != 0,
			FullyRandom: (b.redir.Flags & expr.NF_NAT_RANGE_PROTO_RANDOM_FULLY) != 0,
			RegProtoMin: b.redir.RegisterProtoMin,
			RegProtoMax: b.redir.RegisterProtoMax,
		},
	}

	return nb.EncodeJSON(ctx)
}

//registry

var registry = map[string]encoderFn{}

func register(e expr.Any, fn encoderFn) {
	registry[fmt.Sprintf("%T", e)] = fn
}

type (
	regID  uint32
	regVal struct {
		HumanExpr string
		Len       int
		Expr      expr.Any
		Data      any
		Op        string
	}
	regHolder struct {
		cache map[regID]regVal
	}
)

func (r *regHolder) Get(id regID) (regVal, bool) { v, ok := r.cache[id]; return v, ok }

func (r *regHolder) Set(id regID, v regVal) {
	r.ensureInit()
	r.cache[id] = v
}

func (r *regHolder) ensureInit() {
	if r.cache == nil {
		r.cache = make(map[regID]regVal)
	}
}

type ctx struct {
	reg  regHolder
	hdr  *pr.ProtoDescPtr
	sets setCache
	rule *nft.Rule
}

//reject

func init() {
	register(&expr.Reject{}, func(e expr.Any) encoder {
		return &rejectEncoder{reject: e.(*expr.Reject)}
	})
}

type (
	rejectEncoder struct {
		reject *expr.Reject
	}
	rejectIR struct {
		typeStr string
		code    uint8
	}
)

func (b *rejectEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	return &rejectIR{typeStr: b.TypeToString(), code: b.reject.Code}, nil
}

func (b *rejectEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	if b.TypeToString() == "" && b.reject.Code == 0 {
		return []byte(`{"reject":null}`), nil
	}

	reject := map[string]interface{}{
		"reject": struct {
			Type string `json:"type,omitempty"`
			Code uint8  `json:"expr,omitempty"`
		}{
			Type: b.TypeToString(),
			Code: b.reject.Code,
		},
	}

	return json.Marshal(reject)
}

func (b *rejectEncoder) TypeToString() string {
	switch b.reject.Type {
	case unix.NFT_REJECT_TCP_RST:
		return "tcp reset"
	case unix.NFT_REJECT_ICMPX_UNREACH:
		if b.reject.Code == unix.NFT_REJECT_ICMPX_PORT_UNREACH {
			break
		}
		return "icmpx"
	case unix.NFT_REJECT_ICMP_UNREACH:
		switch b.reject.Code {
		case unix.NFPROTO_IPV4:
			return "icmp"
		case unix.NFPROTO_IPV6:
			return "icmpv6"
		}
	}
	return ""
}

func (r *rejectIR) Format() string {
	sb := strings.Builder{}
	sb.WriteString("reject")
	if typ := r.typeStr; typ != "" {
		sb.WriteString(fmt.Sprintf(" with %s %d", typ, r.code))
	}
	return sb.String()
}
