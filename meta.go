package encoders

import (
	"encoding/json"
	"fmt"

	rb "github.com/Morwran/nft-go/internal/bytes"
	pr "github.com/Morwran/nft-go/pkg/protocols"

	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
)

func init() {
	register(&expr.Meta{}, func(e expr.Any) encoder {
		return &metaEncoder{meta: e.(*expr.Meta)}
	})
}

type (
	metaEncoder struct {
		meta *expr.Meta
	}

	metaIR struct {
		key MetaKey
		exp string
	}

	MetaKey expr.MetaKey
)

func (b *metaEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	meta := b.meta
	metaKey := MetaKey(meta.Key)
	metaExpr := metaKey.String()
	if !metaKey.IsUnqualified() {
		metaExpr = fmt.Sprintf("meta %s", metaKey)
	}
	if !meta.SourceRegister {
		if meta.Register == 0 {
			return nil, errors.Errorf("%T expression has invalid destination register %d", meta, meta.Register)
		}

		ctx.reg.Set(regID(meta.Register),
			regVal{
				HumanExpr: metaExpr,
				Expr:      meta,
			})
		return nil, ErrNoIR
	}
	srcReg, ok := ctx.reg.Get(regID(meta.Register))
	if !ok {
		return nil, errors.Errorf("%T statement has no expression", meta)
	}
	metaExpr = srcReg.HumanExpr

	switch t := srcReg.Expr.(type) {
	case *expr.Immediate:
		metaExpr = b.metaDataToString(t.Data)
	}

	return &metaIR{key: metaKey, exp: metaExpr}, nil
}

func (b *metaEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	meta := b.meta
	metaJson := map[string]interface{}{
		"meta": struct {
			Key string `json:"key"`
		}{
			Key: MetaKey(meta.Key).String(),
		},
	}
	if !meta.SourceRegister {
		if meta.Register == 0 {
			return nil, errors.Errorf("%T expression has invalid destination register %d", meta, meta.Register)
		}
		ctx.reg.Set(
			regID(meta.Register),
			regVal{
				Data: metaJson,
				Expr: meta,
			})
		return nil, ErrNoJSON
	}

	srcReg, ok := ctx.reg.Get(regID(meta.Register))
	if !ok {
		return nil, errors.Errorf("%T statement has no expression", meta)
	}

	mangle := map[string]interface{}{
		"mangle": struct {
			Key any `json:"key"`
			Val any `json:"value"`
		}{
			Key: metaJson,
			Val: srcReg.Data,
		},
	}

	return json.Marshal(mangle)
}

func (b *metaEncoder) buildFromCmpData(ctx *ctx, cmp *expr.Cmp) (res string) {
	var protos pr.ProtoTypeHolder
	switch b.meta.Key {
	case expr.MetaKeyL4PROTO, expr.MetaKeyPROTOCOL:
		protos = pr.Protocols[expr.PayloadBaseTransportHeader]
	case expr.MetaKeyNFPROTO:
		protos = pr.Protocols[expr.PayloadBaseNetworkHeader]
	}

	res = b.metaDataToString(cmp.Data)

	if proto, ok := protos[pr.ProtoType(int(rb.RawBytes(cmp.Data).Uint64()))]; ok { //nolint:gosec
		res = proto.Name
		*ctx.hdr = &proto
	}
	return res
}

func (b *metaEncoder) metaDataToString(data []byte) string {
	switch b.meta.Key {
	case expr.MetaKeyIIFNAME,
		expr.MetaKeyOIFNAME,
		expr.MetaKeyBRIIIFNAME,
		expr.MetaKeyBRIOIFNAME:
		return rb.RawBytes(data).String()
	case expr.MetaKeyPROTOCOL, expr.MetaKeyNFPROTO, expr.MetaKeyL4PROTO:
		proto := pr.ProtoType(int(rb.RawBytes(data).Uint64())).String() //nolint:gosec

		return proto
	default:
		return rb.RawBytes(data).Text(rb.BaseDec)
	}
}

func (m *metaIR) Format() (res string) {
	metaExpr := fmt.Sprintf("%s set %s", m.key, m.exp)
	if !m.key.IsUnqualified() {
		metaExpr = fmt.Sprintf("meta %s set %s", m.key, m.exp)
	}
	return metaExpr
}

func (m MetaKey) String() string {
	switch expr.MetaKey(m) {
	case expr.MetaKeyLEN:
		return "length"
	case expr.MetaKeyPROTOCOL:
		return "protocol"
	case expr.MetaKeyPRIORITY:
		return "priority"
	case expr.MetaKeyMARK:
		return "mark"
	case expr.MetaKeyIIF:
		return "iif"
	case expr.MetaKeyOIF:
		return "oif"
	case expr.MetaKeyIIFNAME:
		return "iifname"
	case expr.MetaKeyOIFNAME:
		return "oifname"
	case expr.MetaKeyIIFTYPE:
		return "iiftype"
	case expr.MetaKeyOIFTYPE:
		return "oiftype"
	case expr.MetaKeySKUID:
		return "skuid"
	case expr.MetaKeySKGID:
		return "skgid"
	case expr.MetaKeyNFTRACE:
		return "nftrace"
	case expr.MetaKeyRTCLASSID:
		return "rtclassid"
	case expr.MetaKeySECMARK:
		return "secmark"
	case expr.MetaKeyNFPROTO:
		return "nfproto"
	case expr.MetaKeyL4PROTO:
		return "l4proto"
	case expr.MetaKeyBRIIIFNAME:
		return "ibrname"
	case expr.MetaKeyBRIOIFNAME:
		return "obrname"
	case expr.MetaKeyPKTTYPE:
		return "pkttype"
	case expr.MetaKeyCPU:
		return "cpu"
	case expr.MetaKeyIIFGROUP:
		return "iifgroup"
	case expr.MetaKeyOIFGROUP:
		return "oifgroup"
	case expr.MetaKeyCGROUP:
		return "cgroup"
	case expr.MetaKeyPRANDOM:
		return "random"
	}
	return "unknown"
}

func (m MetaKey) IsUnqualified() bool {
	switch expr.MetaKey(m) {
	case expr.MetaKeyIIF,
		expr.MetaKeyOIF,
		expr.MetaKeyIIFNAME,
		expr.MetaKeyOIFNAME,
		expr.MetaKeyIIFGROUP,
		expr.MetaKeyOIFGROUP:
		return true
	default:
		return false
	}
}
