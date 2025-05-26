package encoders

import (
	"encoding/json"
	"fmt"
	"strings"

	pr "github.com/Morwran/nft-go/pkg/protocols"
	"golang.org/x/sys/unix"

	rb "github.com/Morwran/nft-go/internal/bytes"
	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
)

func init() {
	register(&expr.Masq{}, func(e expr.Any) encoder {
		return &masqEncoder{masq: e.(*expr.Masq)}
	})
}

type masqEncoder struct {
	masq *expr.Masq
}

func (b *masqEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	nb := natEncoder{
		nat: &expr.NAT{
			Type:        NATTypeMASQ,
			Persistent:  b.masq.Persistent,
			Random:      b.masq.Random,
			FullyRandom: b.masq.FullyRandom,
			RegProtoMin: b.masq.RegProtoMin,
			RegProtoMax: b.masq.RegProtoMax,
		},
	}

	return nb.EncodeIR(ctx)
}

func (b *masqEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	nb := natEncoder{
		nat: &expr.NAT{
			Type:        NATTypeMASQ,
			Persistent:  b.masq.Persistent,
			Random:      b.masq.Random,
			FullyRandom: b.masq.FullyRandom,
			RegProtoMin: b.masq.RegProtoMin,
			RegProtoMax: b.masq.RegProtoMax,
		},
	}
	return nb.EncodeJSON(ctx)
}

//match

func init() {
	register(&expr.Match{}, func(e expr.Any) encoder {
		return &matchEncoder{match: e.(*expr.Match)}
	})
}

type matchEncoder struct {
	match *expr.Match
}

func (b *matchEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	return simpleIR(fmt.Sprintf(`xt match %q`, b.match.Name)), nil
}

func (b *matchEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	return []byte(fmt.Sprintf(`{"xt":{"type":"match","name":%q}}`, b.match.Name)), nil
}

//meta

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

//nat

func init() {
	register(&expr.NAT{}, func(e expr.Any) encoder {
		return &natEncoder{nat: e.(*expr.NAT)}
	})
}

const (
	NATTypeMASQ expr.NATType = iota + unix.NFT_NAT_DNAT + 1
	NATTypeRedir
)

type (
	natEncoder struct {
		nat *expr.NAT
	}

	natIR struct {
		*expr.NAT
		addr  string
		port  string
		flags []string
	}

	NATType expr.NATType
)

func (b *natEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	var addr, port string
	nat := b.nat
	if nat.RegAddrMin != 0 {
		addrMinExpr, ok := ctx.reg.Get(regID(nat.RegAddrMin))
		if !ok {
			return nil, errors.Errorf("%T statement has no address expression", nat)
		}
		addr = addrMinExpr.HumanExpr

		if nat.Family == unix.NFPROTO_IPV6 {
			if nat.Family == unix.NFPROTO_IPV6 {
				addr = fmt.Sprintf("[%s]", addr)
			}
		}
	}
	if nat.RegAddrMax != 0 && nat.RegAddrMax != nat.RegAddrMin {
		addrMaxExpr, ok := ctx.reg.Get(regID(nat.RegAddrMax))
		if !ok {
			return nil, errors.Errorf("%T statement has no address expression", nat)
		}
		if addr == "" {
			addr = addrMaxExpr.HumanExpr
			if nat.Family == unix.NFPROTO_IPV6 {
				if nat.Family == unix.NFPROTO_IPV6 {
					addr = fmt.Sprintf("[%s]", addr)
				}
			}
		} else {
			addrMax := addrMaxExpr.HumanExpr
			if addrMax != "" {
				addr = fmt.Sprintf("%s-%s", addr, addrMax)
			}
			if nat.Family == unix.NFPROTO_IPV6 {
				addr = fmt.Sprintf("%s-[%s]", addr, addrMax)
			}
		}
	}
	if nat.RegProtoMin != 0 {
		portMinExpr, ok := ctx.reg.Get(regID(nat.RegProtoMin))
		if !ok {
			return nil, errors.Errorf("%T statement has no port expression", nat)
		}
		port = portMinExpr.HumanExpr
	}
	if nat.RegProtoMax != 0 && nat.RegProtoMax != nat.RegProtoMin {
		portMaxExpr, ok := ctx.reg.Get(regID(nat.RegProtoMax))
		if !ok {
			return nil, errors.Errorf("%T statement has no port expression", nat)
		}
		if port == "" {
			port = portMaxExpr.HumanExpr
		} else {
			portMax := portMaxExpr.HumanExpr
			if portMax != "" {
				port = fmt.Sprintf("%s-%s", port, portMax)
			}
		}
	}
	return &natIR{NAT: nat, addr: addr, port: port, flags: b.Flags()}, nil
}

func (b *natEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	var (
		flag       any
		family     string
		addr, port any
		nat        = b.nat
	)
	flags := b.Flags()

	if len(flags) > 1 {
		flag = flags
	} else if len(flags) == 1 {
		flag = flags[0]
	}

	if nat.Family == unix.NFPROTO_IPV4 || nat.Family == unix.NFPROTO_IPV6 {
		family = b.FamilyToString()
	}
	if nat.RegAddrMin != 0 {
		addrMinExpr, ok := ctx.reg.Get(regID(nat.RegAddrMin))
		if !ok {
			return nil, errors.Errorf("%T statement has no address expression", nat)
		}
		addr = addrMinExpr.Data
	}

	if nat.RegAddrMax != 0 && nat.RegAddrMax != nat.RegAddrMin {
		addrMaxExpr, ok := ctx.reg.Get(regID(nat.RegAddrMax))
		if !ok || addrMaxExpr.Data == nil {
			return nil, errors.Errorf("%T statement has no address expression", nat)
		}
		if addr == nil {
			addr = addrMaxExpr.Data
		} else {
			addr = map[string]interface{}{
				"range": [2]any{addr, addrMaxExpr.Data},
			}
		}
	}

	if nat.RegProtoMin != 0 {
		portMinExpr, ok := ctx.reg.Get(regID(nat.RegProtoMin))
		if !ok || portMinExpr.Data == nil {
			return nil, errors.Errorf("%T statement has no port expression", nat)
		}
		port = portMinExpr.Data
	}

	if nat.RegProtoMax != 0 && nat.RegProtoMax != nat.RegProtoMin {
		portMaxExpr, ok := ctx.reg.Get(regID(nat.RegProtoMax))
		if !ok || portMaxExpr.Data == nil {
			return nil, errors.Errorf("%T statement has no port expression", nat)
		}
		if port == nil {
			port = portMaxExpr.Data
		} else {
			port = map[string]interface{}{
				"range": [2]any{port, portMaxExpr.Data},
			}
		}
	}

	natJson := map[string]interface{}{
		NATType(nat.Type).String(): struct {
			Family string `json:"family,omitempty"`
			Addr   any    `json:"addr,omitempty"`
			Port   any    `json:"port,omitempty"`
			Flags  any    `json:"flags,omitempty"`
		}{
			Family: family,
			Addr:   addr,
			Port:   port,
			Flags:  flag,
		},
	}

	return json.Marshal(natJson)
}

func (b *natEncoder) FamilyToString() string {
	switch b.nat.Family {
	case unix.NFPROTO_IPV4:
		return "ip" //nolint:goconst
	case unix.NFPROTO_IPV6:
		return "ip6" //nolint:goconst
	case unix.NFPROTO_INET:
		return "inet"
	case unix.NFPROTO_NETDEV:
		return "netdev"
	case unix.NFPROTO_ARP:
		return "arp"
	case unix.NFPROTO_BRIDGE:
		return "bridge"
	}
	return ""
}

func (b *natEncoder) Flags() (flags []string) {
	if b.nat.Random {
		flags = append(flags, "random")
	}
	if b.nat.FullyRandom {
		flags = append(flags, "fully-random")
	}
	if b.nat.Persistent {
		flags = append(flags, "persistent")
	}
	return flags
}

func (n *natIR) Format() string {
	sb := strings.Builder{}
	sb.WriteString(NATType(n.Type).String())

	if n.addr != "" || n.port != "" {
		switch n.Family {
		case unix.NFPROTO_IPV4:
			sb.WriteString(" ip")
		case unix.NFPROTO_IPV6:
			sb.WriteString(" ip6")
		}
		sb.WriteString(" to")
	}
	if n.addr != "" {
		sb.WriteString(fmt.Sprintf(" %s", n.addr))
	}
	if n.port != "" {
		if n.addr == "" {
			sb.WriteByte(' ')
		}
		sb.WriteString(fmt.Sprintf(":%s", n.port))
	}

	if len(n.flags) > 0 {
		sb.WriteString(fmt.Sprintf(" %s", strings.Join(n.flags, " ")))
	}
	return sb.String()
}

func (n NATType) String() string {
	switch expr.NATType(n) {
	case expr.NATTypeSourceNAT:
		return "snat"
	case expr.NATTypeDestNAT:
		return "dnat"
	case NATTypeMASQ:
		return "masquerade"
	case NATTypeRedir:
		return "redirect"
	}
	return "unknown"
}

//notrack

func init() {
	register(&expr.Notrack{}, func(e expr.Any) encoder {
		return &notrackEncoder{notrack: e.(*expr.Notrack)}
	})
}

type notrackEncoder struct {
	notrack *expr.Notrack
}

func (b *notrackEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	return simpleIR("notrack"), nil
}

func (b *notrackEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	return []byte(`{"notrack":null}`), nil
}
