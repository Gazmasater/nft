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
