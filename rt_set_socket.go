package encoders

import (
	"fmt"
	"strings"

	"github.com/H-BF/corlib/pkg/dict"
	rb "github.com/Morwran/nft-go/internal/bytes"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
)

func init() {
	register(&expr.Rt{}, func(e expr.Any) encoder {
		return &rtEncoder{rt: e.(*expr.Rt)}
	})
}

type rtEncoder struct {
	rt *expr.Rt
}

func (b *rtEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	rt := b.rt
	if rt.Register == 0 {
		return nil, errors.Errorf("%T expression has invalid destination register %d", rt, rt.Register)
	}
	ctx.reg.Set(regID(rt.Register),
		regVal{
			HumanExpr: fmt.Sprintf("rt %s %s", RtKey(rt.Key).Family(), RtKey(rt.Key)),
		},
	)
	return nil, ErrNoIR
}

func (b *rtEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	rt := b.rt
	rtJson := map[string]interface{}{
		"rt": struct {
			Key    string `json:"key"`
			Family string `json:"family,omitempty"`
		}{
			Key:    RtKey(rt.Key).String(),
			Family: RtKey(rt.Key).Family(),
		},
	}

	if rt.Register == 0 {
		return nil, errors.Errorf("%T expression has invalid destination register %d", rt, rt.Register)
	}
	ctx.reg.Set(regID(rt.Register), regVal{Data: rtJson})
	return nil, ErrNoJSON
}

type RtKey expr.RtKey

func (r RtKey) String() string {
	switch expr.RtKey(r) {
	case expr.RtClassid:
		return "classid"
	case expr.RtNexthop4:
		return "nexthop"
	case expr.RtNexthop6:
		return "nexthop"
	case expr.RtTCPMSS:
		return "mtu"
	}
	return "unknown"
}

func (r RtKey) Family() string {
	switch expr.RtKey(r) {
	case expr.RtNexthop4:
		return "ip"
	case expr.RtNexthop6:
		return "ip6"
	}
	return ""
}

//set

type (
	setEncoder struct {
		set setEntry
	}
	setIR struct {
		setEntry
	}
)

func (s *setEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	return &setIR{setEntry: s.set}, nil
}

func (s *setIR) Format() string {
	if !s.Anonymous {
		return fmt.Sprintf("@%s", s.Name)
	}

	var b strings.Builder
	b.WriteByte('{')

	for i, e := range s.elems {
		b.WriteString(s.keyToString(e.Key))
		if i < len(s.elems)-1 {
			b.WriteByte(',')
		}
	}

	b.WriteByte('}')
	return b.String()
}

func (s *setIR) keyToString(k []byte) string {
	switch s.KeyType {
	case nftables.TypeVerdict,
		nftables.TypeString,
		nftables.TypeIFName:
		return rb.RawBytes(k).String()

	case nftables.TypeIPAddr,
		nftables.TypeIP6Addr:
		return rb.RawBytes(k).Ip().String()

	case nftables.TypeBitmask,
		nftables.TypeLLAddr,
		nftables.TypeEtherAddr,
		nftables.TypeTCPFlag,
		nftables.TypeMark,
		nftables.TypeUID,
		nftables.TypeGID:
		return rb.RawBytes(k).Text(rb.BaseHex)

	default:
		return rb.RawBytes(k).Text(rb.BaseDec)
	}
}

type (
	setCache struct {
		dict.HDict[setKey, setEntry]
	}
	setEntry struct {
		nftables.Set
		elems []nftables.SetElement
	}

	setKey struct {
		tableName string
		setName   string
		setId     uint32
	}
)

func (s *setCache) RefreshFromTable(t *nftables.Table) error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	defer func() { _ = conn.CloseLasting() }()
	sets, err := conn.GetSets(t)
	if err != nil {
		return err
	}
	for _, set := range sets {
		if set != nil {
			elems, err := conn.GetSetElements(set)
			if err != nil {
				return err
			}
			s.Put(setKey{
				tableName: set.Table.Name,
				setName:   set.Name,
				setId:     set.ID,
			}, setEntry{
				Set:   *set,
				elems: elems,
			})
		}
	}
	return nil
}

//socket

func init() {
	register(&expr.Socket{}, func(e expr.Any) encoder {
		return &socketEncoder{socket: e.(*expr.Socket)}
	})
}

type socketEncoder struct {
	socket *expr.Socket
}

func (b *socketEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	sb := strings.Builder{}
	sock := b.socket
	if sock.Register == 0 {
		return nil, errors.Errorf("%T expression has invalid destination register %d", sock, sock.Register)
	}
	sb.WriteString(fmt.Sprintf("socket %s", SocketKey(sock.Key)))
	if sock.Key == expr.SocketKeyCgroupv2 {
		sb.WriteString(fmt.Sprintf(" level %d", sock.Level))
	}
	ctx.reg.Set(regID(sock.Register), regVal{HumanExpr: sb.String(), Expr: sock})
	return nil, ErrNoIR
}

func (b *socketEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	sock := b.socket
	if sock.Register == 0 {
		return nil, errors.Errorf("%T expression has invalid destination register %d", sock, sock.Register)
	}
	sockJson := map[string]interface{}{
		"socket": struct {
			Key string `json:"omitempty"`
		}{
			SocketKey(sock.Key).String(),
		},
	}
	ctx.reg.Set(regID(sock.Register), regVal{Data: sockJson})
	return nil, ErrNoJSON
}

type SocketKey expr.SocketKey

func (s SocketKey) String() string {
	switch expr.SocketKey(s) {
	case expr.SocketKeyTransparent:
		return "transparent"
	case expr.SocketKeyMark:
		return "mark"
	case expr.SocketKeyWildcard:
		return "wildcard"
	case expr.SocketKeyCgroupv2:
		return "cgroupv2"
	}
	return "unknown"
}
