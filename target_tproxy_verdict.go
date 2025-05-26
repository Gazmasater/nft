//nolint:dupl
package encoders

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func init() {
	register(&expr.Target{}, func(e expr.Any) encoder {
		return &targetEncoder{target: e.(*expr.Target)}
	})
}

type targetEncoder struct {
	target *expr.Target
}

func (b *targetEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	return simpleIR(fmt.Sprintf(`xt target %q`, b.target.Name)), nil
}

func (b *targetEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	return []byte(fmt.Sprintf(`{"xt":{"type":"target","name":%q}}`, b.target.Name)), nil
}

//tproxy

func init() {
	register(&expr.TProxy{}, func(e expr.Any) encoder {
		return &tproxyEncoder{tproxy: e.(*expr.TProxy)}
	})
}

type (
	tproxyEncoder struct {
		tproxy *expr.TProxy
	}
	tproxyIR struct {
		*expr.TProxy
		addr, port string
	}

	Family byte
)

func (b *tproxyEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	addrExpr, _ := ctx.reg.Get(regID(b.tproxy.RegAddr))
	portExpr, _ := ctx.reg.Get(regID(b.tproxy.RegPort))

	return &tproxyIR{TProxy: b.tproxy, addr: addrExpr.HumanExpr, port: portExpr.HumanExpr}, nil
}

func (b *tproxyEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	tp := b.tproxy
	addrExpr, _ := ctx.reg.Get(regID(tp.RegAddr))
	portExpr, _ := ctx.reg.Get(regID(tp.RegPort))
	root := struct {
		Family string `json:"op,omitempty"`
		Addr   any    `json:"addr,omitempty"`
		Port   any    `json:"port,omitempty"`
	}{
		Addr: addrExpr.Data,
		Port: portExpr.Data,
	}
	if tp.TableFamily == unix.NFPROTO_INET && tp.Family != unix.NFPROTO_UNSPEC {
		root.Family = Family(tp.Family).String()
	}
	tproxy := map[string]interface{}{
		"tproxy": root,
	}

	return json.Marshal(tproxy)
}

func (t *tproxyIR) Format() string {
	sb := strings.Builder{}
	sb.WriteString("tproxy")
	if t.TableFamily == unix.NFPROTO_INET && t.Family != unix.NFPROTO_UNSPEC {
		sb.WriteString(fmt.Sprintf(" %s", Family(t.Family)))
	}
	sb.WriteString(" to")
	if t.addr != "" {
		if t.Family == unix.NFPROTO_IPV6 {
			if t.Family == unix.NFPROTO_IPV6 {
				t.addr = fmt.Sprintf("[%s]", t.addr)
			}
		}
		sb.WriteString(fmt.Sprintf(" %s", t.addr))
	}
	if t.port != "" {
		if t.addr == " " {
			sb.WriteByte(' ')
		}
		sb.WriteString(fmt.Sprintf(":%s", t.port))
	}
	return sb.String()
}

func (t Family) String() string {
	switch t {
	case unix.NFPROTO_IPV4:
		return "ip"
	case unix.NFPROTO_IPV6:
		return "ip6"
	case unix.NFPROTO_INET:
		return "inet"
	case unix.NFPROTO_NETDEV:
		return "netdev"
	case unix.NFPROTO_ARP:
		return "arp"
	case unix.NFPROTO_BRIDGE:
		return "bridge"
	}
	return "unknown"
}

//verdict

func init() {
	register(&expr.Verdict{}, func(e expr.Any) encoder {
		return &verdictEncoder{verdict: e.(*expr.Verdict)}
	})
}

type verdictEncoder struct {
	verdict *expr.Verdict
}

func (b *verdictEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	verdict := b.verdict
	if verdict.Chain == "" {
		return simpleIR(VerdictKind(verdict.Kind).String()), nil
	}
	return simpleIR(fmt.Sprintf("%s %s", VerdictKind(verdict.Kind).String(), verdict.Chain)), nil
}

func (b *verdictEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	verdict := b.verdict
	if verdict.Chain == "" {
		return []byte(fmt.Sprintf(`{%q:null}`, VerdictKind(verdict.Kind).String())), nil
	}
	return []byte(fmt.Sprintf(`{%q:{"target":%q}}`, VerdictKind(verdict.Kind).String(), verdict.Chain)), nil
}

type VerdictKind expr.VerdictKind

const (
	VerdictReturn   = "return"
	VerdictGoto     = "goto"
	VerdictJump     = "jump"
	VerdictBreak    = "break"
	VerdictContinue = "continue"
	VerdictDrop     = "drop"
	VerdictAccept   = "accept"
	VerdictStolen   = "storlen"
	VerdictQueue    = "queue"
	VerdictRepeat   = "repeat"
	VerdictStop     = "stop"
)

var verdictMap = map[expr.VerdictKind]string{
	expr.VerdictReturn:   VerdictReturn,
	expr.VerdictGoto:     VerdictGoto,
	expr.VerdictJump:     VerdictJump,
	expr.VerdictBreak:    VerdictBreak,
	expr.VerdictContinue: VerdictContinue,
	expr.VerdictDrop:     VerdictDrop,
	expr.VerdictAccept:   VerdictAccept,
	expr.VerdictStolen:   VerdictStolen,
	expr.VerdictQueue:    VerdictQueue,
	expr.VerdictRepeat:   VerdictRepeat,
	expr.VerdictStop:     VerdictStop,
}

func (v VerdictKind) String() (verdict string) {
	verdict, ok := verdictMap[expr.VerdictKind(v)]
	if !ok {
		verdict = "unknown"
	}
	return verdict
}
