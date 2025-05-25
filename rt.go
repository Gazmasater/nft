package encoders

import (
	"fmt"

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
