package encoders

import (
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
)

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
