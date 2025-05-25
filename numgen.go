package encoders

import (
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func init() {
	register(&expr.Numgen{}, func(e expr.Any) encoder {
		return &numgenEncoder{numgen: e.(*expr.Numgen)}
	})
}

type numgenEncoder struct {
	numgen *expr.Numgen
}

func (b *numgenEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	numgen := b.numgen
	if numgen.Register == 0 {
		return nil, errors.Errorf("%T expression has invalid destination register %d", numgen, numgen.Register)
	}
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("numgen %s mod %d", b.NumgenModeToString(), numgen.Modulus))
	if numgen.Offset != 0 {
		sb.WriteString(fmt.Sprintf(" offset %d", numgen.Offset))
	}
	ctx.reg.Set(regID(numgen.Register),
		regVal{
			HumanExpr: sb.String(),
			Expr:      numgen,
		})
	return nil, ErrNoIR
}

func (b *numgenEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	numgen := b.numgen
	if numgen.Register == 0 {
		return nil, errors.Errorf("%T expression has invalid destination register %d", numgen, numgen.Register)
	}
	nj := map[string]interface{}{
		"numgen": struct {
			Mode   string `json:"mode"`
			Mod    uint32 `json:"mod"`
			Offset uint32 `json:"offset"`
		}{
			Mode:   b.NumgenModeToString(),
			Mod:    numgen.Modulus,
			Offset: numgen.Offset,
		},
	}
	ctx.reg.Set(regID(numgen.Register), regVal{Data: nj})

	return nil, ErrNoJSON
}

func (b *numgenEncoder) NumgenModeToString() string {
	n := b.numgen
	switch n.Type {
	case unix.NFT_NG_INCREMENTAL:
		return "inc"
	case unix.NFT_NG_RANDOM:
		return "random"
	}

	return "unknown"
}
