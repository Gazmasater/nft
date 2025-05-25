package encoders

import (
	"encoding/json"
	"fmt"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func init() {
	register(&expr.Connlimit{}, func(e expr.Any) encoder {
		return &connlimitEncoder{connlimit: e.(*expr.Connlimit)}
	})
}

type connlimitEncoder struct {
	connlimit *expr.Connlimit
}

func (b *connlimitEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	c := b.connlimit
	return simpleIR(fmt.Sprintf("ct count %s%d",
		map[bool]string{true: "over ", false: ""}[c.Flags != 0], c.Count)), nil
}
func (b *connlimitEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	cl := map[string]interface{}{
		"ct count": struct {
			Val uint32 `json:"val"`
			Inv bool   `json:"inv,omitempty"`
		}{
			Val: b.connlimit.Count,
			Inv: b.connlimit.Flags&unix.NFT_LIMIT_F_INV != 0,
		},
	}
	return json.Marshal(cl)
}
