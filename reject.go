package encoders

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

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
