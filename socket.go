package encoders

import (
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
)

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
