package encoders

import (
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func init() {
	register(&expr.Objref{}, func(e expr.Any) encoder {
		return &objrefEncoder{objrerf: e.(*expr.Objref)}
	})
}

type (
	objrefEncoder struct {
		objrerf *expr.Objref
	}
	objrefIR struct {
		*expr.Objref
	}
)

func (b *objrefEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	return &objrefIR{b.objrerf}, nil
}

func (b *objrefEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	o := b.objrerf
	return []byte(fmt.Sprintf(`{%q:%q}`, o.Type, o.Name)), nil
}

func (o *objrefIR) Format() string {
	sb := strings.Builder{}
	objType := ObjType(o.Type)
	switch objType {
	case ObjCtHelper:
		sb.WriteString("ct helper set ")
	case ObjCtTimeout:
		sb.WriteString("ct timeout set ")
	case ObjCtExpect:
		sb.WriteString("ct expectation set ")
	case ObjSecMark:
		sb.WriteString("meta secmark set ")
	default:
		sb.WriteString(fmt.Sprintf("%s name ", objType))
	}
	sb.WriteString(o.Name)
	return sb.String()
}

type ObjType int

const (
	ObjCounter   ObjType = unix.NFT_OBJECT_COUNTER
	ObjQuota     ObjType = unix.NFT_OBJECT_QUOTA
	ObjCtHelper  ObjType = unix.NFT_OBJECT_CT_HELPER
	ObjLimit     ObjType = unix.NFT_OBJECT_LIMIT
	ObjCtTimeout ObjType = unix.NFT_OBJECT_CT_TIMEOUT
	ObjSecMark   ObjType = unix.NFT_OBJECT_SECMARK
	ObjSynProxy  ObjType = unix.NFT_OBJECT_SYNPROXY
	ObjCtExpect  ObjType = unix.NFT_OBJECT_CT_EXPECT
)

func (o ObjType) String() string {
	switch o {
	case ObjCounter:
		return "counter"
	case ObjQuota:
		return "quota"
	case ObjCtHelper:
		return "ct helper"
	case ObjLimit:
		return "limit"
	case ObjCtTimeout:
		return "ct timeout"
	case ObjSecMark:
		return "secmark"
	case ObjSynProxy:
		return "synproxy"
	case ObjCtExpect:
		return "ct expectation"
	}
	return "unknown"
}
