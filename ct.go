package encoders

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Morwran/nft-go/internal/bytes"
	pr "github.com/Morwran/nft-go/pkg/protocols"

	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
)

func init() {
	register(&expr.Ct{}, func(e expr.Any) encoder {
		return &ctEncoder{ct: e.(*expr.Ct)}
	})
}

type ctEncoder struct {
	ct *expr.Ct
}

func (b *ctEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	ct := b.ct
	human := fmt.Sprintf("ct %s", CtKey(ct.Key))
	if !ct.SourceRegister {
		if ct.Register == 0 {
			return nil, errors.Errorf("%T expression has invalid destination register %d", ct, ct.Register)
		}
		ctx.reg.Set(regID(ct.Register),
			regVal{
				HumanExpr: human,
				Expr:      ct,
			})
		return nil, ErrNoIR
	}
	srcReg, ok := ctx.reg.Get(regID(ct.Register))

	if !ok {
		return nil, errors.Errorf("%T statement has no expression", ct)
	}

	rhs := srcReg.HumanExpr

	return simpleIR(fmt.Sprintf("%s set %s", human, rhs)), nil
}

func (b *ctEncoder) buildCtWithMask(base string, mask []byte) string {
	return fmt.Sprintf("%s %s", base, CtDesk[b.ct.Key](mask))
}

func (b *ctEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	ct := b.ct
	ctJson := map[string]interface{}{
		"ct": struct {
			Key string `json:"key"`
		}{
			Key: CtKey(ct.Key).String(),
		},
	}
	if !ct.SourceRegister {
		if ct.Register == 0 {
			return nil, errors.Errorf("%T expression has invalid destination register %d", ct, ct.Register)
		}
		ctx.reg.Set(regID(ct.Register), regVal{Data: ctJson})
		return nil, ErrNoJSON
	}

	srcReg, ok := ctx.reg.Get(regID(ct.Register))

	if !ok || srcReg.Data == nil {
		return nil, errors.Errorf("%T statement has no expression", ct)
	}

	mangle := map[string]interface{}{
		"mangle": struct {
			Key any `json:"key"`
			Val any `json:"value"`
		}{
			Key: ctJson,
			Val: srcReg.Data,
		},
	}
	return json.Marshal(mangle)
}

type (
	CtKey    expr.CtKey
	CtDir    uint32
	CtStatus uint32
	CtState  uint32
	CtEvents uint32
)

const (
	CtStateBitINVALID     CtState = CtState(expr.CtStateBitINVALID)
	CtStateBitESTABLISHED CtState = CtState(expr.CtStateBitESTABLISHED)
	CtStateBitRELATED     CtState = CtState(expr.CtStateBitRELATED)
	CtStateBitNEW         CtState = CtState(expr.CtStateBitNEW)
	CtStateBitUNTRACKED   CtState = CtState(expr.CtStateBitUNTRACKED)
)

func (c CtKey) String() string {
	switch expr.CtKey(c) {
	case expr.CtKeySTATE:
		return "state"
	case expr.CtKeyDIRECTION:
		return "direction"
	case expr.CtKeySTATUS:
		return "status"
	case expr.CtKeyMARK:
		return "mark" //nolint:goconst
	case expr.CtKeySECMARK:
		return "secmark" //nolint:goconst
	case expr.CtKeyEXPIRATION:
		return "expiration"
	case expr.CtKeyHELPER:
		return "helper"
	case expr.CtKeyL3PROTOCOL:
		return "l3proto"
	case expr.CtKeySRC:
		return "saddr"
	case expr.CtKeyDST:
		return "daddr"
	case expr.CtKeyPROTOCOL:
		return "protocol"
	case expr.CtKeyPROTOSRC:
		return "proto-src"
	case expr.CtKeyPROTODST:
		return "proto-dst"
	case expr.CtKeyLABELS:
		return "label"
	case expr.CtKeyPKTS:
		return "packets"
	case expr.CtKeyBYTES:
		return "bytes"
	case expr.CtKeyAVGPKT:
		return "avgpkt"
	case expr.CtKeyZONE:
		return "zone"
	case expr.CtKeyEVENTMASK:
		return "event"
	}
	return "unknown"
}

func (c CtState) String() string {
	var st []string

	if c&CtStateBitNEW != 0 {
		st = append(st, "new")
	}
	if c&CtStateBitESTABLISHED != 0 {
		st = append(st, "established")
	}
	if c&CtStateBitRELATED != 0 {
		st = append(st, "related")
	}
	if c&CtStateBitINVALID != 0 {
		st = append(st, "invalid")
	}
	if c&CtStateBitUNTRACKED != 0 {
		st = append(st, "untracked")
	}

	return strings.Join(st, ",")
}

// CT DIR TYPE
const (
	IP_CT_DIR_ORIGINAL CtDir = iota
	IP_CT_DIR_REPLY
)

func (c CtDir) String() string {
	switch c {
	case IP_CT_DIR_ORIGINAL:
		return "original"
	case IP_CT_DIR_REPLY:
		return "reply"
	}
	return "unknown"
}

// CT STATUS
const (
	IPS_EXPECTED CtStatus = 1 << iota
	IPS_SEEN_REPLY
	IPS_ASSURED
	IPS_CONFIRMED
	IPS_SRC_NAT
	IPS_DST_NAT
	IPS_DYING CtStatus = 512
)

func (c CtStatus) String() string {
	var st []string
	if c&IPS_EXPECTED != 0 {
		st = append(st, "expected")
	}
	if c&IPS_SEEN_REPLY != 0 {
		st = append(st, "seen-reply")
	}
	if c&IPS_ASSURED != 0 {
		st = append(st, "assured")
	}
	if c&IPS_CONFIRMED != 0 {
		st = append(st, "confirmed")
	}
	if c&IPS_SRC_NAT != 0 {
		st = append(st, "snat")
	}
	if c&IPS_DST_NAT != 0 {
		st = append(st, "dnat")
	}
	if c&IPS_DYING != 0 {
		st = append(st, "dying")
	}

	return strings.Join(st, ",")
}

// CT EVENTS
const (
	IPCT_NEW CtEvents = iota
	IPCT_RELATED
	IPCT_DESTROY
	IPCT_REPLY
	IPCT_ASSURED
	IPCT_PROTOINFO
	IPCT_HELPER
	IPCT_MARK
	IPCT_SEQADJ
	IPCT_SECMARK
	IPCT_LABEL
)

func (c CtEvents) String() string {
	var events []string
	switch c {
	case c & (1 << IPCT_NEW):
		events = append(events, "new")
	case c & (1 << IPCT_RELATED):
		events = append(events, "related")
	case c & (1 << IPCT_DESTROY):
		events = append(events, "destroy")
	case c & (1 << IPCT_REPLY):
		events = append(events, "reply")
	case c & (1 << IPCT_ASSURED):
		events = append(events, "assured")
	case c & (1 << IPCT_PROTOINFO):
		events = append(events, "protoinfo")
	case c & (1 << IPCT_HELPER):
		events = append(events, "helper")
	case c & (1 << IPCT_MARK):
		events = append(events, "mark")
	case c & (1 << IPCT_SEQADJ):
		events = append(events, "seqadj")
	case c & (1 << IPCT_SECMARK):
		events = append(events, "secmark")
	case c & (1 << IPCT_LABEL):
		events = append(events, "label")
	}
	return strings.Join(events, ",")
}

var CtDesk = map[expr.CtKey]func(b []byte) string{
	expr.CtKeySTATE:      BytesToCtStateString,
	expr.CtKeyDIRECTION:  BytesToCtDirString,
	expr.CtKeySTATUS:     BytesToCtStatusString,
	expr.CtKeyMARK:       bytes.LEBytesToIntString,
	expr.CtKeySECMARK:    bytes.LEBytesToIntString,
	expr.CtKeyEXPIRATION: bytes.BytesToTimeString,
	expr.CtKeyHELPER:     bytes.BytesToString,
	expr.CtKeyL3PROTOCOL: bytes.BytesToNfProtoString,
	expr.CtKeySRC:        bytes.BytesToInvalidType,
	expr.CtKeyDST:        bytes.BytesToInvalidType,
	expr.CtKeyPROTOCOL:   pr.BytesToProtoString,
	expr.CtKeyPROTOSRC:   bytes.BytesToDecimalString,
	expr.CtKeyPROTODST:   bytes.BytesToDecimalString,
	expr.CtKeyLABELS:     bytes.BytesToDecimalString,
	expr.CtKeyPKTS:       bytes.LEBytesToIntString,
	expr.CtKeyBYTES:      bytes.LEBytesToIntString,
	expr.CtKeyAVGPKT:     bytes.LEBytesToIntString,
	expr.CtKeyZONE:       bytes.LEBytesToIntString,
	expr.CtKeyEVENTMASK:  BytesToCtEventString,
}

func BytesToCtStateString(b []byte) string {
	return CtState(bytes.RawBytes(b).LittleEndian().Uint64()).String() //nolint:gosec
}

func BytesToCtDirString(b []byte) string {
	return CtDir(uint32(b[0])).String()
}

func BytesToCtStatusString(b []byte) string {
	return CtStatus(bytes.RawBytes(b).LittleEndian().Uint64()).String() //nolint:gosec
}

func BytesToCtEventString(b []byte) string {
	return CtEvents(bytes.RawBytes(b).LittleEndian().Uint64()).String() //nolint:gosec
}
