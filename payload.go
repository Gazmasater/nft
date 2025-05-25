package encoders

import (
	"encoding/json"
	"fmt"

	"github.com/Morwran/nft-go/internal/bytes"
	pr "github.com/Morwran/nft-go/pkg/protocols"

	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func init() {
	register(&expr.Payload{}, func(e expr.Any) encoder {
		return &payloadEncoder{payload: e.(*expr.Payload)}
	})
}

// payloadBuilder converts nftables payload expressions into an internal IR and
// JSON representation.
type payloadEncoder struct {
	payload *expr.Payload
}

// EncodeIR returns the compiler IR representation.  When the expression writes
// to a register we only update the register map and emit no IR node.
func (b *payloadEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	key := b.buildKey(ctx)

	if b.payload.DestRegister != 0 {
		ctx.reg.Set(regID(b.payload.DestRegister), regVal{HumanExpr: key, Expr: b.payload})
		return nil, ErrNoIR
	}

	srcReg, ok := ctx.reg.Get(regID(b.payload.SourceRegister))
	if !ok {
		return nil, errors.Errorf("%T statement has no expression", b.payload)
	}
	return simpleIR(fmt.Sprintf("%s set %s", key, srcReg.HumanExpr)), nil
}

// EncodeJSON produces a JSON serialization compatible with nft‑go’s CLI tools.
func (b *payloadEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	key := b.jsonKey()

	if b.payload.DestRegister != 0 {
		ctx.reg.Set(regID(b.payload.DestRegister), regVal{Data: key, Expr: b.payload})
		return nil, ErrNoJSON
	}

	srcReg, ok := ctx.reg.Get(regID(b.payload.SourceRegister))
	if !ok || srcReg.Data == nil {
		return nil, errors.Errorf("%T statement has no expression", b.payload)
	}

	mangle := map[string]any{
		"mangle": struct {
			Key any `json:"key"`
			Val any `json:"value"`
		}{Key: key, Val: srcReg.Data},
	}
	return json.Marshal(mangle)
}

// buildKey builds a human‑readable key (e.g. "ip saddr") suitable for IR or
// debug output.  If the offset cannot be resolved it falls back to the raw
// @base,offset,len notation understood by nft.
func (b *payloadEncoder) buildKey(ctx *ctx) string {
	offset := pr.HeaderOffset(b.payload.Offset).BytesToBits()
	if hdr, ok := b.resolveHeader(offset, ctx, includeHeaderIfKnown(ctx)); ok {
		return hdr
	}
	return fmt.Sprintf("@%s,%d,%d", PayloadBase(b.payload.Base), b.payload.Offset, b.payload.Len)
}

// buildPlWithMask is required by other packages to format a key that contains
// a bit‑mask.  Implementation mirrors buildKey() but applies the supplied mask
// and *always* prefixes the header name.
func (b *payloadEncoder) buildPlWithMask(ctx *ctx, mask []byte) string {
	maskedOffset := pr.HeaderOffset(b.payload.Offset).
		BytesToBits().
		WithBitMask(uint32(bytes.RawBytes(mask).Uint64())) //nolint:gosec

	// Keep caller’s header context intact
	bak := *ctx.hdr
	defer func() { *ctx.hdr = bak }()

	if hdr, ok := b.resolveHeader(maskedOffset, ctx, alwaysIncludeHeader()); ok {
		return hdr
	}

	return fmt.Sprintf("@%s,%d,%d/%#x", // fallback
		PayloadBase(b.payload.Base),
		b.payload.Offset, b.payload.Len,
		bytes.RawBytes(mask).Uint64(),
	)
}

// jsonKey returns the canonical JSON representation used when serializing
// rulesets.  Stable on purpose – human‑readable descriptions are *not* embedded
// to avoid churn in generated JSON.
func (b *payloadEncoder) jsonKey() any {
	return map[string]any{
		"payload": struct {
			Base   string `json:"base"`
			Offset uint32 `json:"offset"`
			Len    uint32 `json:"len"`
		}{
			Base:   PayloadBase(b.payload.Base).String(),
			Offset: b.payload.Offset,
			Len:    b.payload.Len,
		},
	}
}

// resolveHeader translates a byte offset into a human‑readable description
// based on the current protocol context. The returned string may or may not
// include the header prefix; this is controlled via the includeHeader flag.
func (b *payloadEncoder) resolveHeader(offset pr.HeaderOffset, ctx *ctx, includeHeader includeHeaderFlag) (string, bool) {
	// 1. Prefer the header we are already inside
	if hdr := *ctx.hdr; hdr != nil {
		if desc, ok := hdr.Offsets[offset]; ok {
			hdr.CurrentOffset = offset
			if includeHeader == addHeaderName ||
				hdr.Id == unix.IPPROTO_IP || hdr.Id == unix.IPPROTO_NONE {
				return fmt.Sprintf("%s %s", hdr.Name, desc.Name), true
			}
			return desc.Name, true
		}
	}

	// 2. Fall back to static protocol tables
	proto, ok := pr.Protocols[b.payload.Base]
	if !ok {
		return "", false
	}

	protoKey := unix.IPPROTO_IP
	if b.payload.Base == expr.PayloadBaseTransportHeader {
		protoKey = unix.IPPROTO_NONE
	}

	header := proto[pr.ProtoType(protoKey)] //nolint:gosec
	if desc, ok := header.Offsets[offset]; ok {
		if ctx.hdr != nil {
			*ctx.hdr = &header // update context for following expressions
		}
		header.CurrentOffset = offset
		return fmt.Sprintf("%s %s", header.Name, desc.Name), true
	}
	return "", false
}

func (b *payloadEncoder) buildLRFromCmpData(ctx *ctx, cmp *expr.Cmp) (left, right string) {
	offset := pr.HeaderOffset(b.payload.Offset).BytesToBits()
	left, _ = b.resolveHeader(offset, ctx, includeHeaderIfKnown(ctx))

	// pretty‑print RHS when we have metadata
	if *ctx.hdr != nil {
		if desc, ok := (*ctx.hdr).Offsets[offset]; ok {
			right = desc.Desc(cmp.Data)
			return
		}
	}

	// fallback to raw bytes
	right = bytes.RawBytes(cmp.Data).String()
	return
}

type (
	PayloadOperationType expr.PayloadOperationType
	PayloadBase          expr.PayloadBase
)

func (p PayloadOperationType) String() string {
	switch expr.PayloadOperationType(p) {
	case expr.PayloadLoad:
		return "load"
	case expr.PayloadWrite:
		return "write"
	default:
		return ""
	}
}

func (p PayloadBase) String() string {
	switch expr.PayloadBase(p) {
	case expr.PayloadBaseLLHeader:
		return "ll"
	case expr.PayloadBaseNetworkHeader:
		return "nh"
	case expr.PayloadBaseTransportHeader:
		return "th"
	default:
		return ""
	}
}

// includeHeaderFlag signals whether resolveHeader should prefix the header name.
// Historically buildPlFromHdrOffset() omitted the prefix *inside* a header while
// buildPlWithMask() always included it.
type includeHeaderFlag bool

const (
	addHeaderName       includeHeaderFlag = true  // always include header prefix
	omitHeaderIfCurrent includeHeaderFlag = false // drop prefix if we’re already inside
)

func includeHeaderIfKnown(ctx *ctx) includeHeaderFlag {
	if *ctx.hdr != nil {
		return omitHeaderIfCurrent
	}
	return addHeaderName
}

func alwaysIncludeHeader() includeHeaderFlag { return addHeaderName }
