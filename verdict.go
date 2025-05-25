package encoders

import (
	"fmt"

	"github.com/google/nftables/expr"
)

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
