package encoders

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	pr "github.com/Morwran/nft-go/pkg/protocols"
  
	"github.com/H-BF/corlib/pkg/atomic"
	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

var setsHolder atomic.Value[setCache]

func init() {
	setsHolder.Store(setCache{}, nil)
}

type RuleExprEncoder nft.Rule

func NewRuleExprEncoder(r *nft.Rule) *RuleExprEncoder {
	return (*RuleExprEncoder)(r)
}

func (r *RuleExprEncoder) String() string {
	str, _ := r.Format()
	return str
}

func (r *RuleExprEncoder) MustString() string {
	str, err := r.Format()
	if err != nil {
		panic(err)
	}
	return str
}

// Format — convert nftables rule expressions to a string line of human format.
func (r *RuleExprEncoder) Format() (string, error) {
	var set setCache
	setsHolder.Fetch(func(sc setCache) {
		set = sc
	})
	ctx := &ctx{
		reg:  regHolder{},
		hdr:  new(pr.ProtoDescPtr),
		sets: set,
		rule: (*nft.Rule)(r),
	}
	nodes := make([]irNode, 0, len(r.Exprs))

	for _, e := range r.Exprs {
		b, err := makeEncoder(e)
		if err != nil {
			return "", fmt.Errorf("failed to make encoder for %T: %w", e, err)
		}
		n, err := b.EncodeIR(ctx)
		if err != nil && !errors.Is(err, ErrNoIR) {
			return "", fmt.Errorf("failed to build IR for %T: %w", e, err)
		}
		if n != nil {
			nodes = append(nodes, n)
		}
	}
	var sb strings.Builder
	for i, n := range nodes {
		l, _ := sb.WriteString(n.Format())
		if i < len(nodes)-1 && l > 0 {
			_ = sb.WriteByte(' ')
		}
	}
	return sb.String(), nil
}

// MarshalJSON — convert nftables rule to json format
func (r *RuleExprEncoder) MarshalJSON() ([]byte, error) {
	var out []json.RawMessage
	ctx := &ctx{reg: regHolder{}}
	for _, e := range r.Exprs {
		b, err := makeEncoder(e)
		if err != nil {
			return nil, err
		}
		j, err := b.EncodeJSON(ctx)
		if err != nil && !errors.Is(err, ErrNoJSON) {
			return nil, err
		}
		if j == nil || string(j) == "{}" {
			continue
		}

		out = append(out, json.RawMessage(j))
	}

	return json.Marshal(out)
}

type (
	encoderFn func(expr.Any) encoder

	encoder interface {
		EncodeIR(*ctx) (irNode, error)
		EncodeJSON(*ctx) ([]byte, error)
	}
)

func makeEncoder(e expr.Any) (encoder, error) {
	if fn, ok := registry[fmt.Sprintf("%T", e)]; ok {
		return fn(e), nil
	}
	return nil, fmt.Errorf("no encoder for type '%T'", e)
}

var ErrNoJSON = errors.New("statement has no json marshaler")
