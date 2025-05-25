package encoders

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/nftables/expr"
)

func init() {
	register(&expr.Queue{}, func(e expr.Any) encoder {
		return &queueEncoder{que: e.(*expr.Queue)}
	})
}

type (
	queueEncoder struct {
		que *expr.Queue
	}
	queueIR struct {
		*expr.Queue
	}

	QueueFlag expr.QueueFlag
)

func (b *queueEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	return &queueIR{b.que}, nil
}

func (b *queueEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	var flag any
	q := b.que
	flags := QueueFlag(q.Flag).List()
	if len(flags) > 1 {
		flag = flags
	} else if len(flags) == 1 {
		flag = flags[0]
	}
	que := map[string]interface{}{
		"queue": struct {
			Num   uint16 `json:"num,omitempty"`
			Flags any    `json:"flags,omitempty"`
		}{
			Num:   q.Num,
			Flags: flag,
		},
	}

	return json.Marshal(que)
}

func (q *queueIR) Format() string {
	sb := strings.Builder{}
	total := q.Total
	exp := strconv.Itoa(int(q.Num))
	if total > 1 {
		total += q.Num - 1
		exp = fmt.Sprintf("%s-%d", exp, total)
	}
	sb.WriteString("queue")
	flags := QueueFlag(q.Flag).List()
	if len(flags) > 0 {
		sb.WriteString(fmt.Sprintf(" flags %s", strings.Join(QueueFlag(q.Flag).List(), ",")))
	}
	sb.WriteString(fmt.Sprintf(" to %s", exp))
	return sb.String()
}

func (fl QueueFlag) List() (flags []string) {
	if fl&QueueFlag(expr.QueueFlagBypass) != 0 {
		flags = append(flags, "bypass")
	}
	if fl&QueueFlag(expr.QueueFlagFanout) != 0 {
		flags = append(flags, "fanout")
	}
	return flags
}
