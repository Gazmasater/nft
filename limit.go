package encoders

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
)

func init() {
	register(&expr.Limit{}, func(e expr.Any) encoder {
		return &limitEncoder{limit: e.(*expr.Limit)}
	})
}

type (
	limitIR struct {
		*expr.Limit
	}

	limitEncoder struct {
		limit *expr.Limit
	}
)

func (l *limitIR) Format() string {
	if l.Type == expr.LimitTypePkts {
		return fmt.Sprintf("limit rate %s %d/%s burst %d packets",
			map[bool]string{true: "over", false: ""}[l.Over],
			l.Rate, LimitTime(l.Unit), l.Burst)
	}
	sb := strings.Builder{}
	rateVal, rateUnit := rate(l.Rate).Rate()
	sb.WriteString(fmt.Sprintf("limit rate %s %d/%s/%s",
		map[bool]string{true: "over", false: ""}[l.Over],
		rateVal, rateUnit, LimitTime(l.Unit)))
	if l.Burst != 0 {
		burst, burstUnit := rate(uint64(l.Burst)).Rate()
		sb.WriteString(fmt.Sprintf(" burst %d %s", burst, burstUnit))
	}
	return sb.String()
}

func (b *limitEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	if lt := b.limit.Type; lt != expr.LimitTypePkts &&
		lt != expr.LimitTypePktBytes {
		return nil, fmt.Errorf("'%T' has unsupported type of limit '%d'", b.limit, lt)
	}
	return &limitIR{b.limit}, nil
}

func (b *limitEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	var (
		rateVal, burst      uint64
		rateUnit, burstUnit string

		limit = b.limit
	)
	if limit.Type == expr.LimitTypePktBytes {
		rateVal, rateUnit = rate(limit.Rate).Rate()
		burst, burstUnit = rate(limit.Burst).Rate()
	}

	limitJson := map[string]interface{}{
		"limit": struct {
			Rate      uint64 `json:"rate"`
			Burst     uint64 `json:"burst"`
			Per       string `json:"per,omitempty"`
			Inv       bool   `json:"inv,omitempty"`
			RateUnit  string `json:"rate_unit,omitempty"`
			BurstUnit string `json:"burst_unit,omitempty"`
		}{
			Rate:      rateVal,
			Burst:     burst,
			Per:       LimitTime(limit.Unit).String(),
			Inv:       limit.Over,
			RateUnit:  rateUnit,
			BurstUnit: burstUnit,
		},
	}

	return json.Marshal(limitJson)
}

type (
	LimitType expr.LimitType
	LimitTime expr.LimitTime
	rate      uint64
)

func (r rate) Rate() (val uint64, unit string) {
	return getRate(uint64(r))
}

func (l LimitTime) String() string {
	switch expr.LimitTime(l) {
	case expr.LimitTimeSecond:
		return "second"
	case expr.LimitTimeMinute:
		return "minute"
	case expr.LimitTimeHour:
		return "hour"
	case expr.LimitTimeDay:
		return "day"
	case expr.LimitTimeWeek:
		return "week"
	}
	return "error"
}

func getRate(bytes uint64) (val uint64, unit string) {
	dataUnit := [...]string{"bytes", "kbytes", "mbytes"}
	if bytes == 0 {
		return 0, dataUnit[0]
	}
	i := 0
	for i = range dataUnit {
		if bytes%1024 != 0 {
			break
		}
		bytes /= 1024
	}
	return bytes, dataUnit[i]
}
