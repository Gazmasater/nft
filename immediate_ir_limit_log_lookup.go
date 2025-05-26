package encoders

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Morwran/nft-go/internal/bytes"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/google/nftables/expr"
)

func init() {
	register(&expr.Immediate{}, func(e expr.Any) encoder {
		return &immediateEncoder{immediate: e.(*expr.Immediate)}
	})
}

type immediateEncoder struct {
	immediate *expr.Immediate
}

func (b *immediateEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	ctx.reg.Set(regID(b.immediate.Register),
		regVal{
			HumanExpr: bytes.RawBytes((b.immediate.Data)).String(),
			Expr:      b.immediate,
		})
	return nil, ErrNoIR
}
func (b *immediateEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	ctx.reg.Set(regID(b.immediate.Register),
		regVal{Data: bytes.RawBytes((b.immediate.Data))})
	return nil, ErrNoJSON
}

//ir

type (
	irNode   interface{ Format() string }
	simpleIR string
)

func (s simpleIR) Format() string { return string(s) }

var ErrNoIR = errors.New("statement has no intermediate representation")

//limit

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

//log

func init() {
	register(&expr.Log{}, func(e expr.Any) encoder {
		return &logEncoder{log: e.(*expr.Log)}
	})
}

type (
	logEncoder struct {
		log *expr.Log
	}
	logIR struct {
		*expr.Log
	}

	LogFlags expr.LogFlags
	LogLevel expr.LogLevel
)

func (b *logEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	return &logIR{Log: b.log}, nil
}

func (b *logEncoder) EncodeJSON(ctx *ctx) ([]byte, error) {
	var fl any
	l := b.log
	flags := LogFlags(l.Flags).String()
	if len(flags) > 1 {
		fl = flags
	} else if len(flags) == 1 {
		fl = flags[0]
	}
	log := &struct {
		Prefix     string `json:"prefix,omitempty"`
		Group      uint16 `json:"group,omitempty"`
		Snaplen    uint32 `json:"snaplen,omitempty"`
		QThreshold uint16 `json:"queue-threshold,omitempty"`
		Level      string `json:"level,omitempty"`
		Flags      any    `json:"flags,omitempty"`
	}{
		Flags: fl,
	}

	if l.Key&(1<<unix.NFTA_LOG_PREFIX) != 0 {
		log.Prefix = string(bytes.TrimRight(l.Data, "\x00"))
	}
	if l.Key&(1<<unix.NFTA_LOG_GROUP) != 0 {
		log.Group = l.Group
	}
	if l.Key&(1<<unix.NFTA_LOG_SNAPLEN) != 0 {
		log.Snaplen = l.Snaplen
	}
	if l.Key&(1<<unix.NFTA_LOG_QTHRESHOLD) != 0 {
		log.QThreshold = l.QThreshold
	}
	if l.Key&(1<<unix.NFTA_LOG_LEVEL) != 0 {
		log.Level = LogLevel(l.Level).String()
	}
	if l.Key == 0 {
		log = nil
	}
	lg := map[string]interface{}{
		"log": log,
	}
	return json.Marshal(lg)
}

func (l *logIR) Format() string {
	sb := strings.Builder{}
	sb.WriteString("log")
	if l.Key&(1<<unix.NFTA_LOG_PREFIX) != 0 {
		sb.WriteString(fmt.Sprintf(" prefix \"%s\"", string(bytes.TrimRight(l.Data, "\x00"))))
	}
	if l.Key&(1<<unix.NFTA_LOG_GROUP) != 0 {
		sb.WriteString(fmt.Sprintf(" group %d", l.Group))
	}
	if l.Key&(1<<unix.NFTA_LOG_SNAPLEN) != 0 {
		sb.WriteString(fmt.Sprintf(" snaplen %d", l.Snaplen))
	}
	if l.Key&(1<<unix.NFTA_LOG_QTHRESHOLD) != 0 {
		sb.WriteString(fmt.Sprintf(" queue-threshold %d", l.QThreshold))
	}
	if l.Key&(1<<unix.NFTA_LOG_LEVEL) != 0 {
		sb.WriteString(fmt.Sprintf(" level %s", LogLevel(l.Level)))
	}
	flags := LogFlags(l.Flags).String()
	if len(flags) > 0 {
		sb.WriteString(fmt.Sprintf(" flags %s", strings.Join(flags, ", ")))
	}

	return sb.String()
}

func (l LogFlags) String() []string {
	var flags []string
	if l == LogFlags(expr.LogFlagsMask) {
		flags = append(flags, "all")
		return flags
	}
	if l == LogFlags(expr.LogFlagsTCPSeq) {
		flags = append(flags, "tcp sequence")
	}
	if l == LogFlags(expr.LogFlagsTCPOpt) {
		flags = append(flags, "tcp options")
	}
	if l == LogFlags(expr.LogFlagsIPOpt) {
		flags = append(flags, "ip options")
	}
	if l == LogFlags(expr.LogFlagsUID) {
		flags = append(flags, "skuid")
	}
	if l == LogFlags(expr.LogFlagsNFLog) {
		flags = append(flags, "nflog")
	}
	if l == LogFlags(expr.LogFlagsMACDecode) {
		flags = append(flags, "mac-decode")
	}
	return flags
}

func (l LogLevel) String() string {
	switch expr.LogLevel(l) {
	case expr.LogLevelEmerg:
		return "emerg"
	case expr.LogLevelAlert:
		return "alert"
	case expr.LogLevelCrit:
		return "crit"
	case expr.LogLevelErr:
		return "err"
	case expr.LogLevelWarning:
		return "warn"
	case expr.LogLevelNotice:
		return "notice"
	case expr.LogLevelInfo:
		return "info"
	case expr.LogLevelDebug:
		return "debug"
	case expr.LogLevelAudit:
		return "audit"
	}
	return "unknown"
}
