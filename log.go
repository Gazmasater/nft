package encoders

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

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
