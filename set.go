package encoders

import (
	"fmt"
	"strings"

	"github.com/H-BF/corlib/pkg/dict"
	rb "github.com/Morwran/nft-go/internal/bytes"
	"github.com/google/nftables"
)

type (
	setEncoder struct {
		set setEntry
	}
	setIR struct {
		setEntry
	}
)

func (s *setEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	return &setIR{setEntry: s.set}, nil
}

func (s *setIR) Format() string {
	if !s.Anonymous {
		return fmt.Sprintf("@%s", s.Name)
	}

	var b strings.Builder
	b.WriteByte('{')

	for i, e := range s.elems {
		b.WriteString(s.keyToString(e.Key))
		if i < len(s.elems)-1 {
			b.WriteByte(',')
		}
	}

	b.WriteByte('}')
	return b.String()
}

func (s *setIR) keyToString(k []byte) string {
	switch s.KeyType {
	case nftables.TypeVerdict,
		nftables.TypeString,
		nftables.TypeIFName:
		return rb.RawBytes(k).String()

	case nftables.TypeIPAddr,
		nftables.TypeIP6Addr:
		return rb.RawBytes(k).Ip().String()

	case nftables.TypeBitmask,
		nftables.TypeLLAddr,
		nftables.TypeEtherAddr,
		nftables.TypeTCPFlag,
		nftables.TypeMark,
		nftables.TypeUID,
		nftables.TypeGID:
		return rb.RawBytes(k).Text(rb.BaseHex)

	default:
		return rb.RawBytes(k).Text(rb.BaseDec)
	}
}

type (
	setCache struct {
		dict.HDict[setKey, setEntry]
	}
	setEntry struct {
		nftables.Set
		elems []nftables.SetElement
	}

	setKey struct {
		tableName string
		setName   string
		setId     uint32
	}
)

func (s *setCache) RefreshFromTable(t *nftables.Table) error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	defer func() { _ = conn.CloseLasting() }()
	sets, err := conn.GetSets(t)
	if err != nil {
		return err
	}
	for _, set := range sets {
		if set != nil {
			elems, err := conn.GetSetElements(set)
			if err != nil {
				return err
			}
			s.Put(setKey{
				tableName: set.Table.Name,
				setName:   set.Name,
				setId:     set.ID,
			}, setEntry{
				Set:   *set,
				elems: elems,
			})
		}
	}
	return nil
}
