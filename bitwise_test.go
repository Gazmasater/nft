package encoders

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
)

type bitwiseEncoderTestSuite struct {
	suite.Suite
}

func (sui *bitwiseEncoderTestSuite) Test_IpDaddrBitwise24() {
	rule := nftables.Rule{
		Table: &nftables.Table{Name: "test"},
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16,
				Len:          4,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{255, 255, 255, 0},
				Xor:            []byte{0, 0, 0, 0},
			},
			&expr.Cmp{
				Register: 1,
				Op:       expr.CmpOpEq,
				Data:     []byte{192, 168, 1, 0},
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}

	expected := "ip daddr 192.168.1.0/24 accept"
	str, err := NewRuleExprEncoder(&rule).Format()
	sui.Require().NoError(err)
	sui.Require().Equal(expected, str)
}

func Test_BitwiseEncoder(t *testing.T) {
	suite.Run(t, new(bitwiseEncoderTestSuite))
}
