package encoders

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"
)

type exthdrEncoderTestSuite struct {
	suite.Suite
}

func (sui *exthdrEncoderTestSuite) Test_ExthdrDstExistsAccept() {
	testData := []struct {
		name     string
		exprs    nftables.Rule
		expected string
	}{
		{
			name: "exthdr dst exists accept",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Exthdr{
						Op:     expr.ExthdrOpIpv6,
						Type:   60, // 60 — Destination Options Header (dst)
						Offset: 0,
						Len:    0,
						Flags:  unix.NFT_EXTHDR_F_PRESENT,
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			},
			expected: "ip option 60 accept",
		},
	}

	for _, tc := range testData {
		sui.Run(tc.name, func() {
			str, err := NewRuleExprEncoder(&tc.exprs).Format()
			sui.Require().NoError(err)
			sui.Require().Equal(tc.expected, str)
		})
	}
}

func Test_ExthdrEncoder(t *testing.T) {
	suite.Run(t, new(exthdrEncoderTestSuite))
}
