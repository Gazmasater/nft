package encoders

import (
	"fmt"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"
)

type exthdrEncoderTestSuite struct {
	suite.Suite
}

func (sui *exthdrEncoderTestSuite) Test_ExthdrExistsAccept_WithAliases() {
	testData := []struct {
		name     string
		exprs    nftables.Rule
		expected string
	}{
		{
			name: "exthdr dst exists accept (alias)",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Exthdr{
						Op:     expr.ExthdrOpIpv6,
						Type:   unix.IPPROTO_DSTOPTS,
						Offset: 0,
						Len:    0,
						Flags:  unix.NFT_EXTHDR_F_PRESENT,
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			},
			expected: "exthdr dst exists accept",
		},
		{
			name: "exthdr frag exists accept (alias)",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Exthdr{
						Op:     expr.ExthdrOpIpv6,
						Type:   unix.IPPROTO_FRAGMENT,
						Offset: 0,
						Len:    0,
						Flags:  unix.NFT_EXTHDR_F_PRESENT,
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			},
			expected: "exthdr frag exists accept",
		},
		{
			name: "exthdr mh exists accept (alias)",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Exthdr{
						Op:     expr.ExthdrOpIpv6,
						Type:   unix.IPPROTO_MH,
						Offset: 0,
						Len:    0,
						Flags:  unix.NFT_EXTHDR_F_PRESENT,
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			},
			expected: "exthdr mh exists accept",
		},

		{
			name: "exthdr dst exists exthdr frag exists accept",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Exthdr{
						Type:  unix.IPPROTO_DSTOPTS,
						Flags: unix.NFT_EXTHDR_F_PRESENT,
					},
					&expr.Exthdr{
						Type:  unix.IPPROTO_FRAGMENT,     // frag
						Flags: unix.NFT_EXTHDR_F_PRESENT, // exists
					},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
			},
			expected: "exthdr dst exists exthdr frag exists accept",
		},
	}

	for _, tc := range testData {
		sui.Run(tc.name, func() {
			str, err := NewRuleExprEncoder(&tc.exprs).Format()
			sui.Require().NoError(err)
			fmt.Printf("Expected=%s\n", tc.expected)
			fmt.Printf("IR=%s\n", str)
			sui.Require().Equal(tc.expected, str)
		})
	}
}

func Test_ExthdrEncoder(t *testing.T) {
	suite.Run(t, new(exthdrEncoderTestSuite))
}
