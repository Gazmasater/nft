package encoders

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
)

// Объявляем константы битов CT state (если вдруг их нет в expr)

type ctEncoderTestSuite struct {
	suite.Suite
}

func (sui *ctEncoderTestSuite) Test_CtExprToString() {
	testData := []struct {
		name     string
		exprs    nftables.Rule
		expected string
	}{
		{
			name: "ct state new",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Ct{
						Key:      expr.CtKeySTATE,
						Register: 1,
					},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpEq,
						Data:     []byte{byte(CtStateBitNEW), 0, 0, 0, 0, 0, 0, 0}, // только new
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			},
			expected: "ct state new accept",
		},
		{
			name: "ct state established,related",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Ct{
						Key:      expr.CtKeySTATE,
						Register: 1,
					},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpEq,
						Data:     []byte{byte(CtStateBitESTABLISHED | CtStateBitRELATED), 0, 0, 0, 0, 0, 0, 0},
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			},
			expected: "ct state established,related accept",
		},
		{
			name: "ct state new,established,related",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Ct{
						Key:      expr.CtKeySTATE,
						Register: 1,
					},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpEq,
						Data:     []byte{byte(CtStateBitNEW | CtStateBitESTABLISHED | CtStateBitRELATED), 0, 0, 0, 0, 0, 0, 0},
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			},
			expected: "ct state new,established,related accept",
		},
		{
			name: "ct state invalid",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Ct{
						Key:      expr.CtKeySTATE,
						Register: 1,
					},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpEq,
						Data:     []byte{byte(CtStateBitINVALID), 0, 0, 0, 0, 0, 0, 0}, // только invalid
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			},
			expected: "ct state invalid accept",
		},
		{
			name: "ct state new,established,invalid",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Ct{
						Key:      expr.CtKeySTATE,
						Register: 1,
					},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpEq,
						Data:     []byte{byte(CtStateBitNEW | CtStateBitESTABLISHED | CtStateBitINVALID), 0, 0, 0, 0, 0, 0, 0},
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			},
			expected: "ct state new,established,invalid accept",
		},

		{
			name: "ct state new,established,related,invalid",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Ct{
						Key:      expr.CtKeySTATE,
						Register: 1,
					},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpEq,
						Data:     []byte{byte(CtStateBitNEW | CtStateBitESTABLISHED | CtStateBitRELATED | CtStateBitINVALID), 0, 0, 0, 0, 0, 0, 0},
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			},
			expected: "ct state new,established,related,invalid accept",
		},
		{
			name: "ct state new,untracked",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Ct{
						Key:      expr.CtKeySTATE,
						Register: 1,
					},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpEq,
						Data:     []byte{byte(CtStateBitNEW | CtStateBitUNTRACKED), 0, 0, 0, 0, 0, 0, 0},
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			},
			expected: "ct state new,untracked accept",
		},

		{
			name: "ct state not established",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Ct{
						Key:      expr.CtKeySTATE,
						Register: 1,
					},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpNeq, // НЕ established
						Data:     []byte{byte(CtStateBitESTABLISHED), 0, 0, 0, 0, 0, 0, 0},
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			},
			expected: "ct state != established accept",
		},
		{
			name: "ct state invalid drop",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Ct{
						Key:      expr.CtKeySTATE,
						Register: 1,
					},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpEq,
						Data:     []byte{byte(CtStateBitINVALID), 0, 0, 0, 0, 0, 0, 0},
					},
					&expr.Verdict{Kind: expr.VerdictDrop},
				},
			},
			expected: "ct state invalid drop",
		},
		{
			name: "ct state established ct expiration 5s",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Ct{
						Key:      expr.CtKeySTATE,
						Register: 1,
					},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpEq,
						Data:     []byte{byte(CtStateBitESTABLISHED), 0, 0, 0, 0, 0, 0, 0},
					},
					&expr.Ct{
						Key:      expr.CtKeyEXPIRATION,
						Register: 2,
					},
					&expr.Cmp{
						Register: 2,
						Op:       expr.CmpOpEq,
						Data:     []byte{0x88, 0x13, 0x00, 0x00}, // 5000 мс = 5s
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			},
			expected: "ct state established ct expiration 5s accept",
		},

		{
			name: "ct state established ct protocol tcp",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Ct{
						Key:      expr.CtKeySTATE,
						Register: 1,
					},
					&expr.Cmp{
						Register: 1,
						Op:       expr.CmpOpEq,
						Data:     []byte{byte(CtStateBitESTABLISHED), 0, 0, 0, 0, 0, 0, 0},
					},
					&expr.Ct{
						Key:      expr.CtKeyPROTOCOL,
						Register: 2,
					},
					&expr.Cmp{
						Register: 2,
						Op:       expr.CmpOpEq,
						Data:     []byte{6}, // TCP
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			},
			expected: "ct state established ct protocol tcp accept",
		},
	}

	for _, t := range testData {
		sui.Run(t.name, func() {
			str, err := NewRuleExprEncoder(&t.exprs).Format()
			sui.Require().NoError(err)
			sui.Require().Equal(t.expected, str)
		})
	}
}

func Test_CtEncoder(t *testing.T) {
	suite.Run(t, new(ctEncoderTestSuite))
}
