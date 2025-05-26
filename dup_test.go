package encoders

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
)

type dupEncoderTestSuite struct {
	suite.Suite
}

func (sui *dupEncoderTestSuite) Test_DupExprToString() {
	testData := []struct {
		name     string
		exprs    nftables.Rule
		expected string
	}{
		{
			name: "dup to address",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Immediate{Register: 1, Data: []byte("10.1.2.3")},
					&expr.Dup{RegAddr: 1},
				},
			},
			expected: "dup to 10.1.2.3",
		},
		{
			name: "dup to address and device",
			exprs: nftables.Rule{
				Exprs: []expr.Any{
					&expr.Immediate{Register: 1, Data: []byte("192.168.1.10")},
					&expr.Immediate{Register: 2, Data: []byte("lo")},
					&expr.Dup{RegAddr: 1, RegDev: 2},
				},
			},
			expected: "dup to 192.168.1.10 device lo",
		},
		// {
		// 	name: "oifname ip daddr counter log",
		// 	exprs: nftables.Rule{
		// 		Exprs: []expr.Any{
		// 			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		// 			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("lo")},
		// 			&expr.Payload{DestRegister: 1, Base: 0, Offset: 16, Len: 4},
		// 			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{192, 168, 1, 10}},
		// 			&expr.Counter{},
		// 			&expr.Log{},
		// 		},
		// 	},
		// 	expected: "oifname lo ip daddr 192.168.1.10 counter packets 0 bytes 0 log",
		// },
	}

	for _, t := range testData {
		sui.Run(t.name, func() {
			str, err := NewRuleExprEncoder(&t.exprs).Format()
			sui.Require().NoError(err)
			sui.Require().Equal(t.expected, str)
		})
	}
}

func Test_DupEncoder(t *testing.T) {
	suite.Run(t, new(dupEncoderTestSuite))
}
