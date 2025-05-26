package encoders

import (
	"encoding/json"
	"testing"

	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"
)

type connlimitEncoderTestSuite struct {
	suite.Suite
}

func (sui *connlimitEncoderTestSuite) Test_ConnlimitEncodeIR() {
	testData := []struct {
		name      string
		connlimit *expr.Connlimit
		expected  string
	}{
		{
			name:      "simple count",
			connlimit: &expr.Connlimit{Count: 5, Flags: 0},
			expected:  "ct count 5",
		},
		{
			name:      "over count (NFT_LIMIT_F_INV)",
			connlimit: &expr.Connlimit{Count: 10, Flags: unix.NFT_LIMIT_F_INV},
			expected:  "ct count over 10",
		},
	}

	for _, tc := range testData {
		sui.Run(tc.name, func() {
			ctx := &ctx{}
			enc := &connlimitEncoder{connlimit: tc.connlimit}
			ir, err := enc.EncodeIR(ctx)
			sui.Require().NoError(err)

			sui.Require().Equal(tc.expected, ir.Format())
		})
	}
}

func (sui *connlimitEncoderTestSuite) Test_ConnlimitEncodeJSON() {
	testData := []struct {
		name      string
		connlimit *expr.Connlimit
		expected  map[string]interface{}
	}{
		{
			name:      "simple count",
			connlimit: &expr.Connlimit{Count: 7, Flags: 0},
			expected: map[string]interface{}{
				"ct count": map[string]interface{}{
					"val": float64(7),
				},
			},
		},
		{
			name:      "over count (NFT_LIMIT_F_INV)",
			connlimit: &expr.Connlimit{Count: 20, Flags: unix.NFT_LIMIT_F_INV},
			expected: map[string]interface{}{
				"ct count": map[string]interface{}{
					"val": float64(20),
					"inv": true,
				},
			},
		},
	}

	for _, tc := range testData {
		sui.Run(tc.name, func() {
			ctx := &ctx{}
			enc := &connlimitEncoder{connlimit: tc.connlimit}
			data, err := enc.EncodeJSON(ctx)
			sui.Require().NoError(err)

			var got map[string]interface{}
			sui.Require().NoError(json.Unmarshal(data, &got))
			sui.Require().Equal(tc.expected, got)
		})
	}
}

func Test_ConnlimitEncoder(t *testing.T) {
	suite.Run(t, new(connlimitEncoderTestSuite))
}
