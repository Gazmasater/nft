package encoders

import (
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
)

type dynsetEncoderTestSuite struct {
	suite.Suite
}

func (sui *dynsetEncoderTestSuite) Test_DynsetEncodeIR() {
	testData := []struct {
		name     string
		dynset   *expr.Dynset
		srcKey   string
		timeout  time.Duration
		op       DynSetOP
		expected string
	}{
		{
			name:     "add",
			dynset:   &expr.Dynset{Operation: uint32(DynSetOPAdd), SetName: "myset", SrcRegKey: 1},
			srcKey:   "10.0.0.1",
			expected: "add @myset { 10.0.0.1 }",
		},
		{
			name:     "add with timeout",
			dynset:   &expr.Dynset{Operation: uint32(DynSetOPAdd), SetName: "myset", SrcRegKey: 2, Timeout: 10 * time.Second},
			srcKey:   "192.168.1.10",
			timeout:  10 * time.Second,
			expected: "add @myset { 192.168.1.10 timeout 10s }",
		},
		{
			name:     "update",
			dynset:   &expr.Dynset{Operation: uint32(DynSetOPUpdate), SetName: "myset", SrcRegKey: 3},
			srcKey:   "testkey",
			expected: "update @myset { testkey }",
		},
		{
			name:     "delete",
			dynset:   &expr.Dynset{Operation: uint32(DynSetOPDelete), SetName: "myset", SrcRegKey: 4},
			srcKey:   "remove_this",
			expected: "delete @myset { remove_this }",
		},

		{
			name: "add with log expr",
			dynset: &expr.Dynset{
				Operation: uint32(DynSetOPAdd),
				SetName:   "myset",
				SrcRegKey: 1,
				Exprs: []expr.Any{
					&expr.Log{},
				},
			},
			srcKey:   "10.10.10.10",
			expected: "add @myset { 10.10.10.10 log }",
		},
		{
			name: "add with timeout and counter",
			dynset: &expr.Dynset{
				Operation: uint32(DynSetOPAdd),
				SetName:   "myset",
				SrcRegKey: 2,
				Timeout:   20 * time.Second,
				Exprs: []expr.Any{
					&expr.Counter{},
				},
			},
			srcKey:   "172.16.0.7",
			expected: "add @myset { 172.16.0.7 timeout 20s counter packets 0 bytes 0 }",
		},
		{
			name: "delete with counter and timeout",
			dynset: &expr.Dynset{
				Operation: uint32(DynSetOPDelete),
				SetName:   "myset",
				SrcRegKey: 5,
				Timeout:   30 * time.Second,
				Exprs: []expr.Any{
					&expr.Counter{},
				},
			},
			srcKey:   "192.0.2.55",
			expected: "delete @myset { 192.0.2.55 timeout 30s counter packets 0 bytes 0 }",
		},
		{
			name: "add with log and counter",
			dynset: &expr.Dynset{
				Operation: uint32(DynSetOPAdd),
				SetName:   "myset",
				SrcRegKey: 8,
				Exprs: []expr.Any{
					&expr.Log{},
					&expr.Counter{},
				},
			},
			srcKey:   "8.8.8.8",
			expected: "add @myset { 8.8.8.8 log counter packets 0 bytes 0 }",
		},
	}

	for _, tc := range testData {
		sui.Run(tc.name, func() {
			// Настраиваем regHolder с нужным regVal по srcRegKey
			var reg regHolder
			reg.Set(regID(tc.dynset.SrcRegKey), regVal{
				HumanExpr: tc.srcKey,
			})

			ctx := &ctx{
				reg:  reg,
				rule: &nftables.Rule{},
			}

			enc := &dynsetEncoder{dynset: tc.dynset}
			ir, err := enc.EncodeIR(ctx)
			sui.Require().NoError(err)
			sui.Require().Equal(tc.expected, ir.Format())
		})
	}
}

func Test_DynsetEncoder(t *testing.T) {
	suite.Run(t, new(dynsetEncoderTestSuite))
}
