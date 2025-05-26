package encoders

import (
	"fmt"
	"testing"

	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/suite"
)

type counterEncoderTestSuite struct {
	suite.Suite
}

func (sui *counterEncoderTestSuite) Test_CounterEncodeIR() {
	testData := []struct {
		name     string
		counter  *expr.Counter
		expected string
	}{
		{
			name:     "default counter (zeroes)",
			counter:  &expr.Counter{},
			expected: "counter packets 0 bytes 0",
		},
		{
			name:     "counter with values (ignored in IR)",
			counter:  &expr.Counter{Packets: 123, Bytes: 456},
			expected: "counter packets 0 bytes 0", // IR всегда статичен
		},
	}

	for _, tc := range testData {
		sui.Run(tc.name, func() {
			ctx := &ctx{}
			enc := &counterEncoder{counter: tc.counter}
			ir, err := enc.EncodeIR(ctx)
			sui.Require().NoError(err)
			fmt.Printf("Expected=%s\n", tc.expected)
			fmt.Printf("ir.Format=%s\n", ir.Format())
			sui.Require().Equal(tc.expected, ir.Format())
		})
	}
}

func (sui *counterEncoderTestSuite) Test_CounterEncodeJSON() {
	testData := []struct {
		name     string
		counter  *expr.Counter
		expected string
	}{
		{
			name:     "default counter (zeroes)",
			counter:  &expr.Counter{},
			expected: `{"counter":{"bytes":0,"packets":0}}`,
		},
	}

	for _, tc := range testData {
		sui.Run(tc.name, func() {
			ctx := &ctx{}
			enc := &counterEncoder{counter: tc.counter}
			data, err := enc.EncodeJSON(ctx)
			sui.Require().NoError(err)
			fmt.Printf("Expected=%s\n", tc.expected)
			fmt.Printf("DATA=%s\n", string(data))

			sui.Require().JSONEq(tc.expected, string(data))
		})
	}
}

func Test_CounterEncoder(t *testing.T) {
	suite.Run(t, new(counterEncoderTestSuite))
}
