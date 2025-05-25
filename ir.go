package encoders

import "github.com/pkg/errors"

type (
	irNode   interface{ Format() string }
	simpleIR string
)

func (s simpleIR) Format() string { return string(s) }

var ErrNoIR = errors.New("statement has no intermediate representation")
