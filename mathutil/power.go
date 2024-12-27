package mathutil

import (
	"golang.org/x/exp/constraints"
)

func ToPowerOf2[N constraints.Integer](exp N) N {
	return 1 << exp
}
