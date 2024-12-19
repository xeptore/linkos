package mathutil

import (
	"golang.org/x/exp/constraints"
)

func IsPowerOf2[N constraints.Integer](n N) bool {
	return n > 0 && (n&(n-1)) == 0
}
