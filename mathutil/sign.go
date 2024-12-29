package mathutil

import (
	"math/rand/v2"
)

// RandomSign returns a random sign, either 1 or -1.
func RandomSign() int {
	return 2*rand.IntN(2) - 1 //nolint:gosec
}
