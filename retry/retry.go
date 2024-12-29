package retry

import "github.com/matryer/try"

type Action bool

const (
	Retry Action = true
	Abort Action = false
)

func Do(fn func(attempt int) (Action, error)) error {
	return try.Do(func(attempt int) (bool, error) {
		action, err := fn(attempt)
		if nil != err {
			return true, err
		}
		return bool(action), nil
	})
}
