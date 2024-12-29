package retry

import (
	"github.com/matryer/try"
)

type Action struct {
	shouldContinue bool
	err            error
}

func Fail(err error) Action {
	return Action{
		shouldContinue: false,
		err:            err,
	}
}

func Retry() Action {
	return Action{
		shouldContinue: true,
		err:            nil,
	}
}

func Success() Action {
	return Action{
		shouldContinue: false,
		err:            nil,
	}
}

func Do(fn func(attempt int) Action) error {
	return try.Do(func(attempt int) (bool, error) {
		action := fn(attempt)
		if action.shouldContinue {
			return true, nil
		}
		return false, action.err
	})
}
