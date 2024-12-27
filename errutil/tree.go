package errutil

import (
	"fmt"

	"github.com/rs/zerolog"
)

type ErrInfo struct {
	Message    string
	TypeName   string
	SyntaxRepr string
	Children   []ErrInfo
}

func (i ErrInfo) logDict() *zerolog.Event {
	children := zerolog.Arr()
	if len(i.Children) > 0 {
		for _, child := range i.Children {
			children.Dict(child.logDict())
		}
	}

	return zerolog.
		Dict().
		Str("message", i.Message).
		Str("type_name", i.TypeName).
		Str("syntax_repr", i.SyntaxRepr).
		Array("children", children)
}

func TreeLog(err error) func(*zerolog.Event) {
	info := Tree(err)

	children := zerolog.Arr()
	if len(info.Children) > 0 {
		for _, child := range info.Children {
			children.Dict(child.logDict())
		}
	}

	return func(e *zerolog.Event) {
		e.Dict(
			"err_tree",
			zerolog.
				Dict().
				Str("message", info.Message).
				Str("type_name", info.TypeName).
				Str("syntax_repr", info.SyntaxRepr).
				Array("children", children),
		)
	}
}

func Tree(err error) ErrInfo {
	if err == nil {
		panic("nil error")
	}

	//nolint:errorlint
	switch x := err.(type) {
	case interface{ Unwrap() error }:
		var children []ErrInfo
		if err := x.Unwrap(); nil != err {
			children = []ErrInfo{Tree(err)}
		}
		return ErrInfo{
			Message:    err.Error(),
			TypeName:   fmt.Sprintf("%T", err),
			SyntaxRepr: fmt.Sprintf("%+#v", err),
			Children:   children,
		}
	case interface{ Unwrap() []error }:
		errs := x.Unwrap()
		joined := make([]ErrInfo, 0, len(errs))
		for _, err := range errs {
			joined = append(joined, Tree(err))
		}
		return ErrInfo{
			Message:    err.Error(),
			TypeName:   fmt.Sprintf("%T", err),
			SyntaxRepr: fmt.Sprintf("%+#v", err),
			Children:   joined,
		}
	default:
		return ErrInfo{
			Message:    err.Error(),
			TypeName:   fmt.Sprintf("%T", err),
			SyntaxRepr: fmt.Sprintf("%+#v", err),
			Children:   nil,
		}
	}
}
