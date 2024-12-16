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

func (e ErrInfo) LogDict() *zerolog.Event {
	// var ch []flaw.P
	// if len(e.Children) > 0 {
	// 	ch := make([]flaw.P, len(e.Children))
	// 	for i, child := range e.Children {
	// 		ch[i] = child.FlawP()
	// 	}
	// }

	// return flaw.P{
	// 	"message":     e.Message,
	// 	"type_name":   e.TypeName,
	// 	"syntax_repr": e.SyntaxRepr,
	// 	"children":    ch,
	// }
	return nil
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
