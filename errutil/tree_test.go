package errutil_test

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/xeptore/linkos/errutil"
)

func TestTree(t *testing.T) {
	t.Parallel()

	t.Run("NilErr", func(t *testing.T) {
		t.Parallel()
		assert.PanicsWithValue(t, "nil error", func() { errutil.Tree(nil) })
	})

	t.Run("SimpleStringErr", func(t *testing.T) {
		t.Parallel()
		tree := errutil.Tree(errors.New("simple string error"))
		expected := errutil.ErrInfo{
			Message:    "simple string error",
			TypeName:   "*errors.errorString",
			SyntaxRepr: "",
			Children:   nil,
		}
		assertErrInfoAreEqual(t, expected, tree)
	})

	t.Run("JoinedSimpleStringErrs", func(t *testing.T) {
		t.Parallel()
		tree := errutil.Tree(
			errors.Join(
				errors.New("simple string error"),
				errors.New("another simple string error"),
			),
		)
		expected := errutil.ErrInfo{
			Message:    "simple string error\nanother simple string error",
			TypeName:   "*errors.joinError",
			SyntaxRepr: "",
			Children: []errutil.ErrInfo{
				{
					Message:    "simple string error",
					TypeName:   "*errors.errorString",
					SyntaxRepr: "",
					Children:   nil,
				},
				{
					Message:    "another simple string error",
					TypeName:   "*errors.errorString",
					SyntaxRepr: "",
					Children:   nil,
				},
			},
		}
		assertErrInfoAreEqual(t, expected, tree)
	})

	t.Run("DeepJoinedSimpleStringErrs", func(t *testing.T) {
		t.Parallel()
		tree := errutil.Tree(
			errors.Join(
				errors.New("simple string error"),
				errors.Join(
					errors.New("first nested simple string error"),
					errors.New("second nested simple string error"),
					errors.Join(
						errors.New("third nested simple string error"),
						errors.New("fourth nested simple string error"),
						errors.New("fifth nested simple string error"),
					),
				),
				errors.New("another simple string error"),
			),
		)
		expected := errutil.ErrInfo{
			Message:    "simple string error\nfirst nested simple string error\nsecond nested simple string error\nthird nested simple string error\nfourth nested simple string error\nfifth nested simple string error\nanother simple string error",
			TypeName:   "*errors.joinError",
			SyntaxRepr: "",
			Children: []errutil.ErrInfo{
				{
					Message:    "simple string error",
					TypeName:   "*errors.errorString",
					SyntaxRepr: "",
					Children:   nil,
				},
				{
					Message:    "first nested simple string error\nsecond nested simple string error\nthird nested simple string error\nfourth nested simple string error\nfifth nested simple string error",
					TypeName:   "*errors.joinError",
					SyntaxRepr: "",
					Children: []errutil.ErrInfo{
						{
							Message:    "first nested simple string error",
							TypeName:   "*errors.errorString",
							SyntaxRepr: "",
							Children:   nil,
						},
						{
							Message:    "second nested simple string error",
							TypeName:   "*errors.errorString",
							SyntaxRepr: "",
							Children:   nil,
						},
						{
							Message:    "third nested simple string error\nfourth nested simple string error\nfifth nested simple string error",
							TypeName:   "*errors.joinError",
							SyntaxRepr: "",
							Children: []errutil.ErrInfo{
								{
									Message:    "third nested simple string error",
									TypeName:   "*errors.errorString",
									SyntaxRepr: "",
									Children:   nil,
								},
								{
									Message:    "fourth nested simple string error",
									TypeName:   "*errors.errorString",
									SyntaxRepr: "",
									Children:   nil,
								},
								{
									Message:    "fifth nested simple string error",
									TypeName:   "*errors.errorString",
									SyntaxRepr: "",
									Children:   nil,
								},
							},
						},
					},
				},
				{
					Message:    "another simple string error",
					TypeName:   "*errors.errorString",
					SyntaxRepr: "",
					Children:   nil,
				},
			},
		}
		assertErrInfoAreEqual(t, expected, tree)
	})

	ErrRetryable := errors.New("retrayable error")

	t.Run("UnwrapableErr", func(t *testing.T) {
		t.Parallel()
		_, err := os.ReadDir("nonexistent")
		tree := errutil.Tree(
			errors.Join(
				ErrRetryable,
				fmt.Errorf("os.ReadDir error: %w", err),
			),
		)
		expected := errutil.ErrInfo{
			Message:    "retrayable error\nos.ReadDir error: open nonexistent: no such file or directory",
			TypeName:   "*errors.joinError",
			SyntaxRepr: "",
			Children: []errutil.ErrInfo{
				{
					Message:    "retrayable error",
					TypeName:   "*errors.errorString",
					SyntaxRepr: "",
					Children:   nil,
				},
				{
					Message:    "os.ReadDir error: open nonexistent: no such file or directory",
					TypeName:   "*fmt.wrapError",
					SyntaxRepr: "",
					Children: []errutil.ErrInfo{
						{
							Message:    "open nonexistent: no such file or directory",
							TypeName:   "*fs.PathError",
							SyntaxRepr: "",
							Children: []errutil.ErrInfo{
								{
									Message:    "no such file or directory",
									TypeName:   "syscall.Errno",
									SyntaxRepr: "",
									Children:   nil,
								},
							},
						},
					},
				},
			},
		}
		assertErrInfoAreEqual(t, expected, tree)
	})
}

func assertErrInfoAreEqual(t *testing.T, expected, actual errutil.ErrInfo) {
	t.Helper()
	assert.Exactly(t, expected.Message, actual.Message, "unequal Message field: expected: %q, actual: %q", expected.Message, actual.Message)
	assert.Exactly(t, expected.TypeName, actual.TypeName, "unequal TypeName field: expected: %q, actual: %q", expected.TypeName, actual.TypeName)
	assert.Len(t, actual.Children, len(expected.Children), "unequal Children length: expected: %d, actual: %d", len(expected.Children), len(actual.Children))
	for i, child := range actual.Children {
		assertErrInfoAreEqual(t, expected.Children[i], child)
	}
}
