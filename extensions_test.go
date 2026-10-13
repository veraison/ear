// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/veraison/eat"
)

func TestExtensions(t *testing.T) {
	exts := NewExtensions()

	assert.True(t, exts.IsEmpty())
	assert.Equal(t, 0, exts.Len())

	exts.IntSet(1, "foo").
		StringSet("2", 42).
		StringSet("bar", int64(0)).
		Set(eat.IntOrStringFromString("qux"), map[string]string{"key": "value"}).
		StringSet("zot", []string{"one", "two"}).
		StringSet("baz", []any{1, 2}).
		StringSet("eggs", map[string]any{"one": 1, "two": "two"}).
		StringSet("spam", map[int64]any{1: 1, 2: "two"})

	assert.False(t, exts.IsEmpty())
	assert.Equal(t, 8, exts.Len())

	_, err := exts.Get("doesnotexist")
	assert.ErrorContains(t, err, `extension "doesnotexist" not found`)

	value, err := exts.Get("1")
	assert.NoError(t, err)
	assert.Equal(t, "foo", value)

	text, err := exts.GetString(1)
	assert.NoError(t, err)
	assert.Equal(t, "foo", text)

	_, err = exts.GetInt(1)
	assert.ErrorContains(t, err, "1: has type string (want int64)")

	i, err := exts.GetInt(eat.IntOrStringFromInt(2))
	assert.NoError(t, err)
	assert.EqualValues(t, 42, i)

	i, err = exts.GetInt("bar")
	assert.NoError(t, err)
	assert.EqualValues(t, 0, i)

	i64, err := exts.GetInt64("bar")
	assert.NoError(t, err)
	assert.EqualValues(t, 0, i64)

	slice, err := exts.GetSlice("baz")
	assert.NoError(t, err)
	assert.Equal(t, []any{1, 2}, slice)

	stringSlice, err := exts.GetStringSlice("zot")
	assert.NoError(t, err)
	assert.Equal(t, []string{"one", "two"}, stringSlice)

	mapStringAny, err := exts.GetStringMap("eggs")
	assert.NoError(t, err)
	assert.Equal(t, map[string]any{"one": 1, "two": "two"}, mapStringAny)

	mapStringString, err := exts.GetStringMapString("qux")
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"key": "value"}, mapStringString)

	mapIntAny, err := exts.GetInt64Map("spam")
	assert.NoError(t, err)
	assert.Equal(t, map[int64]any{1: 1, 2: "two"}, mapIntAny)

	exts = NewExtensions()
	toUpdate := make(map[eat.IntOrString]any)
	err = exts.UpdateMap(toUpdate)
	assert.NoError(t, err)
	assert.Equal(t, map[eat.IntOrString]any{}, toUpdate)

	exts.StringSet("foo", "bar")
	err = exts.UpdateMap(toUpdate)
	assert.NoError(t, err)
	assert.Equal(t, map[eat.IntOrString]any{eat.IntOrStringFromString("foo"): "bar"}, toUpdate)

	err = exts.UpdateMap(toUpdate)
	assert.ErrorContains(t, err, `key exists in struct fields: "foo"`)
}
