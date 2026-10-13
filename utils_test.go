// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/cmw"
)

func TestInt64FromAny(t *testing.T) {
	testCases := []struct {
		title    string
		input    any
		expected int64
		err      string
	}{
		{
			title:    "ok float64",
			input:    1.0,
			expected: 1,
		},
		{
			title:    "ok int",
			input:    int(1),
			expected: 1,
		},
		{
			title:    "ok int64",
			input:    int64(1),
			expected: 1,
		},
		{
			title:    "ok uint",
			input:    uint(1),
			expected: 1,
		},
		{
			title:    "ok uint64",
			input:    uint64(1),
			expected: 1,
		},
		{
			title:    "ok string",
			input:    "1",
			expected: 1,
		},
		{
			title:    "ok pointer",
			input:    Ptr(1),
			expected: 1,
		},
		{
			title: "err nil pointer",
			input: (*int)(nil),
			err:   "nil pointer",
		},
		{
			title: "err bool",
			input: true,
			err:   "cannot convert true (bool) to int64",
		},
		{
			title: "err uint out of range",
			input: uint(math.MaxInt64) + 1,
			err:   "out of range: 9223372036854775808",
		},
		{
			title: "err uint64 out of range",
			input: uint64(math.MaxInt64) + 1,
			err:   "out of range: 9223372036854775808",
		},
		{
			title: "err non-int string",
			input: "foo",
			err:   `strconv.Atoi: parsing "foo": invalid syntax`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			result, err := Int64FromAny(tc.input)
			if tc.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			} else {
				assert.ErrorContains(t, err, tc.err)
			}
		})
	}
}

func TestCMWFromAny(t *testing.T) {
	testCMW, err := cmw.NewMonad(
		"application/x-test",
		[]byte{0xde, 0xad, 0xbe, 0xef},
	)
	require.NoError(t, err)

	testCases := []struct {
		title string
		input any
		err   string
	}{
		{
			title: "ok CMW pointer",
			input: testCMW,
		},
		{
			title: "ok CMW",
			input: *testCMW,
		},
		{
			title: "ok slice",
			input: []any{
				"application/x-test",
				"3q2-7w",
			},
		},
		{
			title: "err int",
			input: 1,
			err:   "want JSON object or JSON array start symbols, got: 0x31",
		},
		{
			title: "err chat",
			input: make(chan int),
			err:   "json: unsupported type: chan int",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			result, err := CMWFromAny(tc.input)

			if tc.err == "" {
				assert.NoError(t, err)

				actualType, _ := result.GetMonadType()
				assert.Equal(t, "application/x-test", actualType)

				actualValue, _ := result.GetMonadValue()
				assert.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, actualValue)
			} else {
				assert.ErrorContains(t, err, tc.err)
			}
		})
	}
}
