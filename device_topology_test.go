// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeviceTopologyFromAny(t *testing.T) {
	testCases := []struct {
		title    string
		input    any
		expected DeviceTopology
		err      string
	}{
		{
			title: "ok DeviceTopology",
			input: DeviceTopology{
				"foo": []string{"bar", "qux"},
			},
			expected: DeviceTopology{
				"foo": []string{"bar", "qux"},
			},
		},
		{
			title: "ok map[string][]string",
			input: map[string][]string{
				"foo": []string{"bar", "qux"},
			},
			expected: DeviceTopology{
				"foo": []string{"bar", "qux"},
			},
		},
		{
			title: "ok map[string]any ([]string adjacency)",
			input: map[string]any{
				"foo": []string{"bar", "qux"},
			},
			expected: DeviceTopology{
				"foo": []string{"bar", "qux"},
			},
		},
		{
			title: "ok map[string]any ([]any adjacency)",
			input: map[string]any{
				"foo": []any{"bar", "qux"},
			},
			expected: DeviceTopology{
				"foo": []string{"bar", "qux"},
			},
		},
		{
			title: "err bad type",
			input: 1,
			err:   "invalid type int for DeviceTopology",
		},
		{
			title: "err int adjacency",
			input: map[string]any{
				"foo": 1,
			},
			err: "foo: expected []string, got int",
		},
		{
			title: "err ints adjacency",
			input: map[string]any{
				"foo": []any{1, 2},
			},
			err: "adjacent[0] for foo: expected string, got int",
		},
		{
			title: "err empty",
			input: map[string]any{},
			err:   "empty device topology",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			result, err := DeviceTopologyFromAny(tc.input)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.EqualValues(t, tc.expected, result)
			} else {
				assert.ErrorContains(t, err, tc.err)
			}
		})
	}
}
