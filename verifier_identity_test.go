// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifierIdentityFromAny(t *testing.T) {
	testCases := []struct {
		title    string
		input    any
		expected VerifierIdentity
		err      string
	}{
		{
			title: "ok VerifierIdentity",
			input: VerifierIdentity{
				Developer: "test-developer",
				Build:     "test-build",
			},
			expected: VerifierIdentity{
				Developer: "test-developer",
				Build:     "test-build",
			},
		},
		{
			title: "ok VerifierIdentity pointer",
			input: &VerifierIdentity{
				Developer: "test-developer",
				Build:     "test-build",
			},
			expected: VerifierIdentity{
				Developer: "test-developer",
				Build:     "test-build",
			},
		},
		{
			title: "ok map[string]any",
			input: map[string]any{
				"developer": "test-developer",
				"build":     "test-build",
			},
			expected: VerifierIdentity{
				Developer: "test-developer",
				Build:     "test-build",
			},
		},
		{
			title: "err bad type",
			input: 1,
			err:   "cannot convert int to map[eat.IntOrString]any",
		},
		{
			title: "err unexpected field",
			input: map[string]any{
				"foo":       "bar",
				"developer": "test-developer",
				"build":     "test-build",
			},
			err: "unexpected VerifierIdentity field: foo",
		},
		{
			title: "err bad developer",
			input: map[string]any{
				"developer": 1,
				"build":     "test-build",
			},
			err: "developer: expected string, got int",
		},
		{
			title: "err bad build",
			input: map[string]any{
				"developer": "test-developer",
				"build":     1,
			},
			err: "build: expected string, got int",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			result, err := VerifierIdentityFromAny(tc.input)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, &tc.expected, result)
			} else {
				assert.ErrorContains(t, err, tc.err)
			}
		})
	}
}
