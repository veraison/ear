// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var testClaimsSetIssue22 = []byte(`{
	"ear.status": "affirming",
	"eat_profile": "tag:github.com,2022:veraison/ear",
	"ear.trustworthiness-vector": {
		"instance-identity": 2,
		"configuration": 2,
		"executables": 3,
		"file-system": 2,
		"hardware": 2,
		"runtime-opaque": 2,
		"storage-opaque": 2,
		"sourced-data": 2
	},
	"ear.raw-evidence": "3q2+7w==",
	"iat": 1666091373,
	"ear.appraisal-policy-id": "https://veraison.example/policy/1/60a0068d"
}`)

// Regression test for https://github.com/veraison/ear/issues/22
// EAT-19 §7.2.2: bstr fields MUST use base64url encoding
func Test_Regression_issue_22(t *testing.T) {
	cmd := NewCreateCmd()

	files := []fileEntry{
		{"skey.json", testSKey},
		{"ear-claims.json", testClaimsSetIssue22},
	}
	makeFS(t, files)

	args := []string{
		"--skey=skey.json",
		"--claims=ear-claims.json",
		"--alg=ES256",
		"ear.jwt",
	}
	cmd.SetArgs(args)

	expectedErr := `decoding EAR claims-set from "ear-claims.json": invalid values(s) for 'ear.raw-evidence'`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}
