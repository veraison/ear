// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_PrintCmd_unknown_argument(t *testing.T) {
	cmd := NewPrintCmd()

	args := []string{"--unknown-argument=val"}
	cmd.SetArgs(args)

	err := cmd.Execute()
	assert.EqualError(t, err, "unknown flag: --unknown-argument")
}

func Test_PrintCmd_no_input_file(t *testing.T) {
	cmd := NewPrintCmd()

	cmd.SetArgs([]string{})

	err := cmd.Execute()
	assert.EqualError(t, err, "validating arguments: no input file supplied")
}

func Test_PrintCmd_input_file_not_found(t *testing.T) {
	cmd := NewPrintCmd()

	files := []fileEntry{}
	makeFS(t, files)

	args := []string{
		"non-existent-ear.jwt",
	}
	cmd.SetArgs(args)

	expectedErr := `reading JWT from "non-existent-ear.jwt": open non-existent-ear.jwt: file does not exist`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_PrintCmd_input_file_bad_format(t *testing.T) {
	cmd := NewPrintCmd()

	emptiness := []byte{}

	files := []fileEntry{
		{"ear.jwt", emptiness},
	}
	makeFS(t, files)

	args := []string{
		"ear.jwt",
	}
	cmd.SetArgs(args)

	expectedErr := `failed to parse serialized JWT: jws.Parse: invalid byte sequence`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_PrintCmd_ok(t *testing.T) {
	cmd := NewPrintCmd()

	args := []string{
		"ear.jwt",
	}
	cmd.SetArgs(args)

	// all test JWTs should be printed without errors
	test_JWTs := [][]byte{testJWT, testJWT_JWK, testRealmJWT}

	for _, jwt := range test_JWTs {
		files := []fileEntry{
			{"ear.jwt", jwt},
		}
		makeFS(t, files)

		err := cmd.Execute()
		assert.NoError(t, err)
	}
}
