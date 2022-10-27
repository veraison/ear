// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_VerifyCmd_unknown_argument(t *testing.T) {
	cmd := NewVerifyCmd()

	args := []string{"--unknown-argument=val"}
	cmd.SetArgs(args)

	err := cmd.Execute()
	assert.EqualError(t, err, "unknown flag: --unknown-argument")
}

func Test_VerifyCmd_no_input_file(t *testing.T) {
	cmd := NewVerifyCmd()

	cmd.SetArgs([]string{})

	err := cmd.Execute()
	assert.EqualError(t, err, "validating arguments: no input file supplied")
}

func Test_VerifyCmd_pkey_file_not_found(t *testing.T) {
	cmd := NewVerifyCmd()

	files := []fileEntry{
		{"ear.jwt", testJWT},
	}
	makeFS(t, files)

	args := []string{
		"--pkey=non-existent-pkey.json",
		"--alg=ES256",
		"ear.jwt",
	}
	cmd.SetArgs(args)

	expectedErr := `loading verification key from "non-existent-pkey.json": open non-existent-pkey.json: file does not exist`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_VerifyCmd_pkey_file_bad_format(t *testing.T) {
	cmd := NewVerifyCmd()

	files := []fileEntry{
		{"ear.jwt", testJWT},
		{"empty-pkey.json", testEmptyKey},
	}
	makeFS(t, files)

	args := []string{
		"--pkey=empty-pkey.json",
		"--alg=ES256",
		"ear.jwt",
	}
	cmd.SetArgs(args)

	expectedErr := `parsing verification key from "empty-pkey.json": failed to unmarshal JSON into key hint: EOF`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_VerifyCmd_skey_not_ok_for_verifying(t *testing.T) {
	cmd := NewVerifyCmd()

	files := []fileEntry{
		{"ear.jwt", testJWT},
		{"skey.json", testSKey},
	}
	makeFS(t, files)

	args := []string{
		"--pkey=skey.json",
		"--alg=ES256",
		"ear.jwt",
	}
	cmd.SetArgs(args)

	expectedErr := `verifying signed EAR from ear.jwt: failed verifying JWT message: could not verify message using any of the signatures or keys`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_VerifyCmd_input_file_not_found(t *testing.T) {
	cmd := NewVerifyCmd()

	files := []fileEntry{}
	makeFS(t, files)

	args := []string{
		"--pkey=ignored.json",
		"--alg=ES256",
		"non-existent-ear.jwt",
	}
	cmd.SetArgs(args)

	expectedErr := `loading signed EAR from "non-existent-ear.jwt": open non-existent-ear.jwt: file does not exist`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_VerifyCmd_input_file_bad_format(t *testing.T) {
	cmd := NewVerifyCmd()

	emptiness := []byte{}

	files := []fileEntry{
		{"ear.jwt", emptiness},
		{"pkey.json", testPKey},
	}
	makeFS(t, files)

	args := []string{
		"--pkey=pkey.json",
		"--alg=ES256",
		"ear.jwt",
	}
	cmd.SetArgs(args)

	expectedErr := `verifying signed EAR from ear.jwt: failed verifying JWT message: failed to parse jws: invalid byte sequence`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_VerifyCmd_unknown_verification_alg(t *testing.T) {
	cmd := NewVerifyCmd()

	files := []fileEntry{
		{"pkey.json", testPKey},
		{"ear.jwt", testJWT},
	}
	makeFS(t, files)

	args := []string{
		"--pkey=pkey.json",
		"--alg=XYZ",
		"ear.jwt",
	}
	cmd.SetArgs(args)

	expectedErr := `verifying signed EAR from ear.jwt: failed verifying JWT message: WithKey() option must be specified using jwa.SignatureAlgorithm (got jwa.InvalidKeyAlgorithm)`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_VerifyCmd_ok(t *testing.T) {
	cmd := NewVerifyCmd()

	files := []fileEntry{
		{"pkey.json", testPKey},
		{"ear.jwt", testJWT},
	}
	makeFS(t, files)

	args := []string{
		"--pkey=pkey.json",
		"--alg=ES256",
		"ear.jwt",
	}
	cmd.SetArgs(args)

	err := cmd.Execute()
	assert.NoError(t, err)
}
