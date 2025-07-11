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

	expectedErr := `parsing verification key from "empty-pkey.json": jwk.Parse: failed to probe data: probe: failed to unmarshal data: EOF`

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

	expectedErr := `verifying signed EAR from "ear.jwt" using "pkey.json" key: failed verifying JWT message: jwt.Parse: failed to parse token: jwt.verifyFast: failed to split compact: jwsbb: invalid number of segments`

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

	expectedErr := `parsing algorithm from "XYZ": invalid key value: "XYZ": invalid key algorithm`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_VerifyCmd_missing_header_key(t *testing.T) {
	cmd := NewVerifyCmd()

	files := []fileEntry{
		{"ear.jwt", testJWT},
	}
	makeFS(t, files)

	args := []string{
		"ear.jwt",
	}
	cmd.SetArgs(args)

	expectedErr := `failed to get JWK key from JWT header`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_VerifyCmd_incorrect_jws(t *testing.T) {
	cmd := NewVerifyCmd()

	files := []fileEntry{
		{"ear.jwt", testJWT_JWK[1:]},
	}
	makeFS(t, files)

	args := []string{
		"ear.jwt",
	}
	cmd.SetArgs(args)

	expectedErr := `failed to parse serialized JWT: jws.Parse: failed to parse compact format: failed to decode protected headers: failed to decode source: illegal base64 data at input byte 212`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_VerifyCmd_header_key_and_expired_token(t *testing.T) {
	cmd := NewVerifyCmd()

	files := []fileEntry{
		{"ear.jwt", testRealmJWT},
	}
	makeFS(t, files)

	args := []string{
		"ear.jwt",
	}
	cmd.SetArgs(args)

	expectedErr := `jwt.Validate: validation failed: "exp" not satisfied: token is expired`

	err := cmd.Execute()
	assert.ErrorContains(t, err, expectedErr)
}

func Test_VerifyCmd_header_key_ignore_alg(t *testing.T) {
	cmd := NewVerifyCmd()

	files := []fileEntry{
		{"ear.jwt", testJWT_JWK},
	}
	makeFS(t, files)

	args := []string{
		"--alg=XYZ",
		"ear.jwt",
	}
	cmd.SetArgs(args)

	err := cmd.Execute()
	assert.NoError(t, err)
}

func Test_VerifyCmd_header_key_ok(t *testing.T) {
	cmd := NewVerifyCmd()

	files := []fileEntry{
		{"ear.jwt", testJWT_JWK},
	}
	makeFS(t, files)

	args := []string{
		"ear.jwt",
	}
	cmd.SetArgs(args)

	err := cmd.Execute()
	assert.NoError(t, err)
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
