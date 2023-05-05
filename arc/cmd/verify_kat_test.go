// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_VerifyKatCmd_unknown_argument(t *testing.T) {
	cmd := NewVerifyKatCmd()

	args := []string{"--unknown-argument=val"}
	cmd.SetArgs(args)

	err := cmd.Execute()
	assert.EqualError(t, err, "unknown flag: --unknown-argument")
}

func Test_VerifyKatCmd_no_kat_file(t *testing.T) {
	cmd := NewVerifyKatCmd()

	cmd.SetArgs([]string{"-a aws-nitro"})

	err := cmd.Execute()
	assert.EqualError(t, err, "validating arguments: no KAT file supplied")
}

func Test_VerifyKatCmd_unknown_attester_type(t *testing.T) {
	cmd := NewVerifyKatCmd()

	cmd.SetArgs([]string{
		"--attester=xyz",
		"kat-file",
	})

	err := cmd.Execute()
	assert.EqualError(t, err, "validating arguments: unsupported attester type: xyz")
}

func Test_VerifyKatCmd_kat_file_not_found(t *testing.T) {
	cmd := NewVerifyKatCmd()

	args := []string{
		"--attester=aws-nitro",
		"non-existent",
	}
	cmd.SetArgs(args)

	expectedErr := `loading key attestation from "non-existent": open non-existent: file does not exist`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_VerifyKatCmd_kat_file_bad_format(t *testing.T) {
	cmd := NewVerifyKatCmd()

	files := []fileEntry{
		{"kat.jwt", []byte("")},
	}
	makeFS(t, files)

	args := []string{
		"--attester=aws-nitro",
		"kat.jwt",
	}
	cmd.SetArgs(args)

	expectedErr := `verification of aws-nitro attestation document failed: Data is not a COSESign1 array`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_VerifyKatCmd_refvalue_bad_format(t *testing.T) {
	cmd := NewVerifyKatCmd()

	files := []fileEntry{
		{"bad-refval.json", []byte(`{ "Measurements": { "PCR0": "XYZ"} }`)},
		{"kat.jwt", []byte("")},
	}
	makeFS(t, files)

	args := []string{
		"--attester=aws-nitro",
		"--refval=bad-refval.json",
		"kat.jwt",
	}
	cmd.SetArgs(args)

	expectedErr := `loading aws-nitro reference values from "bad-refval.json": unmarshaling JSON: decoding hex string: encoding/hex: invalid byte: U+0058 'X'`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}

func Test_VerifyKatCmd_refvalue_file_not_found(t *testing.T) {
	cmd := NewVerifyKatCmd()

	files := []fileEntry{
		{"kat.jwt", []byte("")},
	}
	makeFS(t, files)

	args := []string{
		"--attester=aws-nitro",
		"--refval=non-existent",
		"kat.jwt",
	}
	cmd.SetArgs(args)

	expectedErr := `loading aws-nitro reference values from "non-existent": reading file: open non-existent: file does not exist`

	err := cmd.Execute()
	assert.EqualError(t, err, expectedErr)
}
