// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ar4si

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTrustVector_Report_bw_default(t *testing.T) {
	tv := TrustVector{
		// default is all 0 == none
	}
	color := false

	expectedShort := `Instance Identity [none]: no claim being made
Configuration [none]: no claim being made
Executables [none]: no claim being made
File System [none]: no claim being made
Hardware [none]: no claim being made
Runtime Opaque [none]: no claim being made
Storage Opaque [none]: no claim being made
Sourced Data [none]: no claim being made
`
	short := true
	assert.Equal(t, expectedShort, tv.Report(short, color))

	expectedLong := `Instance Identity [none]: The Evidence received is insufficient to make a conclusion.
Configuration [none]: The Evidence received is insufficient to make a conclusion.
Executables [none]: The Evidence received is insufficient to make a conclusion.
File System [none]: The Evidence received is insufficient to make a conclusion.
Hardware [none]: The Evidence received is insufficient to make a conclusion.
Runtime Opaque [none]: The Evidence received is insufficient to make a conclusion.
Storage Opaque [none]: The Evidence received is insufficient to make a conclusion.
Sourced Data [none]: The Evidence received is insufficient to make a conclusion.
`
	short = false
	assert.Equal(t, expectedLong, tv.Report(short, color))
}

func TestTrustVector_Report_bw_unknown_affirming(t *testing.T) {
	tv := TrustVector{
		InstanceIdentity: -2,
		Configuration:    -2,
		Executables:      -2,
		FileSystem:       -2,
		Hardware:         -2,
		RuntimeOpaque:    -2,
		StorageOpaque:    -2,
		SourcedData:      -2,
	}
	color := false

	expectedShort := `Instance Identity [affirming]: unknown code-point -2
Configuration [affirming]: unknown code-point -2
Executables [affirming]: unknown code-point -2
File System [affirming]: unknown code-point -2
Hardware [affirming]: unknown code-point -2
Runtime Opaque [affirming]: unknown code-point -2
Storage Opaque [affirming]: unknown code-point -2
Sourced Data [affirming]: unknown code-point -2
`
	short := true
	assert.Equal(t, expectedShort, tv.Report(short, color))

	expectedLong := expectedShort

	short = false
	assert.Equal(t, expectedLong, tv.Report(short, color))
}
