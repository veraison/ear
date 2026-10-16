// Copyright 2026 Contributors to the Veraison project.

// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"testing"
)

func Test_RootCmd_config(t *testing.T) {
	files := []fileEntry{
		{"test.yaml", []byte("")},
	}
	makeFS(t, files)

	args := []string{
		"--config=test.yaml",
		"-h",
	}
	rootCmd.SetArgs(args)

	Execute()
}
