// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

type fileEntry struct {
	name    string
	content []byte
}

func makeFS(t *testing.T, fe []fileEntry) {
	fs = afero.NewMemMapFs()

	for _, f := range fe {
		err := afero.WriteFile(fs, f.name, f.content, 0444)
		require.NoError(t, err)
	}
}
