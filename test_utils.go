// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

// zeroSource is an io.Reader that returns an unlimited number of zero bytes.
type zeroSource struct{}

func (zeroSource) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}

	return len(b), nil
}
