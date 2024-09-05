// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

// xSource is an io.Reader that returns an unlimited number of 'x' chars.
type xSource struct{}

func (xSource) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 'x'
	}

	return len(b), nil
}
