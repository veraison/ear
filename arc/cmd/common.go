// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
)

func algList() string {
	var l []string // nolint: prealloc

	for _, a := range jwa.SignatureAlgorithms() {
		l = append(l, a.String())
	}

	return strings.Join(l, ", ")
}
