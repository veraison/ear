// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
)

func algList() string {
	var l []string

	for _, a := range jwa.SignatureAlgorithms() {
		l = append(l, string(a))
	}

	return strings.Join(l, ", ")
}
