// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getExtraKeys(t *testing.T) {
	m := map[string]interface{}{
		"name":   "String Archer",
		"alias":  "duchess",
		"age":    42,
		"height": "6'2\"",
		"eyes":   "blue",
		"hair":   "black",
	}

	extras := getExtraKeys(m, []string{"name", "age", "height"})
	assert.ElementsMatch(t, []string{"alias", "eyes", "hair"}, extras)

	extras = getExtraKeys(m, []string{"name", "alias", "age", "height", "eyes", "hair"})
	assert.ElementsMatch(t, []string{}, extras)

	extras = getExtraKeys(m, []string{"name", "age", "family", "language"})
	assert.ElementsMatch(t, []string{"alias", "height", "eyes", "hair"}, extras)

	extras = getExtraKeys(m, []string{})
	assert.ElementsMatch(t, []string{"name", "alias", "age", "height", "eyes", "hair"}, extras)

	extras = getExtraKeys(map[string]interface{}{}, []string{})
	assert.ElementsMatch(t, []string{}, extras)
}
