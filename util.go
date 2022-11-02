// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

func getExtraKeys(m map[string]interface{}, expected []string) []string {
	expectedMap := make(map[string]bool, len(expected))
	for _, e := range expected {
		expectedMap[e] = true
	}

	var extra []string

	for k := range m {
		if _, found := expectedMap[k]; !found {
			extra = append(extra, k)
		}
	}

	return extra
}
