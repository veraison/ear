// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"errors"
	"fmt"
)

// DeviceTopology is a map that describes the device attester graph using
// adjacency lists. Attesters are represented by their corresponding labels in
// the submods claim. Each map key represents an attester in the graph, and the
// associated map value is an array of labels representing the list of
// sub-attesters for that attester. If the claim is present, the map MUST
// contain at least one element.
type DeviceTopology map[string][]string

// NewDeviceTopology returns a new empty DeviceTopology.
func NewDeviceTopology() DeviceTopology {
	return make(DeviceTopology)
}

// DeviceTopologyFromAny returns a DeviceTopology obtained from provided any
// input. If the input is already a DeviceTopology, the same one is returned,
// otherwise a new DeviceTopology is created. An error is returned if creation
// is not possible.
func DeviceTopologyFromAny(value any) (DeviceTopology, error) {
	var ret DeviceTopology

	switch t := value.(type) {
	case DeviceTopology:
		return t, nil
	case map[string][]string:
		ret = DeviceTopology(t)
	case map[string]any:
		ret = NewDeviceTopology()

		for k, v := range t {
			switch vt := v.(type) {
			case []string:
				ret.Add(k, vt)
			case []any:
				var adjacent []string
				for i, elt := range vt {
					eltString, ok := elt.(string)
					if !ok {
						return nil, fmt.Errorf(
							"adjacent[%d] for %s: expected string, got %T",
							i, k, elt,
						)
					}
					adjacent = append(adjacent, eltString)
				}
				ret.Add(k, adjacent)
			default:
				return nil, fmt.Errorf("%s: expected []string, got %T", k, v)
			}
		}
	default:
		return nil, fmt.Errorf("invalid type %T for DeviceTopology", value)
	}

	if len(ret) == 0 {
		return ret, errors.New("empty device topology")
	}

	return ret, nil
}

// Add the provided submod name and corresponding adjacency list to the
// DeviceTopology.
func (o DeviceTopology) Add(submod string, adjacent []string) DeviceTopology {
	o[submod] = adjacent
	return o
}
