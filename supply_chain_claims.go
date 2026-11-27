// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"errors"
	"fmt"

	"github.com/veraison/eat"
)

// SupplyChainClaims maps identifiers of supply chain entities (e.g., "Arm")
// onto the claims they asserted. It is the value of the ear_endorser_claims
// and ear_reference_value_provider_claims claims. The verifier derives the
// identifiers from the cryptographic identities of the entities.
type SupplyChainClaims map[string]map[eat.IntOrString]any

// SupplyChainClaimsFromAny returns the SupplyChainClaims obtained from the
// provided value. An error is returned if the conversion is not possible or
// the result is not valid.
func SupplyChainClaimsFromAny(value any) (SupplyChainClaims, error) {
	if t, ok := value.(SupplyChainClaims); ok {
		return t, t.Validate()
	}

	entities := make(map[string]any)

	switch t := value.(type) {
	case map[string]map[eat.IntOrString]any:
		return SupplyChainClaimsFromAny(SupplyChainClaims(t))
	case map[string]any:
		entities = t
	case map[any]any:
		for k, v := range t {
			entity, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("entity %v: expected a string identifier, got %T", k, k)
			}

			entities[entity] = v
		}
	default:
		return nil, fmt.Errorf("expected a map, got %T", value)
	}

	ret := make(SupplyChainClaims, len(entities))

	for entity, claims := range entities {
		claimsMap, err := eat.IntOrStringMapFromAny(claims)
		if err != nil {
			return nil, fmt.Errorf("entity %q: %w", entity, err)
		}

		ret[entity] = claimsMap
	}

	return ret, ret.Validate()
}

// Validate returns an error if the receiver has no entities or if any entity
// has no claims.
func (o SupplyChainClaims) Validate() error {
	if len(o) == 0 {
		return errors.New("no entities")
	}

	for entity, claims := range o {
		if len(claims) == 0 {
			return fmt.Errorf("entity %q: no claims", entity)
		}
	}

	return nil
}
