// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
)

// ComponentsBound is the verifier's assessment of the bindings between the
// Component Attesters of a Composite Attester (ear_components_bound). Its
// values are AR4SI enumeration values in the affirming, contraindicated and
// incomplete tiers.
type ComponentsBound struct {
	value int8
}

var (
	// ComponentsBoundBound means that all the bindings in use were
	// verified.
	ComponentsBoundBound = ComponentsBound{2}
	// ComponentsBoundNotBound means that at least one binding in use failed
	// verification.
	ComponentsBoundNotBound = ComponentsBound{96}
	// ComponentsBoundCouldNotDetermine means that at least one binding is
	// in use, but the verifier could not evaluate it.
	ComponentsBoundCouldNotDetermine = ComponentsBound{1}
)

var (
	componentsBoundToString = map[ComponentsBound]string{
		ComponentsBoundBound:             "bound",
		ComponentsBoundNotBound:          "not-bound",
		ComponentsBoundCouldNotDetermine: "could-not-determine",
	}

	componentsBoundToTier = map[ComponentsBound]TrustTier{
		ComponentsBoundBound:             TrustTierAffirming,
		ComponentsBoundNotBound:          TrustTierContraindicated,
		ComponentsBoundCouldNotDetermine: TrustTierIncomplete,
	}
)

// ComponentsBoundFromString returns the ComponentsBound corresponding to the
// provided name. Unrecognised names map to ComponentsBoundCouldNotDetermine.
func ComponentsBoundFromString(s string) ComponentsBound {
	for value, name := range componentsBoundToString {
		if name == s {
			return value
		}
	}

	return ComponentsBoundCouldNotDetermine
}

// ComponentsBoundFromInt returns the ComponentsBound corresponding to the
// provided integer. Unrecognised values map to
// ComponentsBoundCouldNotDetermine.
func ComponentsBoundFromInt(i int64) ComponentsBound {
	if i >= math.MinInt8 && i <= math.MaxInt8 {
		value := ComponentsBound{int8(i)}
		if _, ok := componentsBoundToString[value]; ok {
			return value
		}
	}

	return ComponentsBoundCouldNotDetermine
}

// ComponentsBoundFromAny returns a pointer to the ComponentsBound obtained
// from the provided string or integer value. Unrecognised values map to
// ComponentsBoundCouldNotDetermine. An error is returned if the value is
// neither a string nor an integer.
func ComponentsBoundFromAny(value any) (*ComponentsBound, error) {
	valueInfo := reflect.ValueOf(value)
	if valueInfo.Kind() == reflect.Pointer {
		if valueInfo.IsNil() {
			return nil, fmt.Errorf("nil pointer")
		}

		value = valueInfo.Elem().Interface()
	}

	var ret ComponentsBound

	switch t := value.(type) {
	case ComponentsBound:
		ret = t
	case string:
		ret = ComponentsBoundFromString(t)
	case float64:
		if t != math.Trunc(t) {
			return nil, fmt.Errorf("not an integer: %v", t)
		}
		ret = ComponentsBoundFromInt(int64(t))
	default:
		i, err := Int64FromAny(value)
		if err != nil {
			return nil, err
		}
		ret = ComponentsBoundFromInt(i)
	}

	return &ret, nil
}

// Tier returns the trust tier corresponding to the receiver.
func (o ComponentsBound) Tier() TrustTier {
	return componentsBoundToTier[o.canonical()]
}

// String returns the name of the receiver.
func (o ComponentsBound) String() string {
	return componentsBoundToString[o.canonical()]
}

// Int returns the integer value of the receiver.
func (o ComponentsBound) Int() int {
	return int(o.canonical().value)
}

// WorseThan returns true if the receiver's tier is worse than the other's.
func (o ComponentsBound) WorseThan(other ComponentsBound) bool {
	return o.Tier().WorseThan(other.Tier())
}

func (o ComponentsBound) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.String())
}

func (o *ComponentsBound) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("unable to decode components bound %q: %w", string(data), err)
	}

	*o = ComponentsBoundFromString(s)

	return nil
}

func (o ComponentsBound) MarshalCBOR() ([]byte, error) {
	return em.Marshal(o.canonical().value)
}

func (o *ComponentsBound) UnmarshalCBOR(data []byte) error {
	var i int64
	if err := dm.Unmarshal(data, &i); err != nil {
		return err
	}

	*o = ComponentsBoundFromInt(i)

	return nil
}

// canonical maps the zero value to ComponentsBoundCouldNotDetermine.
func (o ComponentsBound) canonical() ComponentsBound {
	if _, ok := componentsBoundToString[o]; ok {
		return o
	}

	return ComponentsBoundCouldNotDetermine
}
