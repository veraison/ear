// Copyright 2023-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
)

// TrustTier represents the overall state of an evidence appraisal.
//
// TrustTierNone means appraisal could not be conducted for whatever reason
// (e.g., a processing error).
//
// TrustTierAffirming means appraisal was fully successful and the attester can
// be considered trustworthy.
//
// TrustTierWarning means appraisal was mostly successful, but there are
// specific checks that need further attention from the relying party to assess
// whether the attester can be considered trustworthy or not.
//
// TrustTierContraindicated means some specific checks have failed and the
// attester cannot be considered trustworthy.
type TrustTier struct {
	value int8
}

var (
	TrustTierNone            = TrustTier{0}
	TrustTierAffirming       = TrustTier{2}
	TrustTierWarning         = TrustTier{32}
	TrustTierContraindicated = TrustTier{96}
	TrustTierIncomplete      = TrustTier{127}
)

var (
	trustTierToString = map[TrustTier]string{
		TrustTierNone:            "none",
		TrustTierAffirming:       "affirming",
		TrustTierWarning:         "warning",
		TrustTierContraindicated: "contraindicated",
		TrustTierIncomplete:      "incomplete",
	}

	stringToTrustTier = map[string]TrustTier{
		"none":            TrustTierNone,
		"affirming":       TrustTierAffirming,
		"warning":         TrustTierWarning,
		"contraindicated": TrustTierContraindicated,
		"incomplete":      TrustTierIncomplete,
	}

	intToTrustTier = map[int]TrustTier{
		0:   TrustTierNone,
		2:   TrustTierAffirming,
		32:  TrustTierWarning,
		96:  TrustTierContraindicated,
		127: TrustTierIncomplete,
	}
)

// TrustTierFromInt creates a TrustTier from the provided int value. If the
// value does not correspond to a valid TrustTier, an error is returned.
func TrustTierFromInt(i int) (TrustTier, error) {
	tier, ok := intToTrustTier[i]
	if !ok {
		return TrustTierNone, fmt.Errorf("not a valid TrustTier value: %d", i)
	}

	return tier, nil
}

// TrustTierFromInt creates a TrustTier from the provided string value. If the
// value does not correspond to a valid TrustTier, an error is returned.
func TrustTierFromString(s string) (TrustTier, error) {
	tier, ok := stringToTrustTier[s]
	if !ok {
		i, err := strconv.Atoi(s)
		if err == nil {
			return TrustTierFromInt(i)
		}
		return TrustTierNone, fmt.Errorf("not a valid TrustTier name: %q", s)
	}

	return tier, nil
}

// TrustTierFromInt creates a TrustTier from the provided interface. If its
// value does not correspond to a valid TrustTier, an error is returned.
func TrustTierFromAny(value any) (TrustTier, error) {
	var (
		err error
		ok  bool

		tier = TrustTierNone
	)

	valueInfo := reflect.ValueOf(value)
	if valueInfo.Kind() == reflect.Pointer {
		if valueInfo.IsNil() {
			return tier, errors.New("nil pointer")
		}

		value = valueInfo.Elem().Interface()
	}

	switch t := value.(type) {
	case string:
		tier, err = TrustTierFromString(t)
	case TrustClaim:
		tier = t.Tier()
	case int:
		tier, err = TrustTierFromInt(t)
	case int8:
		tier, err = TrustTierFromInt(int(t))
	case int16:
		tier, err = TrustTierFromInt(int(t))
	case int32:
		tier, err = TrustTierFromInt(int(t))
	case int64:
		tier, err = TrustTierFromInt(int(t))
	case uint8:
		tier, err = TrustTierFromInt(int(t))
	case uint16:
		tier, err = TrustTierFromInt(int(t))
	case uint32:
		tier, err = TrustTierFromInt(int(t))
	case uint:
		if t > math.MaxInt64 {
			err = fmt.Errorf("not a valid TrustTier value: %d", t)
		} else {
			tier, err = TrustTierFromInt(int(t))
		}
	case uint64:
		if t > math.MaxInt64 {
			err = fmt.Errorf("not a valid TrustTier value: %d", t)
		} else {
			tier, err = TrustTierFromInt(int(t))
		}
	case float64:
		tier, ok = intToTrustTier[int(t)]
		if !ok {
			err = fmt.Errorf("not a valid TrustTier value: %f (%d)", t, int(t))
		}
	case json.Number:
		i, e := t.Int64()
		if e != nil {
			err = fmt.Errorf("not a valid TrustTier value: %v: %w", t, e)
		} else {
			tier, ok = intToTrustTier[int(i)]
			if !ok {
				err = fmt.Errorf("not a valid TrustTier value: %v (%d)", t, int(i))
			}
		}
	case TrustTier:
		tier = t
	default:
		err = fmt.Errorf("cannot convert %v (%T) to TrustTier", t, t)
	}

	return tier, err
}

// WorseThan returns true if the provided TrustTrier is worse than (has higher
// severity) than the receiver.
func (o TrustTier) WorseThan(other TrustTier) bool {
	return o.value > other.value
}

// Int8 returns the int8 value corresponding to the TrustTier.
func (o TrustTier) Int8() int8 {
	return o.value
}

// Int returns the int value corresponding to the TrustTier.
func (o TrustTier) Int() int {
	return int(o.value)
}

// String returns the string value corresponding to the TrustTier.
func (o TrustTier) String() string {
	return trustTierToString[o]
}

// ColorString returns the string value corresponding to the TrustTier
// surrounded by color ANSI escape sequences.
func (o TrustTier) ColorString() string {
	const (
		reset      = `\033[0m`
		red        = `\033[41m`
		yellow     = `\033[43m`
		green      = `\033[42m`
		white      = `\033[47m`
		incomplete = `\033[1;33;41m`
	)

	var color string
	switch o {
	case TrustTierNone:
		color = white
	case TrustTierAffirming:
		color = green
	case TrustTierWarning:
		color = yellow
	case TrustTierContraindicated:
		color = red
	case TrustTierIncomplete:
		color = incomplete
	default:
		// cases are exhaustive
		panic(fmt.Sprintf("unexpected TrustTier %v", o))
	}

	return color + o.String() + reset
}

// Format behaves like ColorString when color is true, and like String
// otherwise.
func (o TrustTier) Format(color bool) string {
	if color {
		return o.ColorString()
	}

	return o.String()
}

func (o TrustTier) MarshalJSON() ([]byte, error) {
	var (
		s  string
		ok bool
	)

	s, ok = trustTierToString[o]
	if !ok {
		// Cannot get here as an invalid TrustTier cannot be created
		// outside this package.
		panic(fmt.Sprintf("unknown trust tier '%d'", o))
	}

	return json.Marshal(s)
}

func (o *TrustTier) UnmarshalJSON(data []byte) error {
	var s string

	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("unable to decode trust tier %q: %w", string(data), err)
	}

	r, ok := stringToTrustTier[s]
	if !ok {
		return fmt.Errorf("unknown trust tier %q", s)
	}

	*o = r

	return nil
}

func (o TrustTier) MarshalCBOR() ([]byte, error) {
	return em.Marshal(o.value)
}

func (o *TrustTier) UnmarshalCBOR(data []byte) error {
	var value int
	var err error

	if err := dm.Unmarshal(data, &value); err != nil {
		return err
	}

	*o, err = TrustTierFromInt(value)
	return err
}
