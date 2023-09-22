// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"encoding/json"
	"fmt"
	"math"
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
type TrustTier int8

const (
	TrustTierNone            TrustTier = 0
	TrustTierAffirming       TrustTier = 2
	TrustTierWarning         TrustTier = 32
	TrustTierContraindicated TrustTier = 96
)

var (
	TrustTierToString = map[TrustTier]string{
		TrustTierNone:            "none",
		TrustTierAffirming:       "affirming",
		TrustTierWarning:         "warning",
		TrustTierContraindicated: "contraindicated",
	}

	StringToTrustTier = map[string]TrustTier{
		"none":            TrustTierNone,
		"affirming":       TrustTierAffirming,
		"warning":         TrustTierWarning,
		"contraindicated": TrustTierContraindicated,
	}

	IntToTrustTier = map[int]TrustTier{
		0:  TrustTierNone,
		2:  TrustTierAffirming,
		32: TrustTierWarning,
		96: TrustTierContraindicated,
	}
)

// NewTrustTier returns a pointer to a newly-created TrustTier that has the
// specified value. If the provided value is invalid for a TrustTier,
// TrustTierNone will be used instead.
// (This is essentially a Must- wrapper for ToTrustTier().)
func NewTrustTier(v interface{}) *TrustTier {
	tt, err := ToTrustTier(v)

	if err != nil {
		none := TrustTierNone
		return &none
	}

	return tt
}

func getTrustTierFromInt(i int) (TrustTier, error) {
	tier, ok := IntToTrustTier[i]
	if !ok {
		return TrustTierNone, fmt.Errorf("not a valid TrustTier value: %d", i)
	}

	return tier, nil
}

func getTrustTierFromString(s string) (TrustTier, error) {
	tier, ok := StringToTrustTier[s]
	if !ok {
		i, err := strconv.Atoi(s)
		if err == nil {
			return getTrustTierFromInt(i)
		}
		return TrustTierNone, fmt.Errorf("not a valid TrustTier name: %q", s)
	}

	return tier, nil
}

func ToTrustTier(v interface{}) (*TrustTier, error) {
	var (
		err error
		ok  bool

		tier = TrustTierNone
	)

	switch t := v.(type) {
	case string:
		tier, err = getTrustTierFromString(t)
	case []byte:
		tier, err = getTrustTierFromString(string(t))
	case TrustClaim:
		tier = t.GetTier()
	case int:
		tier, err = getTrustTierFromInt(t)
	case int8:
		tier, err = getTrustTierFromInt(int(t))
	case int16:
		tier, err = getTrustTierFromInt(int(t))
	case int32:
		tier, err = getTrustTierFromInt(int(t))
	case int64:
		tier, err = getTrustTierFromInt(int(t))
	case uint8:
		tier, err = getTrustTierFromInt(int(t))
	case uint16:
		tier, err = getTrustTierFromInt(int(t))
	case uint32:
		tier, err = getTrustTierFromInt(int(t))
	case uint:
		if t > math.MaxInt64 {
			err = fmt.Errorf("not a valid TrustTier value: %d", t)
		} else {
			tier, err = getTrustTierFromInt(int(t))
		}
	case uint64:
		if t > math.MaxInt64 {
			err = fmt.Errorf("not a valid TrustTier value: %d", t)

		} else {
			tier, err = getTrustTierFromInt(int(t))
		}
	case float64:
		tier, ok = IntToTrustTier[int(t)]
		if !ok {
			err = fmt.Errorf("not a valid TrustTier value: %f (%d)", t, int(t))
		}
	case json.Number:
		i, e := t.Int64()
		if e != nil {
			err = fmt.Errorf("not a valid TrustTier value: %v: %w", t, err)
		} else {
			tier, ok = IntToTrustTier[int(i)]
			if !ok {
				err = fmt.Errorf("not a valid TrustTier value: %v (%d)", t, int(i))
			}
		}
	case TrustTier:
		tier = t
	case *TrustTier:
		tier = *t
	default:
		err = fmt.Errorf("cannot convert %v (type %T) to TrustTier", t, t)
	}

	return &tier, err
}

func (o TrustTier) Format(color bool) string {
	if color {
		return o.ColorString()
	}

	return o.String()
}

func (o TrustTier) String() string {
	return TrustTierToString[o]
}

func (o TrustTier) ColorString() string {
	const (
		reset  = `\033[0m`
		red    = `\033[41m`
		yellow = `\033[43m`
		green  = `\033[42m`
		white  = `\033[47m`

		unexpected = `\033[1;33;41m`
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
	default:
		color = unexpected
	}

	return color + o.String() + reset
}

func (o TrustTier) MarshalJSON() ([]byte, error) {
	var (
		s  string
		ok bool
	)

	s, ok = TrustTierToString[o]
	if !ok {
		return nil, fmt.Errorf("unknown trust tier '%d'", o)
	}

	return json.Marshal(s)
}

func (o *TrustTier) UnmarshalJSON(data []byte) error {
	var s string

	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("unable to decode trust tier '%s': %w", string(data), err)
	}

	r, ok := StringToTrustTier[s]
	if !ok {
		return fmt.Errorf("unknown trust tier '%s'", s)
	}

	*o = r

	return nil
}
