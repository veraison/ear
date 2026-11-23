// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"errors"
	"fmt"
	"iter"
	"reflect"
	"strings"

	"github.com/veraison/eat"
)

// TrustVectorDetails maps trustworthiness vector categories to human-readable
// reasons for the values of the corresponding categories
// (ear_trustworthiness_vector_details). The reasons are not meant for
// automated decisions and must be treated as untrusted input.
type TrustVectorDetails struct {
	InstanceIdentity []string `cbor:"0,keyasint,omitempty" json:"instance-identity,omitempty"`
	Configuration    []string `cbor:"1,keyasint,omitempty" json:"configuration,omitempty"`
	Executables      []string `cbor:"2,keyasint,omitempty" json:"executables,omitempty"`
	FileSystem       []string `cbor:"3,keyasint,omitempty" json:"file-system,omitempty"`
	Hardware         []string `cbor:"4,keyasint,omitempty" json:"hardware,omitempty"`
	RuntimeOpaque    []string `cbor:"5,keyasint,omitempty" json:"runtime-opaque,omitempty"`
	StorageOpaque    []string `cbor:"6,keyasint,omitempty" json:"storage-opaque,omitempty"`
	SourcedData      []string `cbor:"7,keyasint,omitempty" json:"sourced-data,omitempty"`
}

// TrustVectorDetailsFromAny returns a pointer to a TrustVectorDetails obtained
// from the provided value. If the value is already a TrustVectorDetails, it
// is returned as is, otherwise a new one is created from the value. Category
// keys may be either names or AR4SI integer labels.
func TrustVectorDetailsFromAny(value any) (*TrustVectorDetails, error) {
	valueInfo := reflect.ValueOf(value)
	if valueInfo.Kind() == reflect.Pointer {
		if valueInfo.IsNil() {
			return nil, errors.New("nil pointer")
		}

		value = valueInfo.Elem().Interface()
	}

	if details, ok := value.(TrustVectorDetails); ok {
		return &details, nil
	}

	entries, err := eat.IntOrStringMapFromAny(value)
	if err != nil {
		return nil, err
	}

	var ret TrustVectorDetails

	for key, entry := range entries {
		reasons, err := DetailsFromAny(entry)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key.String(), err)
		}

		field := ret.field(key)
		if field == nil {
			return nil, fmt.Errorf("unknown category %q", key.String())
		}

		*field = reasons
	}

	return &ret, nil
}

// Iter iterates over pairs of category names and corresponding reasons. Only
// categories that have reasons are yielded.
func (o *TrustVectorDetails) Iter() iter.Seq2[string, []string] {
	return func(yield func(string, []string) bool) {
		if o == nil {
			return
		}

		for _, c := range []struct {
			name    string
			reasons []string
		}{
			{"instance-identity", o.InstanceIdentity},
			{"configuration", o.Configuration},
			{"executables", o.Executables},
			{"file-system", o.FileSystem},
			{"hardware", o.Hardware},
			{"runtime-opaque", o.RuntimeOpaque},
			{"storage-opaque", o.StorageOpaque},
			{"sourced-data", o.SourcedData},
		} {
			if c.reasons == nil {
				continue
			}

			if !yield(c.name, c.reasons) {
				return
			}
		}
	}
}

// IsZero returns true if the receiver is nil or has no reasons for any
// category.
func (o *TrustVectorDetails) IsZero() bool {
	for range o.Iter() {
		return false
	}

	return true
}

// Validate returns an error if the receiver has no categories, if any
// category has an empty list of reasons, or if any category is not present in
// the provided trust vector.
func (o *TrustVectorDetails) Validate(vector *TrustVector) error {
	if o.IsZero() {
		return errors.New("no categories")
	}

	claims := vector.Map()

	var missing []string

	for name, reasons := range o.Iter() {
		if err := validateDetails(reasons); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}

		if claims[name] == NoClaim {
			missing = append(missing, name)
		}
	}

	if len(missing) != 0 {
		return fmt.Errorf(
			"categories not in trust vector: %s",
			strings.Join(missing, ", "),
		)
	}

	return nil
}

func (o *TrustVectorDetails) field(key eat.IntOrString) *[]string {
	switch key {
	case eat.IntOrStringFromString("instance-identity"), eat.IntOrStringFromInt(0):
		return &o.InstanceIdentity
	case eat.IntOrStringFromString("configuration"), eat.IntOrStringFromInt(1):
		return &o.Configuration
	case eat.IntOrStringFromString("executables"), eat.IntOrStringFromInt(2):
		return &o.Executables
	case eat.IntOrStringFromString("file-system"), eat.IntOrStringFromInt(3):
		return &o.FileSystem
	case eat.IntOrStringFromString("hardware"), eat.IntOrStringFromInt(4):
		return &o.Hardware
	case eat.IntOrStringFromString("runtime-opaque"), eat.IntOrStringFromInt(5):
		return &o.RuntimeOpaque
	case eat.IntOrStringFromString("storage-opaque"), eat.IntOrStringFromInt(6):
		return &o.StorageOpaque
	case eat.IntOrStringFromString("sourced-data"), eat.IntOrStringFromInt(7):
		return &o.SourcedData
	default:
		return nil
	}
}

// DetailsFromAny returns the list of human-readable reasons (the value of
// ear_status_details or of a ear_trustworthiness_vector_details category)
// obtained from the provided value. An error is returned if the value is not
// a non-empty list of strings.
func DetailsFromAny(value any) ([]string, error) {
	var ret []string

	switch t := value.(type) {
	case []string:
		ret = t
	case []any:
		ret = make([]string, len(t))
		for i, elt := range t {
			s, ok := elt.(string)
			if !ok {
				return nil, fmt.Errorf("[%d]: expected a string, got %T", i, elt)
			}

			ret[i] = s
		}
	default:
		return nil, fmt.Errorf("expected a list of strings, got %T", value)
	}

	if err := validateDetails(ret); err != nil {
		return nil, err
	}

	return ret, nil
}

func validateDetails(reasons []string) error {
	if reasons != nil && len(reasons) == 0 {
		return errors.New("empty list of reasons")
	}

	return nil
}
