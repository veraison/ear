// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"errors"
	"fmt"
	"iter"
	"math"

	"github.com/veraison/eat"
)

var ErrKeyExists = errors.New("key exists in struct fields")

// Extensions collects claims that are not part of EAR specification.
type Extensions struct {
	values map[eat.IntOrString]any
}

// NewExtensions returns a pointer to an new empty Extensions.
func NewExtensions() *Extensions {
	return &Extensions{}
}

// StringSet sets the specified string key to the specified value. Pointer to
// the receiver is returned to allow chaining.
func (o *Extensions) StringSet(key string, value any) *Extensions {
	return o.Set(eat.IntOrStringFromString(key), value)
}

// IntSet sets the specified int key to the specified value. Pointer to
// the receiver is returned to allow chaining.
func (o *Extensions) IntSet(key int, value any) *Extensions {
	return o.Set(eat.IntOrStringFromInt(key), value)
}

// Set sets the specified eat.IntOrString key to the specified value. Pointer
// to the receiver is returned to allow chaining.
func (o *Extensions) Set(key eat.IntOrString, value any) *Extensions {
	if o.values == nil {
		o.values = make(map[eat.IntOrString]any)
	}

	o.values[key] = value

	return o
}

// Get returns the value associated with the specified key. The key must a
// string, int, or eat.IntOrString. If the key is invalid or does not exist, an
// error is returned.
func (o *Extensions) Get(key any) (any, error) {
	actualKey, err := convertKey(key)
	if err != nil {
		return nil, err
	}

	if o.values == nil {
		return nil, fmt.Errorf("extension %q not found", actualKey.String())
	}

	ret, ok := o.values[actualKey]
	if !ok {
		return nil, fmt.Errorf("extension %q not found", actualKey.String())
	}

	return ret, nil
}

// GetInt64 returns the int64 value associated with the specified key (must be int,
// string or eat.IntOrString). An Error is returned if the key is invalid or
// doesn't exist, or the associated value is of the wrong type.
func (o *Extensions) GetInt64(key any) (int64, error) {
	value, err := o.Get(key)
	if err != nil {
		return 0, err
	}

	switch t := value.(type) {
	case int:
		return int64(t), nil
	case int64:
		return t, nil
	case float64:
		if t == math.Trunc(t) {
			return int64(t), nil
		}
		return 0, fmt.Errorf("%v: has type %T (want int64)", key, value)
	default:
		return 0, fmt.Errorf("%v: has type %T (want int64)", key, value)
	}

}

// GetInt returns the int value associated with the specified key (must be int,
// string or eat.IntOrString). An Error is returned if the key is invalid or
// doesn't exist, or the associated value is of the wrong type.
func (o *Extensions) GetInt(key any) (int, error) {
	value, err := o.GetInt64(key)
	if err != nil {
		return 0, err
	}

	// on 32-bit platforms
	if value > math.MaxInt {
		return 0, fmt.Errorf("overflow: %d", value)
	}

	return int(value), nil
}

// GetString returns the string value associated with the specified key (must
// be int, string or eat.IntOrString). An Error is returned if the key is
// invalid or doesn't exist, or the associated value is of the wrong type.
func (o *Extensions) GetString(key any) (string, error) {
	return getTyped[string](o, key)
}

// GetSlice returns the []any value associated with the specified key (must
// be int, string or eat.IntOrString). An Error is returned if the key is
// invalid or doesn't exist, or the associated value is of the wrong type.
func (o *Extensions) GetSlice(key any) ([]any, error) {
	return getTyped[[]any](o, key)
}

// GetStringSlice returns the []string value associated with the specified key (must
// be int, string or eat.IntOrString). An Error is returned if the key is
// invalid or doesn't exist, or the associated value is of the wrong type.
func (o *Extensions) GetStringSlice(key any) ([]string, error) {
	return getTyped[[]string](o, key)
}

// GetInt64Map returns the map[int64]any value associated with the specified
// key (must be int, string or eat.IntOrString). An Error is returned if the
// key is invalid or doesn't exist, or the associated value is of the wrong
// type.
func (o *Extensions) GetInt64Map(key any) (map[int64]any, error) {
	return getTyped[map[int64]any](o, key)
}

// GetMap returns the map[any]any value associated with the specified key (must
// be int, string or eat.IntOrString). An Error is returned if the key is
// invalid or doesn't exist, or the associated value is of the wrong type.
func (o *Extensions) GetMap(key any) (map[any]any, error) {
	return getTyped[map[any]any](o, key)
}

// GetStringMap returns the map[string]any value associated with the specified
// key (must be int, string or eat.IntOrString). An Error is returned if the
// key is invalid or doesn't exist, or the associated value is of the wrong
// type.
func (o *Extensions) GetStringMap(key any) (map[string]any, error) {
	return getTyped[map[string]any](o, key)
}

// GetStringMapString returns the map[string]string value associated with the
// specified key (must be int, string or eat.IntOrString). An Error is returned
// if the key is invalid or doesn't exist, or the associated value is of the
// wrong type.
func (o *Extensions) GetStringMapString(key any) (map[string]string, error) {
	return getTyped[map[string]string](o, key)
}

// Len returns the number of claims inside the receiver.
func (o *Extensions) Len() int {
	return len(o.values)
}

// IsEmpty returns true if the receiver does not contain any claims.
func (o *Extensions) IsEmpty() bool {
	return o.Len() == 0
}

// Iter returns an iterator over key-value pairs of the claims inside the
// receiver.
func (o *Extensions) Iter() iter.Seq2[eat.IntOrString, any] {
	return func(yield func(eat.IntOrString, any) bool) {
		for key, value := range o.values {
			if !yield(key, value) {
				return
			}
		}
	}
}

// UpdateMap updates the provided map[eat.IntOrString]any with the claims
// inside the receiver. An error is returned if any of the receiver's claims
// conflict with those already inside the map.
func (o *Extensions) UpdateMap(toUpdate map[eat.IntOrString]any) error {
	for key, value := range o.Iter() {
		_, exists := toUpdate[key]
		if exists {
			return fmt.Errorf("%w: %q", ErrKeyExists, key.String())
		}

		toUpdate[key] = value
	}

	return nil
}

func convertKey(key any) (eat.IntOrString, error) {
	var ret eat.IntOrString
	switch t := key.(type) {
	case string:
		ret = eat.IntOrStringFromString(t)
	case int:
		ret = eat.IntOrStringFromInt(t)
	case int64:
		ret = eat.IntOrStringFromInt(int(t))
	case eat.IntOrString:
		ret = t
	case *eat.IntOrString:
		ret = *t
	default:
		return ret, fmt.Errorf("invalid extension key type %T", key)
	}

	return ret, nil
}

func getTyped[T any](exts *Extensions, key any) (T, error) {
	var zero T

	val, err := exts.Get(key)
	if err != nil {
		return zero, err
	}

	ret, ok := val.(T)
	if ok {
		return ret, nil
	}

	return zero, fmt.Errorf("%v: has type %T (want %T)", key, val, zero)
}
