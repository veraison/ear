// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/veraison/cmw"
	"github.com/veraison/eat"
)

// Int64FromAny converts provided value into an int64. If the conversion is not
// possible, an error is returned.
func Int64FromAny(value any) (int64, error) {
	valueInfo := reflect.ValueOf(value)
	if valueInfo.Kind() == reflect.Pointer {
		if valueInfo.IsNil() {
			return int64(0), errors.New("nil pointer")
		}

		value = valueInfo.Elem().Interface()
	}

	switch t := value.(type) {
	case float64:
		return int64(t), nil
	case int:
		return int64(t), nil
	case int64:
		return t, nil
	case uint64:
		if t > math.MaxInt64 {
			return int64(0), fmt.Errorf("out of range: %d", t)
		}
		return int64(t), nil
	case uint:
		if uint64(t) > math.MaxInt64 {
			return int64(0), fmt.Errorf("out of range: %d", t)
		}
		return int64(t), nil
	case string:
		ret, err := strconv.Atoi(t)
		if err != nil {
			return int64(0), err
		}

		return int64(ret), nil
	case time.Time:
		return t.Unix(), nil
	default:
		return int64(0), fmt.Errorf("cannot convert %v (%T) to int64", value, value)
	}
}

// CMWFromAny decodes a CMW record (Section 3.1 of RFC9999),
// serialized as the JSON array ["media-type", "base64-encoded-value"].
func CMWFromAny(v any) (*cmw.CMW, error) {
	switch t := v.(type) {
	case *cmw.CMW:
		return t, nil
	case cmw.CMW:
		return &t, nil
	}

	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("re-serializing CMW record: %w", err)
	}

	var c cmw.CMW
	if err := c.UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("decoding CMW record: %w", err)
	}

	return &c, nil
}

// Ptr returns the pointer to the specified value. This is useful when specifying
// literal values for fields that pointers to types for which directly taking a
// pointer of a literal is not possible (e.g. `Field: &"foo"` is not valid, do
// `Field: Ptr("foo")` instead).
func Ptr[T any](v T) *T {
	return &v
}

func getTagLabels(source any, tagType string) map[eat.IntOrString]bool {
	ret := make(map[eat.IntOrString]bool)

	structType := reflect.TypeOf(source)
	if structType.Kind() == reflect.Pointer {
		structType = structType.Elem()
	}

	for i := 0; i < structType.NumField(); i++ {
		tag := structType.Field(i).Tag

		tagText, ok := tag.Lookup(tagType)
		if !ok {
			continue
		}

		labelText := strings.Split(tagText, ",")[0]
		if labelText == "-" {
			continue
		}

		ret[eat.IntOrStringFromString(labelText)] = true
	}

	return ret
}

func structWithExtensionsToMap(source any, tagType string) (map[eat.IntOrString]any, error) {
	structType := reflect.TypeOf(source)
	structVal := reflect.ValueOf(source)
	if structType.Kind() == reflect.Pointer {
		structType = structType.Elem()
		structVal = structVal.Elem()
	}

	if structType.Kind() != reflect.Struct {
		panic(fmt.Errorf("expected struct, got %s", structType.Kind().String()))
	}

	ret := make(map[eat.IntOrString]any)

	var extensions *Extensions

	for i := 0; i < structType.NumField(); i++ {
		fieldType := structType.Field(i)
		fieldValue := structVal.Field(i)

		if fieldType.Type == reflect.TypeOf(extensions) {
			extensions = fieldValue.Interface().(*Extensions)
			continue
		}

		tagText, ok := fieldType.Tag.Lookup(tagType)
		if !ok {
			continue
		}

		rawKey, omitEmpty := parseTag(tagText)
		if rawKey == "-" {
			continue
		}

		if omitEmpty && isEmpty(fieldValue) {
			continue
		}

		ret[eat.IntOrStringFromString(rawKey)] = fieldValue.Interface()
	}

	if extensions != nil {
		if err := extensions.UpdateMap(ret); err != nil {
			return nil, fmt.Errorf("extensions: %w", err)
		}
	}

	return ret, nil
}

func parseTag(tagText string) (string, bool) {
	omitEmpty := false

	if tagText == "" {
		// treat missing tags as if they were explicitly indicating to
		// be skipped.
		return "-", omitEmpty
	}

	parts := strings.Split(tagText, ",")

	for _, part := range parts[1:] {
		if part == "omitempty" || part == "omitzero" {
			omitEmpty = true
		}
	}

	return parts[0], omitEmpty
}

func isEmpty(value reflect.Value) bool {
	if !value.IsValid() {
		return false
	}

	if value.IsZero() {
		return true
	}

	type isZeroer interface {
		IsZero() bool
	}

	checker, ok := value.Interface().(isZeroer)
	if ok && checker.IsZero() {
		return true
	}

	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return true
		}

		value = value.Elem()
	}

	if slices.Contains([]reflect.Kind{
		reflect.Array,
		reflect.Slice,
		reflect.Map,
		reflect.String,
		reflect.Chan,
	}, value.Kind()) {
		if value.Len() == 0 {
			return true
		}

	}

	return false
}
