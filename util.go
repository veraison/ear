// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

type parser func(any) (any, error)

func stringParser(iface any) (any, error) {
	v, ok := iface.(string)
	if !ok {
		return nil, errors.New("not a string")
	}
	return v, nil
}

func stringPtrParser(iface any) (any, error) {
	ret, err := stringParser(iface)
	if err != nil {
		return nil, err
	}
	v := ret.(string)
	return &v, err
}

func stringMapParser(iface any) (any, error) {
	v, ok := iface.(map[string]any)
	if !ok {
		return nil, errors.New("not a map[string]any")
	}
	return v, nil
}

func stringMapPtrParser(iface any) (any, error) {
	ret, err := stringMapParser(iface)
	if err != nil {
		return nil, err
	}
	v := ret.(map[string]any)
	return &v, err
}

func int64Parser(iface any) (any, error) {
	switch t := iface.(type) {
	case float64:
		return int64(t), nil
	case int:
		return int64(t), nil
	case int64:
		return t, nil
	default:
		return int64(0), errors.New("not an int64")
	}
}

func int64PtrParser(iface any) (any, error) {
	ret, err := int64Parser(iface)
	if err != nil {
		return nil, err
	}
	v := ret.(int64)
	return &v, err
}

func stringSliceParser(iface any) (any, error) {
	s, ok := iface.([]any)
	if !ok {
		return nil, errors.New("not an array")
	}

	ret := make([]string, 0, len(s))

	for i, elt := range s {
		v, ok := elt.(string)
		if !ok {
			return nil, fmt.Errorf("element %d: not a string", i)
		}
		ret = append(ret, v)
	}

	if len(ret) == 0 {
		return nil, errors.New("empty array")
	}

	return ret, nil
}

func stringSlicePtrParser(iface any) (any, error) {
	ret, err := stringSliceParser(iface)
	if err != nil {
		return nil, err
	}
	v := ret.([]string)
	return &v, err
}

func topologyParser(iface any) (any, error) {
	m, ok := iface.(map[string]any)
	if !ok {
		return nil, errors.New("not a map[string]any")
	}

	ret := make(map[string][]string, len(m))

	for k, v := range m {
		neighbors, err := stringSliceParser(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		ret[k] = neighbors.([]string)
	}

	if len(ret) == 0 {
		return nil, errors.New("empty map")
	}

	return ret, nil
}

func topologyPtrParser(iface any) (any, error) {
	ret, err := topologyParser(iface)
	if err != nil {
		return nil, err
	}
	v := ret.(map[string][]string)
	return &v, err
}

func structAsMap(
	s any,
	tagKey string,
) (map[string]any, error) {
	result := map[string]any{}
	structType := reflect.TypeOf(s)
	structVal := reflect.ValueOf(s)

	if structType.Kind() != reflect.Struct &&
		(structType.Kind() != reflect.Pointer ||
			structType.Elem().Kind() != reflect.Struct) {
		return nil, errors.New("invalid value: must be a Struct or a *Struct")
	}

	err := doStructAsMap(structType, structVal, result, tagKey)
	return result, err
}

func doStructAsMap(
	structType reflect.Type,
	structVal reflect.Value,
	m map[string]any,
	tagKey string,
) error {
	if structType.Kind() == reflect.Pointer {
		structType = structType.Elem()
		structVal = structVal.Elem()
	}

	for i := 0; i < structVal.NumField(); i++ {
		typeField := structType.Field(i)
		fieldType := typeField.Type
		fieldVal := structVal.Field(i)

		tagSpec, ok := parseTag(typeField.Tag, tagKey)
		if !ok {
			if typeField.Name == fieldType.Name() &&
				fieldType.Kind() == reflect.Struct {
				// embedded struct
				err := doStructAsMap(typeField.Type, fieldVal, m, tagKey)
				if err != nil {
					return err
				}
			}
			continue
		}

		// Dereference pointers, unless they're nil.
		if fieldVal.Kind() == reflect.Pointer {
			if fieldVal.IsNil() {
				if tagSpec.IsMandatory {
					// the field is mandatory (i.e. does
					// not have "omitempty", so we should
					// include the nil value
					m[tagSpec.Name] = nil
				}
				continue
			}

			fieldType = fieldType.Elem()
			fieldVal = fieldVal.Elem()
		}

		// For maps, keys are assumed to be (convertible to) strings.
		// If the values are structs, we need to make sure they're
		// converted, recursively. Otherwise, the map can be handled
		// "normally".
		if fieldType.Kind() == reflect.Map && // a map...
			(fieldType.Elem().Kind() == reflect.Struct || // ...of structs, or...
				(fieldType.Elem().Kind() == reflect.Pointer && // ...pointers...
					fieldType.Elem().Elem().Kind() == reflect.Struct)) { // ...to structs
			valMap := map[string]any{}
			iter := fieldVal.MapRange()

			for iter.Next() {
				mKey := iter.Key().String()
				mVal := map[string]any{}

				if err := doStructAsMap(fieldType.Elem(), iter.Value(),
					mVal, tagKey); err != nil {

					return fmt.Errorf("%s[%s]: %s", typeField.Name, mKey,
						err.Error())
				}

				valMap[mKey] = mVal
			}

			m[tagSpec.Name] = valMap
			continue
		}

		// For arrays and slices, as with map values, we need to make
		// sure we're not dealing with structs, otherwise, we need to
		// recursively convert them.
		if (fieldType.Kind() == reflect.Array || // an array or...
			fieldType.Kind() == reflect.Slice) && // a slice, and...
			(fieldType.Elem().Kind() == reflect.Struct || // ...contains structs, or...
				(fieldType.Elem().Kind() == reflect.Pointer && // ...pointers...
					fieldType.Elem().Elem().Kind() == reflect.Struct)) { // ...to structs

			valSlice := []any{}

			for i := 0; i < fieldVal.Len(); i++ {
				mVal := map[string]any{}

				if err := doStructAsMap(fieldType.Elem(), fieldVal.Index(i),
					mVal, tagKey); err != nil {

					return fmt.Errorf("%s[%d]: %s", typeField.Name, i,
						err.Error())
				}

				valSlice = append(valSlice, mVal)

			}

			m[tagSpec.Name] = valSlice
			continue
		}

		//  if the value has an AsMap() method, use the result of calling it as
		// the entry value...
		if asMapType, ok := fieldType.MethodByName("AsMap"); ok {
			if asMapType.Type.NumIn() != 1 { // the first In is the receiver
				return errors.New("AsMap() must not take arguments") // nolint: golint
			}

			asMap := fieldVal.MethodByName("AsMap")
			ret := asMap.Call([]reflect.Value{})
			if len(ret) != 1 {
				return errors.New("AsMap() did not return exactly one value") // nolint: golint
			}

			val := ret[0]
			if val.Kind() != reflect.Map {
				return errors.New("AsMap() did not return a map") // nolint: golint
			}

			valMap := map[string]any{}
			iter := val.MapRange()
			for iter.Next() {
				valMap[iter.Key().String()] = iter.Value().Interface()
			}

			m[tagSpec.Name] = valMap
			continue
		}

		// Finally, for all other types, assume the value is a
		// serializable type and assign it directly.
		m[tagSpec.Name] = fieldVal.Interface()

	}

	return nil
}

func populateStructFromInterface(
	dest any,
	v any,
	tagKey string,
	parsers map[string]parser,
	defaultParser parser,
	ignoreUnexpected bool,
) error {
	destType := reflect.TypeOf(dest)
	if destType.Kind() != reflect.Pointer || destType.Elem().Kind() != reflect.Struct {
		return errors.New("invalid destination: must be a Struct pointer")
	}

	switch t := v.(type) {
	case map[string]any:
		return populateStructFromMap(dest, t, tagKey, parsers,
			defaultParser, ignoreUnexpected)
	case map[string]string:
		m := make(map[string]any, len(t))
		for k, v := range t {
			m[k] = v
		}
		return populateStructFromMap(dest, m, tagKey, parsers,
			defaultParser, ignoreUnexpected)
	default:
		vType := reflect.TypeOf(v)
		destName := destType.Elem().Name()
		destVal := reflect.ValueOf(dest)

		if vType.Kind() == reflect.Pointer {
			if vType.Elem().Name() != destName {
				return fmt.Errorf("invalid value: expected a *%s, but found %T",
					destName, t)
			}
			destVal.Elem().Set(reflect.ValueOf(v).Elem())
			return nil
		} else if vType.Kind() == reflect.Struct {
			if vType.Name() != destName {
				return fmt.Errorf("invalid value '%v': expected a %s, but found %T",
					t, destName, t)
			}
			destVal.Elem().Set(reflect.ValueOf(v))
			return nil
		}

		return fmt.Errorf("invalid value '%v': expected a %s, but found %T", v, destName, t)
	}
}

func populateStructFromMap(
	dest any,
	m map[string]any,
	tagKey string,
	parsers map[string]parser,
	defaultParser parser,
	ignoreUnexpected bool,
) error {
	var missing, invalid []string
	var problems []string

	destType := reflect.TypeOf(dest)
	destVal := reflect.ValueOf(dest)

	if destType.Kind() != reflect.Pointer || destType.Elem().Kind() != reflect.Struct {
		return errors.New("wrong type: must be a Struct pointer")
	}

	found := doPopulateStructFromMap(destType, destVal,
		m, tagKey, parsers, defaultParser,
		&missing, &invalid)

	extra := getExtraKeys(m, found)

	if len(missing) > 0 {
		msg := fmt.Sprintf("missing mandatory %s", strings.Join(missing, ", "))
		problems = append(problems, msg)
	}

	if len(invalid) > 0 {
		msg := fmt.Sprintf("invalid value(s) for %s", strings.Join(invalid, ", "))
		problems = append(problems, msg)
	}

	if len(extra) > 0 && !ignoreUnexpected {
		msg := fmt.Sprintf("unexpected: %s", strings.Join(extra, ", "))
		problems = append(problems, msg)
	}

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}

	return nil

}

func doPopulateStructFromMap(
	destType reflect.Type,
	destVal reflect.Value,
	m map[string]any,
	tagKey string,
	parsers map[string]parser,
	defaultParser parser,
	missing, invalid *[]string,
) []string {
	var expected []string

	if destType.Kind() == reflect.Pointer {
		destType = destType.Elem()
		destVal = destVal.Elem()
	}

	for i := 0; i < destVal.NumField(); i++ {
		typeField := destType.Field(i)
		fieldVal := destVal.Field(i)

		tagSpec, ok := parseTag(typeField.Tag, tagKey)
		if !ok {
			if typeField.Name == typeField.Type.Name() &&
				typeField.Type.Kind() == reflect.Struct {
				// embedded struct
				embeddedExpected := doPopulateStructFromMap(
					typeField.Type,
					fieldVal,
					m, tagKey,
					parsers, defaultParser,
					missing, invalid)

				expected = append(expected, embeddedExpected...)
			}
			continue
		}

		expected = append(expected, tagSpec.Name)

		rawVal, ok := m[tagSpec.Name]
		if !ok {
			if tagSpec.IsMandatory {
				*missing = append(*missing, tagSpec.QuoteName())
			}
			continue
		}

		parse := defaultParser
		if p, ok := parsers[tagSpec.Name]; ok {
			parse = p
		}

		val, err := parse(rawVal)
		if err != nil {
			mesg := fmt.Sprintf("%s (%s)", tagSpec.QuoteName(), err.Error())
			*invalid = append(*invalid, mesg)
			continue
		}

		fieldVal.Set(reflect.ValueOf(val).Convert(fieldVal.Type()))
	}

	return expected
}

type fieldSpec struct {
	Name        string
	IsMandatory bool
}

func (o fieldSpec) QuoteName() string {
	return fmt.Sprintf("'%s'", o.Name)
}

func parseTag(t reflect.StructTag, key string) (fieldSpec, bool) {
	var ret fieldSpec

	value, ok := t.Lookup(key)
	if !ok {
		return ret, false
	}

	// by convention fields that are tagged exactly "-" are always omitted.
	if value == "-" {
		return ret, false
	}

	parts := strings.Split(value, ",")
	ret.Name = parts[0]

	ret.IsMandatory = true
	if len(parts) > 1 {
		for _, option := range parts[1:] {
			if option == "omitempty" {
				ret.IsMandatory = false
				break
			}
		}
	}

	return ret, true
}

func getExtraKeys(m map[string]any, expected []string) []string {
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
