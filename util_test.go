// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package ear

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_getExtraKeys(t *testing.T) {
	m := map[string]interface{}{
		"name":   "String Archer",
		"alias":  "duchess",
		"age":    42,
		"height": "6'2\"",
		"eyes":   "blue",
		"hair":   "black",
	}

	extras := getExtraKeys(m, []string{"name", "age", "height"})
	assert.ElementsMatch(t, []string{"alias", "eyes", "hair"}, extras)

	extras = getExtraKeys(m, []string{"name", "alias", "age", "height", "eyes", "hair"})
	assert.ElementsMatch(t, []string{}, extras)

	extras = getExtraKeys(m, []string{"name", "age", "family", "language"})
	assert.ElementsMatch(t, []string{"alias", "height", "eyes", "hair"}, extras)

	extras = getExtraKeys(m, []string{})
	assert.ElementsMatch(t, []string{"name", "alias", "age", "height", "eyes", "hair"}, extras)

	extras = getExtraKeys(map[string]interface{}{}, []string{})
	assert.ElementsMatch(t, []string{}, extras)
}

type TestEmbedded struct {
	FieldOne string `json:"embedded-field,omitempty"`
}

type testStruct struct {
	FieldOne   string     `json:"optional-field,omitempty"`
	FieldTwo   *int64     `json:"mandatory-field"`
	FieldThree *string    // untagged
	FieldFour  *string    `cbor:"4,keyasint"` // tagged, but no json
	FieldFive  *testField `json:"custom,omitempty"`

	TestEmbedded
}

type testField struct {
	I int `json:"eye"`
}

func Test_populateStructFromMap(t *testing.T) {
	parsers := map[string]parser{
		// optional-field will rely on the default string parser
		"mandatory-field": int64PtrParser,
	}

	var s testStruct
	var i int

	m := map[string]interface{}{
		"optional-field":  "foo",
		"mandatory-field": 42,
	}

	err := populateStructFromMap(&i, m, "json", parsers, stringParser, true)
	assert.EqualError(t, err, "wrong type: must be a Struct pointer")

	err = populateStructFromMap(s, m, "json", parsers, stringParser, true)
	assert.EqualError(t, err, "wrong type: must be a Struct pointer")

	err = populateStructFromMap(&s, m, "json", parsers, stringParser, true)
	require.NoError(t, err)
	assert.Equal(t, "foo", s.FieldOne)
	assert.Equal(t, int64(42), *s.FieldTwo)

	m = map[string]interface{}{
		"mandatory-field": 42.0,
	}
	err = populateStructFromMap(&s, m, "json", parsers, stringParser, true)
	require.NoError(t, err)
	assert.Equal(t, int64(42), *s.FieldTwo)

	m = map[string]interface{}{
		"optional-field": "foo",
	}
	err = populateStructFromMap(&s, m, "json", parsers, stringParser, true)
	assert.EqualError(t, err, "missing mandatory 'mandatory-field'")

	m = map[string]interface{}{
		"optional-field":  7,
		"mandatory-field": 42,
	}
	err = populateStructFromMap(&s, m, "json", parsers, stringParser, true)
	assert.EqualError(t, err, "invalid value(s) for 'optional-field' (not a string)")

	m = map[string]interface{}{
		"mandatory-field": "foo",
	}
	err = populateStructFromMap(&s, m, "json", parsers, stringParser, true)
	assert.EqualError(t, err, "invalid value(s) for 'mandatory-field' (not an int64)")

	m = map[string]interface{}{
		"embedded-field":  "bar",
		"mandatory-field": 42,
	}
	err = populateStructFromMap(&s, m, "json", parsers, stringParser, true)
	require.NoError(t, err)
	assert.Equal(t, "bar", s.TestEmbedded.FieldOne)

	m = map[string]interface{}{
		"embedded-field":  false,
		"mandatory-field": 42,
	}
	err = populateStructFromMap(&s, m, "json", parsers, stringParser, true)
	assert.EqualError(t, err, "invalid value(s) for 'embedded-field' (not a string)")

	m = map[string]interface{}{
		"mandatory-field": 42,
	}
	err = populateStructFromMap(&s, m, "json", parsers, stringParser, true)
	require.NoError(t, err)

	m = map[string]interface{}{
		"mandatory-field":  42,
		"unexpected-field": "nothing to see here",
	}
	err = populateStructFromMap(&s, m, "json", parsers, stringParser, true)
	assert.NoError(t, err)

	m = map[string]interface{}{
		"mandatory-field":  42,
		"unexpected-field": "nothing to see here",
	}
	err = populateStructFromMap(&s, m, "json", parsers, stringParser, false)
	assert.EqualError(t, err, "unexpected: unexpected-field")
}

func Test_populateStructFromInterface(t *testing.T) {
	parsers := map[string]parser{
		// optional-field will rely on the default string parser
		"mandatory-field": int64PtrParser,
	}

	var s testStruct

	m := map[string]interface{}{
		"optional-field":  "foo",
		"mandatory-field": 42,
	}

	err := populateStructFromInterface(&s, m, "json", parsers, stringParser, true)
	require.NoError(t, err)
	assert.Equal(t, "foo", s.FieldOne)
	assert.Equal(t, int64(42), *s.FieldTwo)

	f2 := int64(7)
	f3 := "field-three"
	other := testStruct{
		FieldOne:   "test",
		FieldTwo:   &f2,
		FieldThree: &f3,
		TestEmbedded: TestEmbedded{
			FieldOne: "embedded-test",
		},
	}

	s = testStruct{}
	err = populateStructFromInterface(&s, other, "json", parsers, stringParser, true)
	require.NoError(t, err)
	assert.Equal(t, "test", s.FieldOne)
	assert.Equal(t, int64(7), *s.FieldTwo)
	assert.Equal(t, "embedded-test", s.TestEmbedded.FieldOne)

	s = testStruct{}
	err = populateStructFromInterface(&s, &other, "json", parsers, stringParser, true)
	require.NoError(t, err)
	assert.Equal(t, "test", s.FieldOne)
	assert.Equal(t, int64(7), *s.FieldTwo)
	assert.Equal(t, "embedded-test", s.TestEmbedded.FieldOne)

	i := 7
	err = populateStructFromInterface(&s, i, "json", parsers, stringParser, true)
	assert.EqualError(t, err, "invalid value '7': expected a testStruct, but found int")

	err = populateStructFromInterface(&s, &i, "json", parsers, stringParser, true)
	assert.EqualError(t, err, "invalid value: expected a *testStruct, but found *int")

	type test2 struct{}
	t2 := test2{}

	err = populateStructFromInterface(&s, t2, "json", parsers, stringParser, true)
	assert.EqualError(t, err, "invalid value '{}': expected a testStruct, but found ear.test2")

	err = populateStructFromInterface(&s, &t2, "json", parsers, stringParser, true)
	assert.EqualError(t, err, "invalid value: expected a *testStruct, but found *ear.test2")
}

type myMapable struct {
	Key string `json:"key"`
}

func (o myMapable) AsMap() map[string]interface{} {
	return map[string]interface{}{
		o.Key: 1,
	}
}

func Test_structAsMap(t *testing.T) {

	type MyEmbedded struct {
		FieldOne *string `json:"embedded-field-one,omitempty"`
	}

	type MyStruct struct {
		FieldOne   *string               `json:"field-one"`
		FieldTwo   string                `json:"field-two"`
		FieldThree *int                  `json:"field-three,omitempty"`
		FieldFour  *myMapable            `json:"field-four,omitempty"`
		FieldFive  myMapable             `json:"field-five"`
		FieldSix   string                // untagged
		FieldSeven string                `cbor:"7,keyasint"` // tagged by no "json"
		FieldEight map[string]*myMapable `json:"field-eight,omitempty"`
		FieldNine  []*myMapable          `json:"field-nine,omitempty"`

		MyEmbedded
	}

	f1 := "first field"
	f3 := 1337
	f4 := myMapable{Key: "inner"}
	fe := "embedded field"

	v := MyStruct{
		FieldOne:   &f1,
		FieldTwo:   "second field",
		FieldThree: &f3,
		FieldFour:  &f4,
		FieldFive:  myMapable{Key: "inner"},
		FieldSix:   "sixth field",
		FieldSeven: "Seventh field",
		FieldEight: map[string]*myMapable{
			"field-eight-sub-one": &f4,
		},
		FieldNine: []*myMapable{&f4},
		MyEmbedded: MyEmbedded{
			FieldOne: &fe,
		},
	}

	expected := map[string]interface{}{
		"field-one":   "first field",
		"field-two":   "second field",
		"field-three": 1337,
		"field-four": map[string]interface{}{
			"inner": 1,
		},
		"field-five": map[string]interface{}{
			"inner": 1,
		},
		"field-eight": map[string]interface{}{
			"field-eight-sub-one": map[string]interface{}{
				"key": "inner",
			},
		},
		"field-nine": []interface{}{
			map[string]interface{}{
				"key": "inner",
			},
		},
		"embedded-field-one": "embedded field",
	}

	m, err := structAsMap(v, "json")
	require.NoError(t, err)
	assert.Equal(t, expected, m)

	v = MyStruct{
		FieldOne:   nil,
		FieldTwo:   "second field",
		FieldThree: &f3,
		FieldFour:  nil,
		FieldFive:  myMapable{Key: "inner"},
		FieldSix:   "sixth field",
		FieldSeven: "Seventh field",
		MyEmbedded: MyEmbedded{
			FieldOne: &fe,
		},
	}

	expected = map[string]interface{}{
		"field-one":   nil,
		"field-two":   "second field",
		"field-three": 1337,
		"field-five": map[string]interface{}{
			"inner": 1,
		},
		"field-eight":        map[string]interface{}{},
		"field-nine":         []interface{}{},
		"embedded-field-one": "embedded field",
	}

	m, err = structAsMap(v, "json")
	require.NoError(t, err)
	assert.Equal(t, expected, m)

	_, err = structAsMap(7, "json")
	assert.EqualError(t, err, "invalid value: must be a Struct or a *Struct")
}
