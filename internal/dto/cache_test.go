package dto

import (
	"reflect"
	"testing"
)

type CustomStruct struct {
	X int
}

func (s CustomStruct) Method1() {}

type CustomInterface interface {
	Method1()
}

var (
	justStruct                     = CustomStruct{1}
	ptrStruct                      = &CustomStruct{2}
	emptyIface     interface{}     = CustomStruct{3}
	iface1         CustomInterface = CustomStruct{4}
	sliceStruct                    = []CustomStruct{{5}, {6}, {7}}
	ptrSliceStruct                 = []*CustomStruct{{8}, {9}, {10}}

	valueMap = map[string]interface{}{
		"bytes":          []byte{0x61, 0x62, 0x63, 0x64},
		"string":         "string",
		"bool":           true,
		"int":            5,
		"int8":           int8(5),
		"int16":          int16(5),
		"int32":          int32(5),
		"int64":          int64(5),
		"uint":           uint(5),
		"uint8":          uint8(5),
		"uint16":         uint16(5),
		"uint32":         uint32(5),
		"uint64":         uint64(5),
		"float32":        float32(5),
		"float64":        float64(5),
		"array":          [5]int{1, 2, 3, 4, 5},
		"slice":          []int{1, 2, 3, 4, 5},
		"emptyIf":        emptyIface,
		"Iface1":         iface1,
		"map":            map[string]string{"foo": "bar"},
		"ptrStruct":      ptrStruct,
		"justStruct":     justStruct,
		"sliceStruct":    sliceStruct,
		"ptrSliceStruct": ptrSliceStruct,
	}
)

func TestRoundTrip(t *testing.T) {

	for _, expected := range valueMap {
		bytes, err := Serialize(expected)
		if err != nil {
			t.Error(err)
			continue
		}

		ptrActual := reflect.New(reflect.TypeOf(expected)).Interface()
		err = Deserialize(bytes, ptrActual)
		if err != nil {
			t.Error(err)
			continue
		}

		actual := reflect.ValueOf(ptrActual).Elem().Interface()
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("(expected) %T %v != %T %v (actual)", expected, expected, actual, actual)
		}
	}
}
