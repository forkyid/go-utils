package pagination

import (
	"errors"
	"fmt"
	"reflect"
	"time"
)

type Kind int32

const (
	KindInt Kind = iota
	KindString
	KindBool
	KindTime
	KindFloat
	KindNil
)

type Value struct {
	K Kind
	I int64
	F float64
	S string
	B bool
	T time.Time
}

func (v Value) GetAny() any {
	switch v.K {
	case KindInt:
		return v.I
	case KindBool:
		return v.B
	case KindFloat:
		return v.F
	case KindTime:
		return v.T
	case KindString:
		return v.S
	}

	return nil
}

func Int[T uint | uint8 | uint16 | uint32 |
	uint64 | int | int8 | int16 | int32 | int64](v T) Value {
	return Value{K: KindInt, I: int64(v)}
}
func Float[T float32 | float64](v T) Value {
	return Value{K: KindFloat, F: float64(v)}
}

func String(v string) Value {
	return Value{K: KindString, S: v}
}

func Bool(v bool) Value {
	return Value{K: KindBool, B: v}
}

func Time(v time.Time) Value {
	return Value{K: KindTime, T: v}
}

func parseValue(item any) (Value, error) {
	switch v := item.(type) {
	case int:
		return Int(v), nil
	case int8:
		return Int(v), nil
	case int16:
		return Int(v), nil
	case int32:
		return Int(v), nil
	case int64:
		return Int(v), nil
	case uint:
		return Int(v), nil
	case uint16:
		return Int(v), nil
	case uint32:
		return Int(v), nil
	case uint64:
		return Int(v), nil
	case string:
		return String(v), nil
	case bool:
		return Bool(v), nil
	case float32:
		return Float(v), nil
	case float64:
		return Float(v), nil
	case time.Time:
		return Time(v), nil
	}

	v := reflect.ValueOf(item)
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		if v.IsNil() {
			return Value{K: KindNil}, nil
		}
	}

	return Value{K: -1}, errors.New(fmt.Sprintf("unsupported data type for %v", reflect.TypeOf(item).Name()))
}
