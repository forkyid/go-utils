package pagination

import (
	"fmt"
	"hash/fnv"
	"strings"
)

type SortDirection string

const (
	Ascending  SortDirection = "asc"
	Descending SortDirection = "desc"
)

func ParseDirectionByte(x byte) SortDirection {
	switch x {
	case 0x01:
		return Ascending
	case 0x02:
		return Descending
	}

	return ""
}

func (s SortDirection) Byte() byte {
	switch s {
	case Ascending:
		return 0x01
	case Descending:
		return 0x02
	}

	return 0x00
}

func (s SortDirection) GetOp(inclusive bool) string {
	str := "<"
	if s == Ascending {
		str = ">"
	}

	if inclusive {
		str += "="
	}

	return str
}

func (s SortDirection) ToUpper() string {
	return strings.ToUpper(string(s))
}

func (s SortDirection) String() string {
	return string(s)
}

func (s SortDirection) Reverse() SortDirection {
	if s == Ascending {
		return Descending
	}
	return Ascending
}

type NullOrder string

const (
	First NullOrder = "first"
	Last  NullOrder = "last"
)

func ParseNullOrder(x byte) NullOrder {
	switch x {
	case 0x01:
		return First
	case 0x02:
		return Last
	}

	return ""
}

func (no NullOrder) Byte() byte {
	switch no {
	case First:
		return 0x01
	case Last:
		return 0x02
	}

	return 0x00
}

func (no NullOrder) ToUpper() string {
	return strings.ToUpper(string(no))
}

func (no NullOrder) Reverse() NullOrder {
	switch no {
	case First:
		return Last
	case Last:
		return First
	}

	return ""
}

type SortOrder struct {
	hashedKey uint32
	Key       string
	Direction SortDirection
	NullOrder NullOrder
}

func (so SortOrder) IsNullable() bool {
	return so.NullOrder != ""
}

func (so SortOrder) String() string {
	if so.NullOrder != "" {
		return fmt.Sprintf("%s %s NULLS %s", so.Key, so.Direction.ToUpper(), so.NullOrder)
	}

	return fmt.Sprintf("%s %s", so.Key, so.Direction.ToUpper())
}

type OrderBuilder interface {
	Build() []SortOrder
	String() string
}

type SingleSortOrder SortOrder

func (sso SingleSortOrder) Build() []SortOrder {
	fnv := fnv.New32a()
	fnv.Write([]byte(sso.Key))

	sso.hashedKey = fnv.Sum32()
	return []SortOrder{SortOrder(sso)}
}

type SortOrderArray []SortOrder

func (soa SortOrderArray) Build() []SortOrder {
	fnv := fnv.New32a()
	for i, _ := range soa {
		fnv.Reset()

		fnv.Write([]byte(soa[i].Key))
		soa[i].hashedKey = fnv.Sum32()
	}

	return soa
}

func (soa SortOrderArray) String() string {
	arr := []string{}
	for _, v := range soa {
		arr = append(arr, v.String())
	}

	return strings.Join(arr, ", ")
}

// RawSortOrder specifies sorting sequences used in database queries.
//
// Defaults to non-nullable columns unless NULLS (FIRST/LAST) is explicitly defined.
//
// Usage:
//
//	// Non-nullable columns
//	pagination.RawSortOrder("created_at DESC, id DESC")
//
//	// Nullable columns
//	pagination.RawSortOrder("name DESC NULLS LAST, id DESC")
func RawSortOrder(str string) OrderBuilder {
	items := strings.Split(string(str), ",")
	sortOrders := make(SortOrderArray, 0)
	for _, item := range items {
		item = strings.ToLower(item)
		keys := strings.Fields(item)
		so := SortOrder{}
		if !strings.Contains(item, Ascending.String()) && !strings.Contains(item, Descending.String()) {
			so.Key, so.Direction = keys[0], Ascending
		} else if len(keys) > 1 {
			so.Key, so.Direction = keys[0], SortDirection(keys[1])
		}

		// looks like column is nullable
		if strings.Contains(item, "nulls") {
			so.NullOrder = NullOrder(keys[3])
		}

		sortOrders = append(sortOrders, so)
	}
	return sortOrders
}
