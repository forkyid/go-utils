package env

import (
	"os"
	"strconv"
)

func GetStr(key string, fallback ...string) string {
	if value, isExist := os.LookupEnv(key); isExist {
		return value
	}
	if len(fallback) > 0 {
		return fallback[0]
	}
	return ""
}

func GetInt(key string, fallback ...int) int {
	if val, isExist := os.LookupEnv(key); isExist {
		if conVal, err := strconv.Atoi(val); err == nil {
			return conVal
		}
	}
	if len(fallback) > 0 {
		return fallback[0]
	}
	return 0
}

func GetBool(key string, fallback ...bool) bool {
	if val, isExist := os.LookupEnv(key); isExist {
		if conVal, err := strconv.ParseBool(val); err == nil {
			return conVal
		}
	}
	if len(fallback) > 0 {
		return fallback[0]
	}
	return false
}
