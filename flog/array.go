package flog

import "strings"

func containString(arr []string, str string) bool {
	for _, s := range arr {
		if strings.EqualFold(s, str) {
			return true
		}
	}
	return false
}
