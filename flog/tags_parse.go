package flog

import "strings"

func ParseTags(t string, f func(s string)) {
	l := strings.Split(t, ",")
	for _, x := range l {
		f(x)
	}
}
