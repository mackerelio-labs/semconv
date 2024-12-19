package main

import "iter"

func Uniq[T comparable](seq iter.Seq[T]) iter.Seq[T] {
	return func(yield func(T) bool) {
		m := make(map[T]struct{})
		for v := range seq {
			if _, ok := m[v]; ok {
				continue
			}
			if !yield(v) {
				return
			}
			m[v] = struct{}{}
		}
	}
}
