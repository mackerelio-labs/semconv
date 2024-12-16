// Package syntax provides utilities for querying or manipulating Go sources.
package syntax

import (
	"go/ast"
	"iter"
)

// Lookup returns a first node matched by f.
func Lookup[T ast.Node, E any](node ast.Node, f func(T) (E, bool)) (E, bool) {
	for n := range ast.Preorder(node) {
		p, ok := n.(T)
		if !ok {
			continue
		}
		v, ok := f(p)
		if !ok {
			continue
		}
		return v, true
	}
	var zero E
	return zero, false
}

// Search returns an iterator over specified nodes by f.
func Search[T ast.Node, E any](node ast.Node, f func(T) (E, bool)) iter.Seq[E] {
	return func(yield func(E) bool) {
		for n := range ast.Preorder(node) {
			p, ok := n.(T)
			if !ok {
				continue
			}
			v, ok := f(p)
			if !ok {
				continue
			}
			if !yield(v) {
				break
			}
		}
	}
}
