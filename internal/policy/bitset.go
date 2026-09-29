package policy

import "math/bits"

// bitset is a fixed-size set of rule indices backed by a []uint64. It is the
// core of the indexed evaluator: posting lists and the allow/deny masks are all
// bitsets over rule IDs, so a decision reduces to a few word-wise OR/AND ops
// instead of a scan over every rule.
//
// All bitsets in a snapshot share the same word length (derived from the rule
// count), so the elementwise operations below never need bounds reconciliation.
type bitset []uint64

func newBitset(nBits int) bitset {
	return make(bitset, (nBits+63)/64)
}

func (b bitset) set(i int) {
	b[i>>6] |= 1 << (uint(i) & 63)
}

// orWith folds o into b (b |= o).
func (b bitset) orWith(o bitset) {
	for i := range b {
		b[i] |= o[i]
	}
}

// andWith intersects o into b (b &= o).
func (b bitset) andWith(o bitset) {
	for i := range b {
		b[i] &= o[i]
	}
}

// andClone returns a new bitset equal to b & mask, leaving both operands intact.
func (b bitset) andClone(mask bitset) bitset {
	out := make(bitset, len(b))
	for i := range b {
		out[i] = b[i] & mask[i]
	}
	return out
}

// forEach calls fn for each set bit, in ascending index order.
func (b bitset) forEach(fn func(i int)) {
	for wi, w := range b {
		for w != 0 {
			fn(wi<<6 + bits.TrailingZeros64(w))
			w &= w - 1 // clear the lowest set bit
		}
	}
}

// ids maps the set bits to their rule IDs, in ascending (file) order. Returns
// nil when empty so callers see the same value as the reference implementation.
func (b bitset) ids(rules []Rule) []string {
	var out []string
	b.forEach(func(i int) { out = append(out, rules[i].ID) })
	return out
}
