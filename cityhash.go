// Package cityhash implements the CityHash family of non-cryptographic string
// hashing functions.
//
// The implementation is a fairly straightforward transliteration of the C++
// code from http://code.google.com/p/cityhash/.  Most of the comments from the
// original are preserved here, except where they are obviously not true in the
// transliterated code.
//
// The implementation of CityHash128 is not yet complete.
package cityhash

// Some primes between 2^63 and 2^64 for various uses.
const (
	k0 = uint64(0xc3a5c85c97cb3127)
	k1 = uint64(0xb492b66fbe98f273)
	k2 = uint64(0x9ae16a3b2f90404f)
)

// Magic numbers for 32-bit hashing.  Copied from Murmur3.
const (
	c1 = uint32(0xcc9e2d51)
	c2 = uint32(0x1b873593)
)

// Hash64 returns a 64-bit hash for a slice of bytes.
func Hash64(s []byte) uint64 {
	n := uint64(len(s))
	if n <= 32 {
		if n <= 16 {
			return hash64Len0to16(s)
		} else {
			return hash64Len17to32(s)
		}
	} else if n <= 64 {
		return hash64Len33to64(s)
	}

	// For strings over 64 bytes we hash the end first, and then as we loop we
	// keep 56 bytes of state: v, w, x, y, and z.
	x := fetch64(s[n-40:])
	y := fetch64(s[n-16:]) + fetch64(s[n-56:])
	z := hash64Len16(fetch64(s[n-48:])+n, fetch64(s[n-24:]))

	v1, v2 := weakHashLen32WithSeeds(s[n-64:], n, z)
	w1, w2 := weakHashLen32WithSeeds(s[n-32:], y+k1, x)
	x = x*k1 + fetch64(s)

	// Decrease n to the nearest multiple of 64, and operate on 64-byte chunks.
	n = (n - 1) &^ 63
	for {
		x = ror64(x+y+v1+fetch64(s[8:]), 37) * k1
		y = ror64(y+v2+fetch64(s[48:]), 42) * k1
		x ^= w2
		y += v1 + fetch64(s[40:])
		z = ror64(z+w1, 33) * k1
		v1, v2 = weakHashLen32WithSeeds(s, v2*k1, x+w1)
		w1, w2 = weakHashLen32WithSeeds(s[32:], z+w2, y+fetch64(s[16:]))
		z, x = x, z
		s = s[64:]
		n -= 64
		if n == 0 {
			break
		}
	}
	return hash64Len16(hash64Len16(v1, w1)+shiftMix(y)*k1+z, hash64Len16(v2, w2)+x)
}

// Hash64WithSeed returns a 64-bit hash for s that includes seed.
func Hash64WithSeed(s []byte, seed uint64) uint64 {
	return Hash64WithSeeds(s, k2, seed)
}

// Hash64WithSeeds returns a 64-bit hash for s that includes the two seed
// values.
func Hash64WithSeeds(s []byte, seed0, seed1 uint64) uint64 {
	return hash64Len16(Hash64(s)-seed0, seed1)
}

func cityHash128(s []byte) (lo, hi uint64) {
	return 0, 0
}

func cityHash128WithSeed(s []byte, loSeed, hiSeed uint64) (lo, hi uint64) {
	return 0, 0
}

// Hash32 returns a 32-bit hash for s.
func Hash32(s []byte) uint32 {
	n := uint32(len(s))
	if n <= 24 {
		if n <= 12 {
			if n <= 4 {
				return hash32Len0to4(s)
			}
			return hash32Len5to12(s)
		}
		return hash32Len13to24(s)
	}

	// n > 24
	h := n
	g := c1 * n
	f := g

	a0 := ror32(fetch32(s[n-4:])*c1, 17) * c2
	a1 := ror32(fetch32(s[n-8:])*c1, 17) * c2
	a2 := ror32(fetch32(s[n-16:])*c1, 17) * c2
	a3 := ror32(fetch32(s[n-12:])*c1, 17) * c2
	a4 := ror32(fetch32(s[n-20:])*c1, 17) * c2

	const magic = 0xe6546b64
	h ^= a0
	h = ror32(h, 19)
	h = h*5 + magic
	h ^= a2
	h = ror32(h, 19)
	h = h*5 + magic
	g ^= a1
	g = ror32(g, 19)
	g = g*5 + magic
	g ^= a3
	g = ror32(g, 19)
	g = g*5 + magic
	f += a4
	f = ror32(f, 19)
	f = f*5 + magic
	for i := (n - 1) / 20; i != 0; i-- {
		a0 := ror32(fetch32(s)*c1, 17) * c2
		a1 := fetch32(s[4:])
		a2 := ror32(fetch32(s[8:])*c1, 17) * c2
		a3 := ror32(fetch32(s[12:])*c1, 17) * c2
		a4 := fetch32(s[16:])
		h ^= a0
		h = ror32(h, 18)
		h = h*5 + magic
		f += a1
		f = ror32(f, 19)
		f = f * c1
		g += a2
		g = ror32(g, 18)
		g = g*5 + magic
		h ^= a3 + a1
		h = ror32(h, 19)
		h = h*5 + magic
		g ^= a4
		g = bswap32(g) * 5
		h += a4 * 5
		h = bswap32(h)
		f += a0
		f, g, h = g, h, f // a.k.a. PERMUTE3
		s = s[20:]
	}
	g = ror32(g, 11) * c1
	g = ror32(g, 17) * c1
	f = ror32(f, 11) * c1
	f = ror32(f, 17) * c1
	h = ror32(h+g, 19)
	h = h*5 + magic
	h = ror32(h, 17) * c1
	h = ror32(h+f, 19)
	h = h*5 + magic
	h = ror32(h, 17) * c1
	return h
}

// Hash128To64 returns a 64-bit hash value for an input of 128 bits.
func Hash128To64(lo, hi uint64) uint64 {
	// Murmur-inspired hashing.
	const multiplier = 0x9ddfea08eb382d69

	a := (lo ^ hi) * multiplier
	a ^= (a >> 47)
	b := (hi ^ a) * multiplier
	b ^= (b >> 47)
	b *= multiplier
	return b
}
