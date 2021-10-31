package cityhash_test

import (
	"fmt"
	"testing"

	"github.com/creachadair/cityhash"
)

func BenchmarkHash64(b *testing.B) {
	for i := 10; i < 1000000; i *= 10 {
		buf := make([]byte, i)
		b.Run(fmt.Sprintf("Size-%d", i), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				cityhash.Hash64(buf)
			}
		})
	}
}

func BenchmarkHash32(b *testing.B) {
	for i := 10; i < 1000000; i *= 10 {
		buf := make([]byte, i)
		b.Run(fmt.Sprintf("Size-%d", i), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				cityhash.Hash32(buf)
			}
		})
	}
}
