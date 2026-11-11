package logstorage

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/cespare/xxhash/v2"
)

func TestTokenizeHashes(t *testing.T) {
	f := func(a []string, hashesExpected []uint64) {
		t.Helper()
		hashes := tokenizeHashes(nil, a)
		if !reflect.DeepEqual(hashes, hashesExpected) {
			t.Fatalf("unexpected hashes\ngot\n%X\nwant\n%X", hashes, hashesExpected)
		}
	}

	f(nil, nil)
	f([]string{""}, nil)
	f([]string{"foo"}, []uint64{0x33BF00A859C4BA3F})
	f([]string{"foo foo", "!!foo //"}, []uint64{0x33BF00A859C4BA3F})
	f([]string{"foo bar---.!!([baz]!!! %$# TaSte"}, []uint64{0x33BF00A859C4BA3F, 0x48A37C90AD27A659, 0x42598CF26A247404, 0x34709F40A3286E46})
	f([]string{"foo bar---.!!([baz]!!! %$# baz foo TaSte"}, []uint64{0x33BF00A859C4BA3F, 0x48A37C90AD27A659, 0x42598CF26A247404, 0x34709F40A3286E46})
	f([]string{"теСТ 1234 f12.34", "34 f12 AS"}, []uint64{0xFE846FA145CEABD1, 0xD8316E61D84F6BA4, 0x6D67BA71C4E03D10, 0x5E8D522CA93563ED, 0xED80AED10E029FC8})
}

func TestTokenizeHashesManyUniqueTokens(t *testing.T) {
	f := func(tokensCount int) {
		t.Helper()

		// Every token appears twice in order to verify deduplication after the hash set grows.
		a := make([]string, 0, 2*tokensCount)
		for i := range 2 * tokensCount {
			a = append(a, fmt.Sprintf("token_%d", i%tokensCount))
		}
		hashes := tokenizeHashes(nil, a)
		if len(hashes) != tokensCount {
			t.Fatalf("unexpected number of unique hashes; got %d; want %d", len(hashes), tokensCount)
		}
		m := make(map[uint64]struct{}, len(hashes))
		for i, h := range hashes {
			if hExpected := xxhash.Sum64String(a[i]); h != hExpected {
				t.Fatalf("unexpected hash at position %d; got %X; want %X", i, h, hExpected)
			}
			m[h] = struct{}{}
		}
		if len(m) != len(hashes) {
			t.Fatalf("duplicate hashes found; got %d unique hashes out of %d", len(m), len(hashes))
		}
	}
	f(1)
	f(hashTokenizerMinSlotsCount / 2)
	f(hashTokenizerMinSlotsCount/2 + 1)
	f(hashTokenizerMinSlotsCount)
	f(100_000)
}

func TestHashTokenizerAddHash(t *testing.T) {
	ht := newHashTokenizer()
	defer putHashTokenizer(ht)

	// zero hash cannot be stored in slots, since it marks an empty slot
	if !ht.addHash(0) {
		t.Fatalf("expecting true for the first zero hash")
	}
	if ht.addHash(0) {
		t.Fatalf("expecting false for the second zero hash")
	}

	// hashes colliding on the same slot must be stored in different slots
	mask := uint64(hashTokenizerMinSlotsCount - 1)
	for i := uint64(1); i <= 10; i++ {
		h := i*(mask+1) + 5
		if !ht.addHash(h) {
			t.Fatalf("expecting true for the first addition of %X", h)
		}
	}
	for i := uint64(1); i <= 10; i++ {
		h := i*(mask+1) + 5
		if ht.addHash(h) {
			t.Fatalf("expecting false for the second addition of %X", h)
		}
	}
	if ht.itemsCount != 10 {
		t.Fatalf("unexpected itemsCount; got %d; want 10", ht.itemsCount)
	}

	// hashes at the end of slots must wrap to the beginning of slots
	if !ht.addHash(mask) || !ht.addHash(2*mask+1) {
		t.Fatalf("expecting true for hashes at the last slot")
	}
	if ht.addHash(2*mask + 1) {
		t.Fatalf("expecting false for the duplicate hash at the wrapped slot")
	}
}

func TestHashTokenizerReset(t *testing.T) {
	ht := newHashTokenizer()

	// grow the hash set
	for i := uint64(1); i <= 100_000; i++ {
		ht.addHash(i)
	}
	if n := len(ht.slots); n < 200_000 {
		t.Fatalf("unexpected number of slots after adding 100K hashes: %d", n)
	}
	if n := len(ht.slots); n&(n-1) != 0 {
		t.Fatalf("the number of slots must be power of two; got %d", n)
	}

	// The first reset keeps the slots, since they are needed for the same number of items.
	slotsCount := len(ht.slots)
	ht.reset()
	if len(ht.slots) != slotsCount {
		t.Fatalf("unexpected number of slots after reset; got %d; want %d", len(ht.slots), slotsCount)
	}
	if ht.itemsCount != 0 || ht.hasZeroHash {
		t.Fatalf("unexpected state after reset: itemsCount=%d, hasZeroHash=%v", ht.itemsCount, ht.hasZeroHash)
	}
	for i, h := range ht.slots {
		if h != 0 {
			t.Fatalf("unexpected non-zero slot %d after reset: %X", i, h)
		}
	}

	// The next reset after adding a few items must release the memory occupied by big slots
	ht.addHash(0)
	ht.addHash(1)
	ht.reset()
	if len(ht.slots) != hashTokenizerMinSlotsCount {
		t.Fatalf("unexpected number of slots after reset; got %d; want %d", len(ht.slots), hashTokenizerMinSlotsCount)
	}
	if !ht.addHash(0) || !ht.addHash(1) {
		t.Fatalf("the hash set must be empty after reset")
	}
}

func TestGetHashTokenizerSlotsCount(t *testing.T) {
	f := func(itemsCount, slotsCountExpected int) {
		t.Helper()
		if n := getHashTokenizerSlotsCount(itemsCount); n != slotsCountExpected {
			t.Fatalf("unexpected slots count for %d items; got %d; want %d", itemsCount, n, slotsCountExpected)
		}
	}
	f(0, hashTokenizerMinSlotsCount)
	f(hashTokenizerMinSlotsCount/2, hashTokenizerMinSlotsCount)
	f(hashTokenizerMinSlotsCount/2+1, 2*hashTokenizerMinSlotsCount)
	f(hashTokenizerMinSlotsCount, 2*hashTokenizerMinSlotsCount)
	f(hashTokenizerMinSlotsCount+1, 4*hashTokenizerMinSlotsCount)
}

func FuzzTokenizeHashes(f *testing.F) {
	f.Add("foo bar baz foo")
	f.Add("")
	f.Add("теСТ 1234 f12.34 34 f12 AS")
	f.Fuzz(func(t *testing.T, s string) {
		values := strings.Split(s, "\n")
		hashes := tokenizeHashes(nil, values)

		// The result must match the unique token hashes in the order of their appearance.
		var hashesExpected []uint64
		seen := make(map[uint64]struct{})
		for _, token := range tokenizeStrings(nil, values) {
			h := xxhash.Sum64String(token)
			if _, ok := seen[h]; !ok {
				seen[h] = struct{}{}
				hashesExpected = append(hashesExpected, h)
			}
		}
		if !reflect.DeepEqual(hashes, hashesExpected) {
			t.Fatalf("unexpected hashes for %q\ngot\n%X\nwant\n%X", s, hashes, hashesExpected)
		}
	})
}

func TestHashTokenizerGrowKeepsAllHashes(t *testing.T) {
	ht := newHashTokenizer()
	const n = 10 * hashTokenizerMinSlotsCount
	for h := uint64(0); h < n; h++ {
		if !ht.addHash(h) {
			t.Fatalf("unexpected duplicate for hash %d", h)
		}
	}
	for h := uint64(0); h < n; h++ {
		if ht.addHash(h) {
			t.Fatalf("hash %d must be detected as duplicate after growing the hash set", h)
		}
	}
}
