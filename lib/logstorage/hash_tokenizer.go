package logstorage

import (
	"math/bits"
	"sync"

	"github.com/cespare/xxhash/v2"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
)

// tokenizeHashes extracts word tokens from a, hashes them, appends hashes to dst and returns the result.
//
// The returned hashes must be passed to bloomFilterMarshalHashes in order to build bloom filters.
// The returned hashes must be passed to appendHashesHashes before being passed to bloomFilter.containsAll.
func tokenizeHashes(dst []uint64, a []string) []uint64 {
	t := getHashTokenizer()
	for i, s := range a {
		if i > 0 && s == a[i-1] {
			// This string has been already tokenized
			continue
		}
		dst = t.tokenizeString(dst, s)
	}
	putHashTokenizer(t)

	return dst
}

// hashTokenizerMinSlotsCount is the minimum number of slots in hashTokenizer hash set.
const hashTokenizerMinSlotsCount = 1024

// hashTokenizer deduplicates token hashes.
//
// It uses open addressing hash set with linear probing, which grows with the number of unique tokens,
// so the cost of adding a token doesn't depend on the number of unique tokens.
type hashTokenizer struct {
	// slots contains the unique token hashes. Zero value marks an empty slot.
	//
	// The number of slots is always a power of two.
	slots []uint64

	// itemsCount is the number of non-zero hashes in slots.
	itemsCount int

	// hasZeroHash is set to true if zero hash has been added.
	hasZeroHash bool
}

func newHashTokenizer() *hashTokenizer {
	return &hashTokenizer{
		slots: make([]uint64, hashTokenizerMinSlotsCount),
	}
}

func (t *hashTokenizer) reset() {
	// Release the memory occupied by too big slots, which may be left after processing values with many unique tokens.
	slotsCount := getHashTokenizerSlotsCount(t.itemsCount)
	if len(t.slots) > 4*slotsCount {
		t.slots = make([]uint64, slotsCount)
	} else {
		clear(t.slots)
	}
	t.itemsCount = 0
	t.hasZeroHash = false
}

// getHashTokenizerSlotsCount returns the number of slots needed for holding itemsCount hashes.
func getHashTokenizerSlotsCount(itemsCount int) int {
	n := 2 * itemsCount
	if n <= hashTokenizerMinSlotsCount {
		return hashTokenizerMinSlotsCount
	}
	return 1 << bits.Len(uint(n-1))
}

func (t *hashTokenizer) tokenizeString(dst []uint64, s string) []uint64 {
	if !isASCII(s) {
		// Slow path - s contains unicode chars
		return t.tokenizeStringUnicode(dst, s)
	}

	// Fast path for ASCII s
	i := 0
	for i < len(s) {
		// Search for the next token.
		start := len(s)
		for i < len(s) {
			if !isTokenChar(s[i]) {
				i++
				continue
			}
			start = i
			i++
			break
		}
		// Search for the end of the token.
		end := len(s)
		for i < len(s) {
			if isTokenChar(s[i]) {
				i++
				continue
			}
			end = i
			i++
			break
		}
		if end <= start {
			break
		}

		// Register the token.
		token := s[start:end]
		if h, ok := t.addToken(token); ok {
			dst = append(dst, h)
		}
	}
	return dst
}

func (t *hashTokenizer) tokenizeStringUnicode(dst []uint64, s string) []uint64 {
	for len(s) > 0 {
		// Search for the next token.
		n := len(s)
		for offset, r := range s {
			if isTokenRune(r) {
				n = offset
				break
			}
		}
		s = s[n:]
		// Search for the end of the token.
		n = len(s)
		for offset, r := range s {
			if !isTokenRune(r) {
				n = offset
				break
			}
		}
		if n == 0 {
			break
		}

		// Register the token
		token := s[:n]
		s = s[n:]
		if h, ok := t.addToken(token); ok {
			dst = append(dst, h)
		}
	}
	return dst
}

func (t *hashTokenizer) addToken(token string) (uint64, bool) {
	h := xxhash.Sum64(bytesutil.ToUnsafeBytes(token))
	return h, t.addHash(h)
}

// addHash adds h to t and returns true if h hasn't been added before.
func (t *hashTokenizer) addHash(h uint64) bool {
	if h == 0 {
		if t.hasZeroHash {
			return false
		}
		t.hasZeroHash = true
		return true
	}

	slots := t.slots
	mask := uint64(len(slots) - 1)
	i := h & mask
	for {
		v := slots[i]
		if v == h {
			return false
		}
		if v == 0 {
			break
		}
		i = (i + 1) & mask
	}

	slots[i] = h
	t.itemsCount++
	if 2*t.itemsCount > len(slots) {
		t.grow()
	}
	return true
}

func (t *hashTokenizer) grow() {
	slotsOld := t.slots
	slots := make([]uint64, 2*len(slotsOld))
	mask := uint64(len(slots) - 1)
	for _, h := range slotsOld {
		if h == 0 {
			continue
		}
		i := h & mask
		for slots[i] != 0 {
			i = (i + 1) & mask
		}
		slots[i] = h
	}
	t.slots = slots
}

func getHashTokenizer() *hashTokenizer {
	v := hashTokenizerPool.Get()
	if v == nil {
		return newHashTokenizer()
	}
	return v.(*hashTokenizer)
}

func putHashTokenizer(t *hashTokenizer) {
	t.reset()
	hashTokenizerPool.Put(t)
}

var hashTokenizerPool sync.Pool
