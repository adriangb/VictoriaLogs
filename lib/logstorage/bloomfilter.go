package logstorage

import (
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"

	"github.com/cespare/xxhash/v2"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/encoding"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/slicesutil"
)

// bloomFilterHashesCount is the number of different hashes to use for bloom filter.
const bloomFilterHashesCount = 6

// bloomFilterBitsPerItem is the number of bits to use per each token.
const bloomFilterBitsPerItem = 16

// bloomFilterMarshalTokens appends marshaled bloom filter for tokens to dst and returns the result.
func bloomFilterMarshalTokens(dst []byte, tokens []string) []byte {
	bf := getBloomFilter()
	bf.mustInitTokens(tokens)
	dst = bf.marshal(dst)
	putBloomFilter(bf)
	return dst
}

// bloomFilterMarshalHashes appends marshaled bloom filter for hashes to dst and returns the result.
func bloomFilterMarshalHashes(dst []byte, hashes []uint64) []byte {
	bf := getBloomFilter()
	bf.mustInitHashes(hashes)
	dst = bf.marshal(dst)
	putBloomFilter(bf)
	return dst
}

type bloomFilter struct {
	// bits contains bloom filter words in the marshaled byte order (big-endian), so marshal and unmarshal are plain copies.
	//
	// Use bloomFilterBitMask for accessing individual bits.
	bits []uint64
}

// bloomFilterBitMask returns the mask for the bit j in a bloomFilter.bits word.
func bloomFilterBitMask(j uint64) uint64 {
	// Swapping the bytes of a word maps its bit j to the bit j^56.
	return uint64(1) << ((j ^ bloomFilterBitIndexXor) & 63)
}

// bloomFilterBitIndexXor is 56 on little-endian architectures, where bloomFilter.bits words are stored with swapped bytes, and 0 otherwise.
var bloomFilterBitIndexXor = func() uint64 {
	if binary.NativeEndian.Uint16([]byte{1, 0}) == 1 {
		return 56
	}
	return 0
}()

// bloomFilterWordsBytes returns bits as a byte slice.
func bloomFilterWordsBytes(bits []uint64) []byte {
	if len(bits) == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&bits[0])), len(bits)*8)
}

func (bf *bloomFilter) reset() {
	clear(bf.bits)
	bf.bits = bf.bits[:0]
}

// marshal appends marshaled bf to dst and returns the result.
func (bf *bloomFilter) marshal(dst []byte) []byte {
	return append(dst, bloomFilterWordsBytes(bf.bits)...)
}

// unmarshal unmarshals bf from src.
func (bf *bloomFilter) unmarshal(src []byte) error {
	if len(src)%8 != 0 {
		return fmt.Errorf("cannot unmarshal bloomFilter from src with size not multiple by 8; len(src)=%d", len(src))
	}
	// There is no need in clearing bf.bits, since they are overwritten below.
	bits := slicesutil.SetLength(bf.bits[:0], len(src)/8)
	copy(bloomFilterWordsBytes(bits), src)
	bf.bits = bits
	return nil
}

// mustInitTokens initializes bf with the given tokens
func (bf *bloomFilter) mustInitTokens(tokens []string) {
	bitsCount := len(tokens) * bloomFilterBitsPerItem
	wordsCount := (bitsCount + 63) / 64
	bits := slicesutil.SetLength(bf.bits, wordsCount)
	bloomFilterAddTokens(bits, tokens)
	bf.bits = bits
}

// mustInitHashes initializes bf with the given hashes
func (bf *bloomFilter) mustInitHashes(hashes []uint64) {
	bitsCount := len(hashes) * bloomFilterBitsPerItem
	wordsCount := (bitsCount + 63) / 64
	bits := slicesutil.SetLength(bf.bits, wordsCount)
	bloomFilterAddHashes(bits, hashes)
	bf.bits = bits
}

// bloomFilterAddTokens adds the given tokens to the bloom filter bits
func bloomFilterAddTokens(bits []uint64, tokens []string) {
	hashesCount := len(tokens) * bloomFilterHashesCount
	a := encoding.GetUint64s(hashesCount)
	a.A = appendTokensHashes(a.A[:0], tokens)
	initBloomFilter(bits, a.A)
	encoding.PutUint64s(a)
}

// bloomFilterAddHashes adds the given haehs to the bloom filter bits
func bloomFilterAddHashes(bits, hashes []uint64) {
	hashesCount := len(hashes) * bloomFilterHashesCount
	a := encoding.GetUint64s(hashesCount)
	a.A = appendHashesHashes(a.A[:0], hashes)
	initBloomFilter(bits, a.A)
	encoding.PutUint64s(a)
}

func initBloomFilter(bits, hashes []uint64) {
	maxBits := uint64(len(bits)) * 64
	bitIndexXor := bloomFilterBitIndexXor
	for _, h := range hashes {
		idx := h % maxBits
		i := idx / 64
		j := idx % 64
		mask := uint64(1) << ((j ^ bitIndexXor) & 63)
		w := bits[i]
		if (w & mask) == 0 {
			bits[i] = w | mask
		}
	}
}

// appendTokensHashes appends hashes for the given tokens to dst and returns the result.
//
// The appended hashes can be then passed to bloomFilter.containsAll().
func appendTokensHashes(dst []uint64, tokens []string) []uint64 {
	dstLen := len(dst)
	hashesCount := len(tokens) * bloomFilterHashesCount

	dst = slicesutil.SetLength(dst, dstLen+hashesCount)
	dst = dst[:dstLen]

	var buf [8]byte
	hp := (*uint64)(unsafe.Pointer(&buf[0]))
	for _, token := range tokens {
		*hp = xxhash.Sum64(bytesutil.ToUnsafeBytes(token))
		for range bloomFilterHashesCount {
			h := xxhash.Sum64(buf[:])
			(*hp)++
			dst = append(dst, h)
		}
	}
	return dst
}

// appendHashesHashes appends hashes for the given hashes to dst and returns the result.
//
// The hashes must be generated from tokens by tokenizeHashes().
// See also appendTokensHashes().
//
// The appended hashes can be then passed to bloomFilter.containsAll().
func appendHashesHashes(dst, hashes []uint64) []uint64 {
	dstLen := len(dst)
	hashesCount := len(hashes) * bloomFilterHashesCount

	dst = slicesutil.SetLength(dst, dstLen+hashesCount)
	dst = dst[:dstLen]

	var buf [8]byte
	hp := (*uint64)(unsafe.Pointer(&buf[0]))
	for _, h := range hashes {
		*hp = h
		for range bloomFilterHashesCount {
			h := xxhash.Sum64(buf[:])
			(*hp)++
			dst = append(dst, h)
		}
	}
	return dst
}

// containsAll returns true if bf contains all the given tokens hashes generated by appendTokensHashes or appendHashesHashes
func (bf *bloomFilter) containsAll(hashes []uint64) bool {
	bits := bf.bits
	if len(bits) == 0 {
		return true
	}
	maxBits := uint64(len(bits)) * 64
	for _, h := range hashes {
		idx := h % maxBits
		i := idx / 64
		j := idx % 64
		mask := bloomFilterBitMask(j)
		w := bits[i]
		if (w & mask) == 0 {
			// The token is missing
			return false
		}
	}
	return true
}

func getBloomFilter() *bloomFilter {
	v := bloomFilterPool.Get()
	if v == nil {
		return &bloomFilter{}
	}
	return v.(*bloomFilter)
}

func putBloomFilter(bf *bloomFilter) {
	bf.reset()
	bloomFilterPool.Put(bf)
}

var bloomFilterPool sync.Pool
