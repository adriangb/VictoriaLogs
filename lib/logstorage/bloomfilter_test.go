package logstorage

import (
	"fmt"
	"testing"
)

func TestBloomFilter(t *testing.T) {
	f := func(tokens []string) {
		t.Helper()
		dataTokens := bloomFilterMarshalTokens(nil, tokens)
		hashes := tokenizeHashes(nil, tokens)
		dataHashes := bloomFilterMarshalHashes(nil, hashes)
		if string(dataTokens) != string(dataHashes) {
			t.Fatalf("unexpected marshaled bloom filters from hashes\ngot\n%X\nwant\n%X", dataHashes, dataTokens)
		}

		bf := getBloomFilter()
		defer putBloomFilter(bf)
		if err := bf.unmarshal(dataTokens); err != nil {
			t.Fatalf("unexpected error when unmarshaling bloom filter: %s", err)
		}
		tokensHashes := appendTokensHashes(nil, tokens)
		if !bf.containsAll(tokensHashes) {
			t.Fatalf("containsAll must return true for the added tokens")
		}
	}
	f(nil)
	f([]string{"foo"})
	f([]string{"foo", "bar", "baz"})

	// 10k tokens
	tokens := make([]string, 10000)
	for i := range tokens {
		tokens[i] = fmt.Sprintf("token_%d", i)
	}
	f(tokens)
}

func TestBloomFilterUnmarshalFailure(t *testing.T) {
	f := func(data []byte) {
		t.Helper()
		bf := getBloomFilter()
		defer putBloomFilter(bf)
		if err := bf.unmarshal(data); err == nil {
			t.Fatalf("expecting non-nil error")
		}
	}
	f([]byte("a"))
	f([]byte("foo"))
}

func TestBloomFilterUnmarshalGarbage(t *testing.T) {
	data := []byte("01234567")
	var bf bloomFilter
	if err := bf.unmarshal(data); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestBloomFilterFalsePositive(t *testing.T) {
	tokens := make([]string, 20000)
	for i := range tokens {
		tokens[i] = fmt.Sprintf("token_%d", i)
	}
	data := bloomFilterMarshalTokens(nil, tokens)
	bf := getBloomFilter()
	defer putBloomFilter(bf)
	if err := bf.unmarshal(data); err != nil {
		t.Fatalf("unexpected error when unmarshaling bloom filter: %s", err)
	}

	// count the number of false positives on 20K non-existing tokens
	falsePositives := 0
	for i := range tokens {
		token := fmt.Sprintf("non-existing-token_%d", i)
		tokensHashes := appendTokensHashes(nil, []string{token})
		if bf.containsAll(tokensHashes) {
			falsePositives++
		}
	}
	p := float64(falsePositives) / float64(len(tokens))
	maxFalsePositive := 0.0011
	if p > maxFalsePositive {
		t.Fatalf("too high false positive rate; got %.4f; want %.4f max", p, maxFalsePositive)
	}
}

func TestBloomFilterMarshal_TokensVSHashes(t *testing.T) {
	tokens := make([]string, 100)
	for i := range tokens {
		tokens[i] = fmt.Sprintf("token_%d", i)
	}

	dataTokens := bloomFilterMarshalTokens(nil, tokens)

	hashes := tokenizeHashes(nil, tokens)
	dataHashes := bloomFilterMarshalHashes(nil, hashes)

	if string(dataTokens) != string(dataHashes) {
		t.Fatalf("unexpected bloom filter obtained from hashes\ngot\n%X\nwant\n%X", dataHashes, dataTokens)
	}
}

func TestBloomFilterMarshalTokens(t *testing.T) {
	f := func(tokens []string, resultExpected string) {
		t.Helper()

		result := bloomFilterMarshalTokens(nil, tokens)
		if string(result) != resultExpected {
			t.Fatalf("unexpected result\ngot\n%X\nwant\n%X", result, resultExpected)
		}
	}

	f([]string{}, "")
	f([]string{"foo"}, "\x00\x00\x00\x82\x40\x18\x00\x04")
	f([]string{"foo", "bar", "baz"}, "\x00\x00\x81\xA3\x48\x5C\x10\x26")
	f([]string{"foo", "bar", "baz", "foo"}, "\x00\x00\x81\xA3\x48\x5C\x10\x26")
}

func TestBloomFilterBitsLayout(t *testing.T) {
	// The bit idx must be stored at the bit idx%64 of the big-endian word idx/64 regardless of the architecture.
	var bf bloomFilter
	bf.bits = make([]uint64, 2)
	initBloomFilter(bf.bits, []uint64{0, 9, 64 + 63})
	data := bf.marshal(nil)
	dataExpected := "\x00\x00\x00\x00\x00\x00\x02\x01\x80\x00\x00\x00\x00\x00\x00\x00"
	if string(data) != dataExpected {
		t.Fatalf("unexpected marshaled bloom filter\ngot\n%X\nwant\n%X", data, dataExpected)
	}

	var bf2 bloomFilter
	if err := bf2.unmarshal([]byte(dataExpected)); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !bf2.containsAll([]uint64{0, 9, 64 + 63}) {
		t.Fatalf("containsAll must return true for the set bits")
	}
	for _, idx := range []uint64{1, 8, 56, 63, 64, 64 + 7, 64 + 56} {
		if bf2.containsAll([]uint64{idx}) {
			t.Fatalf("containsAll must return false for the unset bit %d", idx)
		}
	}
}
