package logstorage

import (
	"fmt"
	"testing"
)

func benchBloomFilters(filtersCount, tokensPerFilter int) [][]byte {
	a := make([][]byte, filtersCount)
	tokens := make([]string, tokensPerFilter)
	for i := range a {
		for j := range tokens {
			tokens[j] = fmt.Sprintf("tok_%d_%d", i, j)
		}
		a[i] = bloomFilterMarshalTokens(nil, tokens)
	}
	return a
}

func BenchmarkBloomFilterContainsAll(b *testing.B) {
	for _, tc := range []struct{ filters, tokens int }{{64, 1000}, {4096, 1000}, {16384, 100}} {
		filters := benchBloomFilters(tc.filters, tc.tokens)
		for _, qn := range []int{1, 3} {
			var q []string
			for i := 0; i < qn; i++ {
				q = append(q, fmt.Sprintf("missing_%d", i))
			}
			hashes := appendTokensHashes(nil, q)
			b.Run(fmt.Sprintf("filters=%d/tokens=%d/query_tokens=%d", tc.filters, tc.tokens, qn), func(b *testing.B) {
				bf := getBloomFilter()
				defer putBloomFilter(bf)
				n := 0
				for b.Loop() {
					for _, data := range filters {
						if err := bf.unmarshal(data, partFormatLatestVersion); err != nil {
							b.Fatal(err)
						}
						if bf.containsAll(hashes) {
							n++
						}
					}
				}
				b.ReportMetric(float64(n)/float64(b.N*len(filters)), "fp_rate")
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*len(filters)), "ns/filter")
			})
		}
	}
}

func BenchmarkBloomFilterMarshalHashes(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		hashes := make([]uint64, n)
		for i := range hashes {
			hashes[i] = uint64(i)*0x9E3779B97F4A7C15 + 1
		}
		b.Run(fmt.Sprintf("hashes=%d", n), func(b *testing.B) {
			var dst []byte
			for b.Loop() {
				dst = bloomFilterMarshalHashes(dst[:0], hashes)
			}
			b.ReportMetric(float64(len(dst)), "bytes")
		})
	}
}
