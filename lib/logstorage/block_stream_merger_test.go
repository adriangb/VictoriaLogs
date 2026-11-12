package logstorage

import (
	"testing"
)

func TestMergeBlockStreams_LegacyBloomFilters(t *testing.T) {
	f := func(lrs []*LogRows, srcPartFormatVersion uint) {
		t.Helper()

		var lrExpected logRows
		for _, lr := range lrs {
			for j, timestamp := range lr.timestamps {
				lrExpected.mustAddRow(lr.streamIDs[j], timestamp, lr.rows[j])
			}
		}

		var mpsSrc []*inmemoryPart
		var bsrs []*blockStreamReader
		for _, lrOrig := range lrs {
			var lr logRows
			lr.mustAddRows(lrOrig)

			mp := getInmemoryPart()
			mp.mustInitFromRows(&lr)
			// Pretend the part has been written in the given format version.
			// The bloom filters at mp are in the latest format, but the merge must re-create them anyway,
			// since it cannot rely on their contents.
			mp.ph.FormatVersion = srcPartFormatVersion
			mpsSrc = append(mpsSrc, mp)

			bsr := getBlockStreamReader()
			bsr.MustInitFromInmemoryPart(mp)
			bsrs = append(bsrs, bsr)
		}
		defer func() {
			for _, bsr := range bsrs {
				putBlockStreamReader(bsr)
			}
			for _, mp := range mpsSrc {
				putInmemoryPart(mp)
			}
		}()

		mpDst := getInmemoryPart()
		defer putInmemoryPart(mpDst)
		bsw := getBlockStreamWriter()
		bsw.MustInitForInmemoryPart(mpDst)
		mustMergeBlockStreams(&mpDst.ph, nil, bsw, bsrs, nil, nil)
		putBlockStreamWriter(bsw)

		if mpDst.ph.FormatVersion != partFormatLatestVersion {
			t.Fatalf("unexpected part format version; got %d; want %d", mpDst.ph.FormatVersion, partFormatLatestVersion)
		}

		sbu := getStringsBlockUnmarshaler()
		defer putStringsBlockUnmarshaler(sbu)
		vd := getValuesDecoder()
		defer putValuesDecoder(vd)

		lrResult := mpDst.readLogRows(sbu, vd)
		if err := checkEqualRows(lrResult, &lrExpected); err != nil {
			t.Fatalf("unequal log entries: %s", err)
		}

		checkBloomFilters(t, mpDst, sbu, vd)
	}

	for _, srcPartFormatVersion := range []uint{partFormatSBBFVersion - 1, partFormatLatestVersion} {
		// small blocks, which are merged into bigger blocks
		f([]*LogRows{newTestLogRows(10, 20, 0)}, srcPartFormatVersion)
		f([]*LogRows{
			newTestLogRows(10, 20, 0),
			newTestLogRows(20, 10, 1),
			newTestLogRows(30, 5, 2),
		}, srcPartFormatVersion)

		// full blocks, which are written to the output part as is for the latest format version
		f([]*LogRows{newTestLogRows(1, 10000, 0)}, srcPartFormatVersion)
		f([]*LogRows{
			newTestLogRows(1, 10000, 0),
			newTestLogRows(2, 10, 1),
		}, srcPartFormatVersion)
	}
}

// checkBloomFilters verifies that every bloom filter at mp is in the latest format and contains all the tokens for the corresponding column.
func checkBloomFilters(t *testing.T, mp *inmemoryPart, sbu *stringsBlockUnmarshaler, vd *valuesDecoder) {
	t.Helper()

	bsr := getBlockStreamReader()
	defer putBlockStreamReader(bsr)
	bsr.MustInitFromInmemoryPart(mp)

	var b block
	var bf bloomFilter
	bloomFiltersChecked := 0
	for bsr.NextBlock() {
		bd := &bsr.blockData
		if err := b.InitFromBlockData(bd, sbu, vd); err != nil {
			t.Fatalf("cannot init block from block data: %s", err)
		}
		for i := range bd.columnsData {
			cd := &bd.columnsData[i]
			if cd.valueType == valueTypeDict {
				continue
			}
			if err := bf.unmarshal(cd.bloomFilterData, mp.ph.FormatVersion); err != nil {
				t.Fatalf("cannot unmarshal bloom filter for column %q: %s", cd.name, err)
			}
			values := b.columns[i].values
			expected := bloomFilterMarshalHashes(nil, tokenizeHashes(nil, values))
			if string(cd.bloomFilterData) != string(expected) {
				t.Fatalf("unexpected bloom filter for column %q", cd.name)
			}
			for _, v := range values {
				if !bf.containsAll(appendTokensHashes(nil, tokenizeStrings(nil, []string{v}))) {
					t.Fatalf("bloom filter for column %q doesn't contain tokens for %q", cd.name, v)
				}
			}
			bloomFiltersChecked++
		}
		sbu.reset()
		vd.reset()
	}
	if bloomFiltersChecked == 0 {
		t.Fatalf("no bloom filters have been checked")
	}
}
