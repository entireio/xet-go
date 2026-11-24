package xethash

import (
	"runtime"
	"sync"

	"lukechampine.com/blake3"
)

// lukechampine.com/blake3 selects its SIMD backend internally. It hashes a
// 64 KiB chunk on the calling goroutine, so this caller-level batch is the
// only parallelism for a batch of chunks. It stays ARM64-only, as before.
const chunkBatchEnabled = runtime.GOARCH == "arm64"

var dataHashers = sync.Pool{
	New: func() any { return blake3.New(Size, dataKey[:]) },
}

func pooledDataHash(data []byte) Hash { return pooledHash(&dataHashers, data) }
