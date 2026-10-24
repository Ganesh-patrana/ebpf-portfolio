# Page Cache Telemetry Model

## Objective
To approximate Page Cache Hits and Misses on a modern Linux node (Kernel 6.x) using eBPF.

## Events Observed
Because Linux does not have a single `tracepoint:page_cache_hit`, we must infer hits and misses by attaching `kprobes` to internal memory management functions:
1. `folio_mark_accessed`: Triggers when the kernel accesses a folio (a block of memory) in the page cache. This represents our **Total Cache Accesses**.
2. `filemap_add_folio`: Triggers when the kernel is forced to fetch data from the disk and insert a new folio into the page cache. This represents our **Cache Misses**.

## Calculation Methodology
* **Cache Misses** = Count of `filemap_add_folio`
* **Total Accesses** = Count of `folio_mark_accessed`
* **Cache Hits** = (Total Accesses) - (Cache Misses)
* **Hit Ratio** = (Cache Hits / Total Accesses) * 100

## Kernel-Version Dependencies
This implementation specifically targets Linux 5.16+ by utilizing the `folio` subsystem API. Older kernels using `mark_page_accessed` will fail to attach these probes.

## Limitations and Misleading Cases
1. **Direct I/O (`O_DIRECT`):** Applications like PostgreSQL or Oracle often bypass the kernel page cache entirely to manage memory themselves. These reads will not trigger our probes, resulting in blind spots for certain databases.
2. **Readahead Engine:** Linux tries to guess what files you will read next and pre-loads them (Read-ahead). This triggers `filemap_add_folio` (Misses) in the background, even if the application hasn't explicitly asked for the data yet. This can temporarily skew the hit/miss ratio.
3. **Approximation:** eBPF kprobes on highly volatile memory functions are an approximation, not byte-for-byte accounting. Under extreme memory pressure, some events may be dropped.
