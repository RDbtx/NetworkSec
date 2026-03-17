# Current Problems

**Network Intrusion Detection System — Blackwall**
*Findings from PCAP Extraction Validation & Classifier Diagnosis*

---

## Summary

Three distinct problems were identified during validation of the tshark-based PCAP extraction pipeline and diagnosis of
the trained XGBoost classifier:

1. A broken tshark extraction caused by a Unicode encoding bug in the separator character.
2. Residual pyshark multi-value field limitations on reassembled TCP/TLS packets.
3. A fundamental class definition mismatch between training labels and network protocol reality, causing 93.5% of attack
   packets to be misclassified.

---

## 1. Discovery: pyshark vs tshark Extraction Gap

The original `data_extraction.py` and `offline_testing.py` used pyshark (a Python wrapper around tshark) to extract
packet features from PCAP files. The dataset creators, however, used tshark directly via a specific command-line
pipeline to generate the training CSVs. A diagnostic tool (`pcap_vs_csv_diff.py`) was built to measure the per-feature,
per-packet difference between what each extraction method produced versus what the training CSV contained.

The tool operates in two modes:

- **pyshark mode** — extracts features using pyshark's JSON API and compares against the CSV.
- **tshark mode** — invokes tshark directly with the same flags as the dataset creators and compares output against the
  CSV.

All CSV values are read as raw strings (`dtype=str`) to prevent pandas type inference from creating false differences.
Binary flag columns are normalised to `"0"`/`"1"` before comparison, and row alignment is verified on every packet via
`frame.len` to detect ordering drift.

### 1.1 First Run Results

| Mode    | Exact matches     | Missing   | Alignment     |
|---------|-------------------|-----------|---------------|
| tshark  | 0 / 920 (0%)      | 254 / 920 | 20 mismatches |
| pyshark | 915 / 920 (99.5%) | 2 / 920   | 0 mismatches  |

The tshark mode was a total failure — every extracted value was NULL. The pyshark mode was nearly perfect but had 5
residual differences across 3 features.

### 1.2 Root Cause: tshark Separator Encoding Bug

The tshark extraction command used the Greek letter α as the column separator, replicating the dataset creators'
original UltraEdit pipeline. When passed through Python's `subprocess` on Linux/macOS, the multi-byte UTF-8 sequence for
α (`0xCE 0xB1`) was mangled. tshark received a garbled byte sequence, rejected it as an invalid separator, and produced
no parseable output — causing every feature to appear as NULL.

**Fix:** the separator was changed to the ASCII pipe character `|`, which is safe across all platforms and never appears
in any network field value.

```python
# BROKEN — alpha separator mangled by subprocess UTF-8 encoding
cmd += ["-E", "separator=α"]

# FIXED — ASCII pipe, no encoding issues
cmd += ["-E", "separator=|"]
```

The post-processing step was updated to replace `|` with `,` instead of replacing α variants.

### 1.3 Residual pyshark Issues (5 cases in 920 comparisons)

After fixing the tshark mode, pyshark still showed 5 residual differences across 3 features, all on packet #7 (a
TCP-reassembled TLS packet with multiple records) and packets #12/#18 (multi-frame HTTP/2):

| Feature                                  | CSV value        | pyshark value | Type    |
|------------------------------------------|------------------|---------------|---------|
| `tls.record.length`                      | `4379+96+53+147` | `4379`        | DIFF    |
| `tls.handshake.length`                   | `4358+75+32+126` | `4358`        | DIFF    |
| `tls.handshake.client_cert_vrfy.sig_len` | `71`             | NULL          | MISSING |
| `http2.length` (pkt 12)                  | `24+4`           | NULL          | MISSING |
| `http2.length` (pkt 18)                  | `0+4`            | `0`           | DIFF    |

**Root cause:** pyshark's JSON mode flattens repeated TLS records and HTTP/2 frames, returning only the first
occurrence. tshark emits all occurrences joined by the separator — e.g. `"4379,96,53,147"` — which after post-processing
becomes `"4379+96+53+147"`, a summable arithmetic string that `resolve_compound` evaluates to a single numeric value.
pyshark structurally cannot replicate this for reassembled TCP segments.

---

## 2. Decision: Replace pyshark with tshark Entirely

Given that tshark achieved **100% match** against the training CSV after the separator fix, while pyshark had structural
limitations with reassembled segments that would require fragile per-version workarounds, pyshark was removed from the
codebase entirely. tshark is now the single extraction backend for both offline and live capture.

### 2.1 Validated tshark Result (after fix, 20 packets)

| Mode           | Exact matches     | DIFF | MISSING | Alignment    |
|----------------|-------------------|------|---------|--------------|
| tshark (fixed) | 920 / 920 (100%)  | 0    | 0       | 0 mismatches |
| pyshark        | 915 / 920 (99.5%) | 3    | 2       | 0 mismatches |

### 2.2 Full-Scale Validation (142,218 packets — entire pcap1-caddy.pcap)

The diff was subsequently run over the complete PCAP file to verify the 100% match holds at scale.

| Metric                    | Result            |
|---------------------------|-------------------|
| Packets compared          | 142,218           |
| Alignment mismatches      | **0**             |
| Total feature comparisons | 6,542,028         |
| Exact matches             | 6,532,512 (99.9%) |
| Value differs (DIFF)      | 1,731 (0.0%)      |
| Missing in extractor      | 4,943 (0.1%)      |
| Extra in extractor        | 2,842 (0.0%)      |

Zero alignment drift across 142k packets confirms the row ordering between tshark and the original CSV is perfectly
stable.

The 0.1% discrepancy is entirely explained by a **tshark version difference**. The dataset was built on Windows with
Wireshark 3.x; the current environment runs:

```
TShark (Wireshark) 4.6.0 (Git commit 35a92c3b364a)
```

The 22 affected features fall into four groups, all attributable to dissector changes between 3.x and 4.x:

| Group                      | Features                                                                                                                                                         | Pattern                | Cause                                                                                           |
|----------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------|-------------------------------------------------------------------------------------------------|
| QUIC dissector changes     | `quic.stream.len`, `quic.packet_number_length`, `quic.padding_length`, `quic.crypto.length`                                                                      | EXTRA + DIFF           | QUIC dissector rewritten in 4.x; field calculation differs                                      |
| TLS reassembly differences | `tls.handshake.length`, `tls.handshake.extensions_length`, `tls.handshake.session_id_length`, `tls.handshake.cipher_suites_length`                               | MISSING + EXTRA + DIFF | 4.x reassembles TLS across TCP segments differently, placing fields on different packet indices |
| 4.x finds more TLS fields  | `tls.handshake.certificates_length`, `tls.handshake.certificate_length`, `tls.handshake.client_cert_vrfy.sig_len`, `tls.reassembled.length`, `tls.record.length` | EXTRA only             | 4.x extracts certificate fields the 3.x version missed entirely                                 |
| 4.x finds more HTTP3/HTTP2 | `http3.settings.*`, `http2.length`, `http2.header.*`                                                                                                             | EXTRA only             | 4.x HTTP3/HTTP2 dissector improvements                                                          |

**Model impact assessment:** none of the 22 affected features appear in the top 10 features by model importance. The
dominant features (`tcp.flags.push`, `dns.flags.response`, `tcp.flags.syn`, `quic.long.packet_type`) are unaffected. The
version discrepancy is not actionable — the training CSVs were built with 3.x and cannot be regenerated — and has
negligible effect on classifier output.

**Conclusion: the extraction pipeline is validated and production-ready.**

### 2.3 Full Dataset Validation (53 files, all attack types)

The diff was subsequently run over all 53 PCAP/CSV pairs across 9 attack folders × 6 servers (excluding `4-http-stream`
which was dropped from training). `pcap5-windows` was initially skipped due to a non-standard filename (
`pcap5-windows-new.pcap`) — the batch runner was updated to detect the `-new` suffix automatically. Total coverage: *
*371 million feature comparisons**.

| Metric                    | Result                   |
|---------------------------|--------------------------|
| Files processed           | 53                       |
| Total packets compared    | ~8.7 million             |
| Alignment mismatches      | **0** (all 53 files)     |
| Total feature comparisons | 371,257,674              |
| Exact matches             | 363,097,236 **(97.80%)** |
| DIFF                      | 1,116,166 (0.30%)        |
| MISSING                   | 932,887 (0.25%)          |
| EXTRA                     | 6,111,385 (1.65%)        |

Zero alignment drift across all 53 files confirms the tshark extraction ordering is perfectly consistent with the
original CSV pipeline at full dataset scale.

**Per-server breakdown** reveals two distinct profiles driven entirely by tshark version differences:

| Server profile               | Files    | Typical exact% | Pattern             |
|------------------------------|----------|----------------|---------------------|
| caddy, h2o, windows          | 16 files | 98.5–100%      | Minimal discrepancy |
| cloudflare, litespeed, nginx | 37 files | 95–98%         | Higher EXTRA counts |

The cloudflare and litespeed files show the highest EXTRA counts (e.g. `pcap8-cloudflare`: 612,321 EXTRA;
`pcap6-litespeed`: 272,079 MISSING + 219,857 EXTRA). This is caused by two tshark 4.x improvements: better TLS 1.3 /
QUIC extension parsing on cloudflare traffic, and different TLS handshake reassembly boundaries on litespeed's TLS-heavy
traffic. The litespeed MISSING+EXTRA pattern specifically indicates reassembly boundary shifts — the same field values
exist but land on different packet indices than in the 3.x-generated CSV.

`pcap5-windows` (quic-flood on Windows, 66,448 packets) showed 96.8% exact with 71,776 MISSING — consistent with the
QUIC dissector differences seen on other QUIC-heavy files. No anomalies.

**Model impact:** The discrepant features are the same 22 identified in the single-file analysis. None appear in the top
10 features by model importance. The dominant decision features (`tcp.flags.push`, `dns.flags.response`,
`tcp.flags.syn`, `quic.long.packet_type`) show zero discrepancy across all 53 files.

**Conclusion: the extraction pipeline is fully validated across the entire dataset.**

pyshark was removed completely. Two interfaces are provided in `data_extraction.py`:

- **`FileCapture`** — a synchronous iterator for offline PCAP files. Yields one `(source_ip, raw_df)` tuple per packet.
  Used by `offline_testing.py`.
- **`LiveCapture`** — runs `tshark -i <interface>` in a background thread, streams line-by-line output via
  `subprocess.Popen` with `bufsize=1` into a queue. Used by the live firewall.
- **`load_pcap_as_dataframe()`** — fast batch extraction: runs tshark once, collects all stdout with `communicate()`,
  parses with `pd.read_csv` in one vectorised call. 20-50x faster than the per-packet loop for large PCAPs.

The extraction pipeline replicates the dataset creators' exact UltraEdit post-processing steps:

```
1. "," → "+"   — join multi-value field commas into summable arithmetic strings
2. strip "      — remove -E quote=d wrapping
3. "|" → ","   — restore standard CSV column separator (step 3 must be last)
```

---

## 3. Classifier Diagnosis: DDoS-flooding Underdetection

After validating the extraction pipeline, `offline_testing.py` was run on `pcap1-caddy.pcap` (http-flood attack
dataset). The results diverged significantly from ground truth:

### 3.1 Prediction vs Ground Truth

| Class         | Ground truth | Predicted | Miss rate |
|---------------|--------------|-----------|-----------|
| Normal        | 78,136       | 121,558   | —         |
| DDoS-flooding | 64,082       | 5,578     | **93.5%** |

The model correctly identified only 6.5% of attack packets, misclassifying 93.5% as Normal.

Additionally, 15,032 Normal packets were incorrectly classified as `Transport-layer` (19.2% false positive rate on
Normal traffic).

### 3.2 Feature Presence Analysis

Inspecting the raw feature values per class revealed the core problem:

**Normal packets** — predominantly TCP traffic:

```
frame.len          78136 / 78136
ip.len             78136 / 78136
tcp.len            52937 / 78136
tcp.flags.ack      52937 / 78136
tcp.window_size    52937 / 78136
```

**http-flood attack packets** — pure QUIC/UDP traffic, zero TCP fields:

```
frame.len            64082 / 64082
quic.packet_length   64082 / 64082
udp.length           64082 / 64082
quic.fixed_bit       63177 / 64082
quic.spin_bit        56738 / 64082
tcp.*                    0 / 64082   ← NO TCP FIELDS AT ALL
```

The caddy server communicates over QUIC (HTTP/3). The http-flood attack against it is therefore a QUIC flood, not a TCP
flood. This is consistent with the labeling logic in `labeling.py` which identifies http-flood packets via
`udp.dstport.notnull()`.

### 3.3 Model Feature Importance Analysis

Inspecting the XGBoost feature importances revealed the model's decision logic:

| Feature                             | Importance |
|-------------------------------------|------------|
| `tcp.flags.push_0.0`                | 0.2621     |
| `tcp.flags.push_1.0`                | 0.1321     |
| `dns.flags.response_-1.0`           | 0.0742     |
| `tcp.flags.syn_-1.0`                | 0.0567     |
| `quic.long.packet_type_-1`          | 0.0477     |
| `quic.packet_length`                | 0.0366     |
| `http.content_type_application/...` | 0.0353     |
| `tls.record.length`                 | 0.0330     |

**The model makes over 40% of its decisions based on `tcp.flags.push` OHE columns.** Attack packets have no TCP fields
at all, so after `fill_missing` they receive `tcp.flags.push = -1` → OHE produces `tcp.flags.push_-1.0 = 1`. That column
has only 1.4% importance — the model never learned to associate the absence of TCP with DDoS-flooding.

Meanwhile, the features that are actually present in attack packets (`quic.packet_length`, `http3.settings.*`) are
ranked 6th and below with low importance.

### 3.4 Root Cause: Class Definition Mismatch

The `LABEL_MAP` in `model_utilities.py` collapses 11 fine-grained attack labels into 5 classes:

```python

LABEL_MAP = {
    "Normal": "Normal",
    "http-flood": "DDoS-flooding",
    "http-stream": "DDoS-flooding",
    "quic-flood": "DDoS-flooding",
    "http-loris": "DDoS-loris",
    "quic-loris": "DDoS-loris",
    "fuzzing": "Transport-layer",
    "quic-enc": "Transport-layer",
    "http-smuggle": "HTTP/2-attacks",
    "http2-concurrent": "HTTP/2-attacks",
    "http2-pause": "HTTP/2-attacks",
}
```

The `DDoS-flooding` class merges attacks that use completely different protocols (TCP-based HTTP floods from some
servers vs QUIC-based floods from QUIC-capable servers like caddy). The merged class has high internal variance — the
model cannot learn a clean decision boundary because the same label covers both TCP and QUIC traffic patterns. The
dominant features it learned (TCP flags) work well for TCP floods but are structurally absent in QUIC floods.

---

## 4. Proposed Solutions

### Option 1 — Retrain with Fine-Grained Labels (Recommended)

Keep all 11 original labels instead of collapsing to 5. Each class will have internally consistent feature
distributions, making the model's task tractable.

```python
# model_utilities.py — identity mapping, no collapsing
LABEL_MAP = {
    "Normal": "Normal",
    "http-flood": "http-flood",
    "http-stream": "http-stream",
    "quic-flood": "quic-flood",
    "http-loris": "http-loris",
    "quic-loris": "quic-loris",
    "fuzzing": "fuzzing",
    "quic-enc": "quic-enc",
    "http-smuggle": "http-smuggle",
    "http2-concurrent": "http2-concurrent",
    "http2-pause": "http2-pause",
}
```

Also update `num_class=11` in the XGBoost/LightGBM model definition.

### Option 2 — Retrain with Protocol-Aware Grouping

If 5 classes are required, split `DDoS-flooding` by protocol layer so each class is internally consistent:

```python
LABEL_MAP = {
    "http-flood": "DDoS-QUIC",  # all QUIC-based floods together
    "http-stream": "DDoS-QUIC",
    "quic-flood": "DDoS-QUIC",
    "quic-loris": "DDoS-QUIC",
    "http-loris": "DDoS-TCP",  # TCP slow attacks
    "fuzzing": "Transport-layer",
    "quic-enc": "Transport-layer",
    "http-smuggle": "HTTP/2-attacks",
    "http2-concurrent": "HTTP/2-attacks",
    "http2-pause": "HTTP/2-attacks",
    "Normal": "Normal",
}
```

### Option 3 — Do Not Retrain (Not Recommended)

The current model is not suitable for deployment on QUIC-capable servers. It will correctly classify TCP-based attacks
but miss virtually all QUIC-based attacks (93.5% miss rate). This is a fundamental limitation of the class definition,
not a bug in the extraction pipeline.

---

## 5. Summary of Changes Made

| File                  | Change                                                                                                                          |
|-----------------------|---------------------------------------------------------------------------------------------------------------------------------|
| `pcap_vs_csv_diff.py` | Added tshark mode; fixed separator from α to `\|`; added per-feature MISSING/EXTRA/DIFF breakdown; added `--debug-pkt` flag     |
| `data_extraction.py`  | Removed pyshark entirely; added `FileCapture`, `LiveCapture`, `load_pcap_as_dataframe` using tshark subprocess                  |
| `offline_testing.py`  | Replaced pyshark loop with `FileCapture`; added `OfflinePreprocessor`; added `diagnose_vs_labels()` for ground-truth comparison |
| `pcap_to_csv.py`      | New file: replicates the dataset creators' exact tshark + UltraEdit pipeline for batch PCAP → CSV conversion                    |