# PCAP Sherlock

Offline TCP troubleshooting from captures collected at one or both ends of a connection. Find anomaly windows, compare packet observations, and export evidence for inspection in Wireshark.

The main entry point, `sherlock.py`, streams tshark output into a disk-backed SQLite index and generates self-contained HTML and JSON reports. It supports captures with truncated payloads when the TCP header and its declared options are complete.

## Requirements

- Python 3.10 or newer.
- tshark available on `PATH`.

The main TCP analyzer uses only the Python standard library. No Python package installation or `uv sync` is required.

Install tshark using your system package manager, for example:

```bash
# Debian / Ubuntu
sudo apt-get install tshark

# macOS
brew install wireshark

# Check availability
tshark --version
```

## Quick start

Run from the repository directory with your own capture files:

```bash
# Analyze captures from both ends
python3 sherlock.py --a client.pcap --b server.pcap --output analysis

# Analyze a single capture point
python3 sherlock.py --a client.pcap --output single-point

# Export the top five anomaly windows with five seconds of context on each side
python3 sherlock.py --a client.pcap --b server.pcap \
  --export-bursts 5 --context 5 --output evidence-analysis
```

Open `analysis/report.html` in a browser. The report works offline and includes per-direction connection statistics, anomaly windows, minute-level summaries, and two-point evidence candidates.

**The output directory must not already exist.** Use a new directory for each run.

### Multiple files and clock offsets

```bash
python3 sherlock.py \
  --a client-1.pcap client-2.pcap \
  --b server-1.pcap server-2.pcap \
  --offset-b -0.25 \
  --window 60 --threshold 10 \
  --output aligned-analysis
```

`--offset-b` adds seconds to B's timestamps during analysis. For example, use `-0.25` when B's clock is 250 ms ahead of A's. Exported captures retain their original timestamps.

Each input file has its own TCP stream IDs. Sessions spanning rotated files are not merged.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `--a FILE [FILE ...]` | Required | Capture files from point A. |
| `--b FILE [FILE ...]` | None | Capture files from point B. |
| `--output DIR` | Required | New directory for reports, the index, and optional evidence. |
| `--offset-b SECONDS` | `0` | Seconds added to B's timestamps. |
| `--window SECONDS` | `60` | Positive integer duration of fixed, epoch-aligned anomaly windows. |
| `--threshold COUNT` | `10` | Minimum number of event packets per stream and window. |
| `--export-bursts N` | `0` | Export the top N anomaly windows, from `0` to `500`; `0` disables export. |
| `--context SECONDS` | `5` | Nonnegative duration of same-stream context before and after each exported window. |

Run `python3 sherlock.py --help` for command-line help.

## Analysis and output

### TCP observations

- Per-direction packet counts, observed wire and TCP bytes, and available ACK RTT statistics.
- Retransmissions, duplicate ACKs, out-of-order packets, zero-window indications, and resets.
- Fixed-window event counts, ranked by event-packet count, with up to 500 anomaly windows.
- Minute-level traffic and event summaries.
- Original file names, frame numbers, and Wireshark stream filters for evidence review.

An event packet is counted once in the window total even if it has multiple event types. Anomaly windows are fixed buckets, not sliding windows.

### Two-point comparison

Packet signatures use addresses, ports, raw sequence and acknowledgment numbers, TCP payload length, flags, and the advertised window. Signatures observed exactly once at each point become candidate matches; repeated signatures are treated as ambiguous.

The report includes aggregate signature counts and up to 1,000 candidate packet pairs. Signature aggregation and lookup use an indexed temporary SQLite table.

### Capture quality

Input summaries include:

- Decoded TCP packets, indexed packets, and records skipped because required headers are incomplete.
- Truncated packets, including skipped incomplete-header records.
- Original timestamp ranges and captured-length ranges.
- Timestamp regressions observed in file order.

Only packets decoded as TCP by tshark are included. The maximum observed captured length does not establish the configured snaplen. A timestamp regression alone does not prove a clock adjustment or network reordering.

### Files

| File | Contents |
| --- | --- |
| `report.html` | Offline report with collapsible tables and evidence download links. |
| `report.json` | Structured results, input metadata, limitations, and export status; current `schema_version` is `2`. |
| `index.sqlite` | Indexed packet observations with source files, frame numbers, TCP fields, and events. |
| `evidence/*.pcapng` | Optional captures containing selected anomaly windows and context. |

Analysis timestamps include the configured offset. Fields named `raw_start` and `raw_end` refer to original capture time. Report filters refer to the corresponding **original input file**.

## Evidence exports

Each export contains both directions of the selected TCP stream from the anomaly's original file, within the window plus the requested context. It does not automatically include the peer capture or adjacent rotated files.

- Original timestamps and payload truncation are preserved.
- Exported frame numbers and TCP stream IDs are reassigned. Original-file filters must not be reused blindly against an export.
- The JSON `exports` entries record source files, original stream IDs, event-frame ranges, original-time selection ranges, filters, and export status.
- tshark may also write fragments on which matching packets depend. Context does not guarantee a complete handshake or session.
- Each export rereads its source file. Start with a small number of high-priority windows.

Failed exports are recorded, and their temporary capture files are removed. Successful exports and the analysis report are retained, but the command exits nonzero if any export fails.

## Limitations

- TCP analysis flags are observations, not proof of a network fault. A signature missing at the peer does not establish packet loss between capture points.
- Exact-header matching does not reconstruct sequence ranges. TSO/GRO segmentation differences, NAT, tuple reuse, and repeated headers can prevent or confuse matches.
- Timestamp differences include clock error and are not one-way latency. Automatic clock-offset or drift calibration is not implemented.
- Byte counts include retransmissions and offload artifacts; they are not application goodput.
- Cross-file session merging, handshake-duration analysis, no-progress detection, and graphical drill-down are not implemented.
- Processing time, peak memory, and report size for real day-long captures have not yet been benchmarked.

## Troubleshooting

- **tshark not found:** install it and confirm that `tshark --version` works in the same shell.
- **Output directory already exists:** choose a new output directory.
- **No anomaly windows:** inspect the connection and input summaries first. A window requires at least `--threshold` event packets; absence of a burst is not a clean bill of health.
- **No two-point comparison:** both capture points need at least one indexable TCP packet.
- **Capture decoding fails:** the command exits nonzero and does not generate a success report. A partial SQLite index may remain for inspection.
- **Evidence export fails:** inspect the corresponding `exports` entry and diagnostics in `report.json`.

## Development and validation

```bash
python3 -m unittest discover -s tests -v
```

Tests cover window boundaries, truncated headers, timestamp offsets, ambiguous and missing matches, report escaping, failure handling, and evidence export. Integration tests generate small truncated TCP captures, run tshark, and read exported captures back to verify packet counts, timestamps, and captured lengths.

All 16 tests have passed locally with tshark 4.6.8, including both integration tests. Without tshark, those two tests are explicitly skipped. GitHub Actions is configured to install tshark and run the full suite.

## Legacy plotting scripts

The original scripts remain available for basic event-count plots:

- `pcap_anomaly_detector.py`: filtered event counting, console statistics, and PNG plots.
- `main.py`: the original prototype.
- `example_usage.py`: legacy examples expecting a local `tcpdump-trace-250728-193554.pcap`, which is not included in the repository.

These scripts require the pandas, NumPy, and Matplotlib dependencies declared in `pyproject.toml`:

```bash
uv sync
uv run python pcap_anomaly_detector.py capture.pcap --window 5 --threshold 10 --stats
uv run python pcap_anomaly_detector.py capture.pcap --filter "tcp.analysis.retransmission"
```

Use `sherlock.py` for two-point analysis, capture-quality checks, structured reports, and evidence export.

## License

MIT.
