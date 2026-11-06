#!/usr/bin/env python3
"""Offline TCP evidence analysis backed by a disk-based SQLite index."""

import argparse
import csv
import html
import json
import math
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile


FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "ip.src",
    "ipv6.src",
    "tcp.srcport",
    "ip.dst",
    "ipv6.dst",
    "tcp.dstport",
    "tcp.stream",
    "tcp.seq_raw",
    "tcp.ack_raw",
    "tcp.len",
    "tcp.flags",
    "tcp.window_size_value",
    "tcp.analysis.ack_rtt",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.out_of_order",
    "tcp.analysis.zero_window",
    "tcp.hdr_len",
    "tcp.checksum",
    "tcp.urgent_pointer",
    "tcp.options",
]


def initialize(db):
    db.execute("PRAGMA temp_store = FILE")
    db.execute("""CREATE TABLE packets (
        source TEXT, file TEXT, frame INTEGER, ts REAL, wire INTEGER,
        captured INTEGER, src TEXT, sport INTEGER, dst TEXT, dport INTEGER,
        stream INTEGER, seq INTEGER, ack INTEGER, length INTEGER,
        flags INTEGER, window INTEGER, rtt REAL, events TEXT)""")


def parse_row(row, source, filename, offset=0):
    if len(row) != len(FIELDS):
        raise ValueError("Unexpected tshark field count")
    f = dict(zip(FIELDS, row))
    required = [
        "tcp.srcport",
        "tcp.dstport",
        "tcp.seq_raw",
        "tcp.ack_raw",
        "tcp.len",
        "tcp.flags",
        "tcp.window_size_value",
        "tcp.stream",
        "tcp.hdr_len",
        "tcp.checksum",
        "tcp.urgent_pointer",
    ]
    if not all(f[k] for k in required):
        return None
    header_length = int(f["tcp.hdr_len"])
    options_length = len(bytes.fromhex(f["tcp.options"].replace(":", "")))
    if not 20 <= header_length <= 60 or options_length < header_length - 20:
        return None
    src, dst = f["ip.src"] or f["ipv6.src"], f["ip.dst"] or f["ipv6.dst"]
    if not src or not dst:
        return None
    flags = int(f["tcp.flags"], 16)
    events = []
    for name, keys in [
        ("retransmission", FIELDS[17:20]),
        ("duplicate_ack", [FIELDS[20]]),
        ("out_of_order", [FIELDS[21]]),
        ("zero_window", [FIELDS[22]]),
    ]:
        if any(f[k] for k in keys):
            events.append(name)
    if flags & 4:
        events.append("reset")
    ts = float(f["frame.time_epoch"]) + offset
    rtt = float(f["tcp.analysis.ack_rtt"]) if f["tcp.analysis.ack_rtt"] else None
    if not math.isfinite(ts) or (rtt is not None and not math.isfinite(rtt)):
        raise ValueError("Non-finite timestamp")
    return (
        source,
        filename,
        int(f["frame.number"]),
        ts,
        int(f["frame.len"]),
        int(f["frame.cap_len"]),
        src,
        int(f["tcp.srcport"]),
        dst,
        int(f["tcp.dstport"]),
        int(f["tcp.stream"]),
        int(f["tcp.seq_raw"]),
        int(f["tcp.ack_raw"]),
        int(f["tcp.len"]),
        flags,
        int(f["tcp.window_size_value"]),
        rtt,
        ",".join(events),
    )


def ingest(db, source, filename, offset=0):
    cmd = [
        "tshark",
        "-n",
        "-r",
        str(filename),
        "-Y",
        "tcp",
        "-T",
        "fields",
        "-E",
        "occurrence=f",
    ]
    for field in FIELDS:
        cmd.extend(["-e", field])
    quality = {
        "source": source,
        "file": str(filename),
        "offset_seconds": offset,
        "packets": 0,
        "decoded_tcp_packets": 0,
        "incomplete_headers": 0,
        "truncated": 0,
        "timestamp_regressions": 0,
        "raw_start": None,
        "raw_end": None,
        "min_captured_length": None,
        "max_captured_length": None,
    }
    previous_timestamp = None
    with tempfile.TemporaryFile(mode="w+t") as errors:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=errors, text=True
        )
        try:
            for row in csv.reader(
                process.stdout, delimiter="\t", quoting=csv.QUOTE_NONE
            ):
                if len(row) != len(FIELDS):
                    raise ValueError("Unexpected tshark field count")
                timestamp = float(row[1])
                if not math.isfinite(timestamp):
                    raise ValueError("Non-finite timestamp")
                captured = int(row[3])
                quality["decoded_tcp_packets"] += 1
                quality["truncated"] += captured < int(row[2])
                if previous_timestamp is not None and timestamp < previous_timestamp:
                    quality["timestamp_regressions"] += 1
                previous_timestamp = timestamp
                for key, value, aggregate in [
                    ("raw_start", timestamp, min),
                    ("raw_end", timestamp, max),
                    ("min_captured_length", captured, min),
                    ("max_captured_length", captured, max),
                ]:
                    quality[key] = (
                        value
                        if quality[key] is None
                        else aggregate(quality[key], value)
                    )
                packet = parse_row(row, source, str(filename), offset)
                if packet is None:
                    quality["incomplete_headers"] += 1
                    continue
                db.execute(
                    "INSERT INTO packets VALUES (" + ",".join(["?"] * 18) + ")", packet
                )
                quality["packets"] += 1
                if quality["packets"] % 10000 == 0:
                    db.commit()
                    print(
                        f"{source}: {quality['packets']} TCP packets", file=sys.stderr
                    )
            code = process.wait()
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.kill()
                process.wait()
        errors.seek(0)
        quality["diagnostics"] = errors.read(16384)
    if code:
        raise RuntimeError(
            f"tshark failed for {filename} ({code}): {quality['diagnostics']}"
        )
    db.commit()
    return quality


def records(db, sql, args=()):
    cursor = db.execute(sql, args)
    keys = [column[0] for column in cursor.description]
    return [dict(zip(keys, row)) for row in cursor]


def report(db, quality, window=60, threshold=10):
    connections = records(
        db,
        """SELECT source, file, stream, src, sport, dst, dport,
        count(*) packets, sum(wire) observed_wire_bytes,
        sum(length) observed_tcp_bytes, min(ts) start, max(ts) end,
        avg(rtt) mean_ack_rtt, max(rtt) max_ack_rtt,
        sum(events != '') event_packets,
        sum(instr(events, 'retransmission') > 0) retransmissions,
        sum(instr(events, 'duplicate_ack') > 0) duplicate_acks,
        sum(instr(events, 'out_of_order') > 0) out_of_order,
        sum(instr(events, 'zero_window') > 0) zero_windows,
        sum(instr(events, 'reset') > 0) resets
        FROM packets GROUP BY source, file, stream, src, sport, dst, dport
        ORDER BY event_packets DESC""",
    )
    for connection in connections:
        connection["wireshark_filter"] = f"tcp.stream == {connection['stream']}"
        connection["event_ratio"] = connection["event_packets"] / connection["packets"]
    bursts = records(
        db,
        """SELECT source, file, stream,
        CAST(ts / ? AS INTEGER) * ? start, count(*) event_packets,
        min(frame) first_frame, max(frame) last_frame
        FROM packets WHERE events != ''
        GROUP BY source, file, stream, CAST(ts / ? AS INTEGER)
        HAVING count(*) >= ? ORDER BY event_packets DESC, start, source, file, stream LIMIT 500""",
        (window, window, window, threshold),
    )
    for burst in bursts:
        burst["end"] = burst["start"] + window
        burst["wireshark_filter"] = (
            f"tcp.stream == {burst['stream']} && frame.number >= {burst['first_frame']} "
            f"&& frame.number <= {burst['last_frame']}"
        )
    timeline = records(
        db,
        """SELECT source, CAST(ts / 60 AS INTEGER) * 60 minute,
        count(*) packets, sum(wire) observed_wire_bytes, sum(events != '') event_packets
        FROM packets GROUP BY source, CAST(ts / 60 AS INTEGER) ORDER BY minute""",
    )
    return {
        "schema_version": 2,
        "inputs": quality,
        "connections": connections,
        "bursts": bursts,
        "timeline": timeline,
        "comparison": compare(db),
        "exports": [],
        "limitations": [
            "TCP analysis flags are observations, not proof of network failure.",
            "Wire and TCP byte counts include retransmissions and offload artifacts.",
            "Only decoded TCP packets are indexed; incomplete headers are skipped.",
            "Streams are local to each input file; rotated-file sessions are not merged.",
            "Comparison uses exact headers, not payload or sequence-range reconstruction; "
            "TSO/GRO, NAT, repeated headers and tuple reuse can prevent or confuse matches.",
            "Timestamp differences include clock error and are not one-way latency.",
            "Burst windows are fixed, epoch-aligned; only the top 500 are reported.",
        ],
    }


def compare(db):
    sources = [
        row[0]
        for row in db.execute("SELECT DISTINCT source FROM packets ORDER BY source")
    ]
    if len(sources) != 2:
        return {"status": "requires_two_nonempty_sources"}
    # Rebuild per report so callers may append observations between reports.
    db.execute("DROP TABLE IF EXISTS temp.signatures")
    db.execute("""CREATE TEMP TABLE signatures AS
        SELECT source, src, sport, dst, dport, seq, ack, length, flags, window,
        count(*) observations, min(ts) ts, min(frame) frame, min(file) file
        FROM packets GROUP BY source, src, sport, dst, dport, seq, ack, length, flags, window""")
    keys = ["src", "sport", "dst", "dport", "seq", "ack", "length", "flags", "window"]
    db.execute(
        "CREATE INDEX temp.signature_lookup ON signatures ("
        + ",".join(keys + ["source"])
        + ")"
    )
    condition = " AND ".join(f"a.{key} = b.{key}" for key in keys)
    matches = records(
        db,
        f"""SELECT a.file file_a, a.frame frame_a,
        b.file file_b, b.frame frame_b, a.src, a.dst, a.seq, a.length,
        b.ts - a.ts timestamp_difference_seconds
        FROM signatures a JOIN signatures b ON {condition}
        WHERE a.source = ? AND b.source = ?
        AND a.observations = 1 AND b.observations = 1
        ORDER BY a.ts LIMIT 1000""",
        sources,
    )
    counts = records(
        db,
        f"""SELECT a.source,
        sum(b.source IS NULL) signatures_not_observed_at_peer,
        sum(b.source IS NOT NULL AND (a.observations > 1 OR b.observations > 1)) ambiguous_signatures,
        sum(CASE WHEN a.observations = 1 AND b.observations = 1 THEN 1 ELSE 0 END) unique_exact_matches
        FROM signatures a LEFT JOIN signatures b ON {condition} AND a.source != b.source
        GROUP BY a.source""",
    )
    return {
        "status": "exact_header_candidates",
        "sources": sources,
        "counts": counts,
        "evidence_sample_limit": 1000,
        "evidence": matches,
    }


def export_bursts(data, directory, limit, context):
    """Export local-stream context, keeping original timestamps and truncation."""
    if not 0 <= limit <= 500 or not math.isfinite(context) or context < 0:
        raise ValueError(
            "export limit must be 0..500 and context finite and nonnegative"
        )
    if not limit or not data["bursts"]:
        return []
    destination = directory / "evidence"
    destination.mkdir(exist_ok=False)
    inputs = {(item["source"], item["file"]): item for item in data["inputs"]}
    exports = []
    for number, burst in enumerate(data["bursts"][:limit], 1):
        offset = inputs[burst["source"], burst["file"]]["offset_seconds"]
        start, end = burst["start"] - offset - context, burst["end"] - offset + context
        expression = (
            f"tcp.stream == {burst['stream']} && "
            f"frame.time_epoch >= {start:.9f} && frame.time_epoch < {end:.9f}"
        )
        name = f"burst-{number:03d}-{burst['source']}.pcapng"
        entry = {
            "source": burst["source"],
            "original_file": burst["file"],
            "original_stream": burst["stream"],
            "first_event_frame": burst["first_frame"],
            "last_event_frame": burst["last_frame"],
            "raw_start": start,
            "raw_end": end,
            "context_seconds": context,
            "wireshark_filter": expression,
        }
        # Publish only completed exports. Each export rereads its original file.
        try:
            with tempfile.TemporaryDirectory(
                prefix=".export-", dir=destination
            ) as temporary:
                output = Path(temporary) / name
                with tempfile.TemporaryFile(mode="w+t") as errors:
                    result = subprocess.run(
                        [
                            "tshark",
                            "-n",
                            "-r",
                            burst["file"],
                            "-Y",
                            expression,
                            "-F",
                            "pcapng",
                            "-w",
                            str(output),
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=errors,
                        text=True,
                    )
                    errors.seek(0)
                    entry["diagnostics"] = errors.read(16384)
                if result.returncode:
                    raise RuntimeError(f"tshark export failed ({result.returncode})")
                if not output.is_file() or not output.stat().st_size:
                    raise RuntimeError("tshark produced no capture file")
                output.rename(destination / name)
            entry.update(status="ok", path=f"evidence/{name}")
        except (OSError, RuntimeError) as error:
            entry.update(status="failed", error=str(error))
        exports.append(entry)
    return exports


def write_report(data, directory):
    (directory / "report.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    sections = []
    if data.get("exports"):
        links = []
        for entry in data["exports"]:
            if entry["status"] == "ok":
                path = html.escape(entry["path"], quote=True)
                links.append(f'<li><a href="{path}">{path}</a></li>')
            else:
                links.append(
                    "<li>Export failed: " + html.escape(entry["error"]) + "</li>"
                )
        sections.append(
            "<h2>Evidence captures</h2><p>Original timestamps and truncation retained; "
            "frame numbers and stream IDs are reassigned in exported files. "
            "Filters below refer to original inputs.</p><ul>" + "".join(links) + "</ul>"
        )
    for key in ["inputs", "connections", "bursts", "timeline"]:
        rows = data[key]
        headers = list(rows[0]) if rows else []
        table = (
            "<tr>" + "".join(f"<th>{html.escape(k)}</th>" for k in headers) + "</tr>"
        )
        for row in rows:
            table += (
                "<tr>"
                + "".join(
                    f"<td>{html.escape(str(row.get(k, '')))}</td>" for k in headers
                )
                + "</tr>"
            )
        sections.append(
            f"<details open><summary>{key} ({len(rows)})</summary><div><table>{table}</table></div></details>"
        )
    sections.append(
        "<h2>Two-point evidence</h2><pre>"
        + html.escape(json.dumps(data["comparison"], indent=2))
        + "</pre>"
    )
    sections.append(
        "<h2>Limitations</h2><ul>"
        + "".join("<li>" + html.escape(x) + "</li>" for x in data["limitations"])
        + "</ul>"
    )
    page = """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
        <title>TCP Sherlock</title><style>body{font:14px system-ui;margin:2rem}table{border-collapse:collapse}
        th,td{padding:.5rem;border:1px solid #ccc;text-align:left}div,pre{overflow:auto}
        details{margin:1rem 0}summary{font-weight:bold;cursor:pointer}</style><h1>TCP Sherlock</h1>"""
    (directory / "report.html").write_text(
        page + "".join(sections) + "</html>", encoding="utf-8"
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--a", type=Path, nargs="+", required=True, help="Capture files at point A"
    )
    parser.add_argument(
        "--b", type=Path, nargs="+", default=[], help="Capture files at point B"
    )
    parser.add_argument(
        "--offset-b", type=float, default=0, help="Seconds added to B timestamps"
    )
    parser.add_argument(
        "--window", type=int, default=60, help="Fixed anomaly window in seconds"
    )
    parser.add_argument(
        "--threshold", type=int, default=10, help="Minimum event packets per window"
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="New output directory"
    )
    parser.add_argument(
        "--export-bursts",
        type=int,
        default=0,
        help="Export the top N anomaly windows (0..500; default: disabled)",
    )
    parser.add_argument(
        "--context",
        type=float,
        default=5,
        help="Seconds of same-stream context on each side of exported windows",
    )
    args = parser.parse_args(argv)
    if args.window <= 0 or args.threshold <= 0 or not math.isfinite(args.offset_b):
        parser.error("window and threshold must be positive; offset must be finite")
    if (
        not 0 <= args.export_bursts <= 500
        or not math.isfinite(args.context)
        or args.context < 0
    ):
        parser.error(
            "export-bursts must be 0..500; context must be finite and nonnegative"
        )
    if not shutil.which("tshark"):
        parser.error("tshark is required; install it before running analysis")
    files = args.a + args.b
    if any(not p.is_file() for p in files):
        parser.error("all input paths must be files")
    if len({p.resolve() for p in files}) != len(files):
        parser.error("duplicate input files are not allowed")
    try:
        args.output.mkdir(parents=True, exist_ok=False)
        with sqlite3.connect(args.output / "index.sqlite") as db:
            initialize(db)
            quality = []
            for source, paths, offset in [
                ("A", args.a, 0),
                ("B", args.b, args.offset_b),
            ]:
                for path in paths:
                    quality.append(ingest(db, source, path.resolve(), offset))
            data = report(db, quality, args.window, args.threshold)
            data["exports"] = export_bursts(
                data, args.output, args.export_bursts, args.context
            )
            write_report(data, args.output)
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
        print(f"Analysis failed: {error}", file=sys.stderr)
        return 1
    print(args.output / "report.html")
    if any(entry["status"] == "failed" for entry in data["exports"]):
        print(
            "Some evidence exports failed; see report.json for details", file=sys.stderr
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
