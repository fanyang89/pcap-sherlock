import sqlite3
import unittest
import io
import tempfile
from pathlib import Path
from unittest.mock import patch

from sherlock import FIELDS, initialize, parse_row, report, ingest, write_report


def row(**values):
    fields = dict.fromkeys(FIELDS, "")
    fields.update(
        {
            "frame.number": "1",
            "frame.time_epoch": "120",
            "frame.len": "1500",
            "frame.cap_len": "96",
            "ip.src": "192.0.2.1",
            "ip.dst": "192.0.2.2",
            "tcp.srcport": "1234",
            "tcp.dstport": "80",
            "tcp.stream": "0",
            "tcp.seq_raw": "1000",
            "tcp.ack_raw": "2000",
            "tcp.len": "1446",
            "tcp.flags": "0x0010",
            "tcp.window_size_value": "4096",
        }
    )
    fields.update(values)
    return [fields[k] for k in FIELDS]


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        initialize(self.db)
        self.addCleanup(self.db.close)

    def add(self, source="A", **values):
        packet = parse_row(row(**values), source, source + ".pcap")
        self.db.execute(
            "INSERT INTO packets VALUES (" + ",".join(["?"] * 18) + ")", packet
        )

    def test_truncated_payload_keeps_wire_length(self):
        self.add()
        result = report(self.db, [])["connections"][0]
        self.assertEqual(result["observed_wire_bytes"], 1500)
        self.assertEqual(result["observed_tcp_bytes"], 1446)

    def test_boundary_events_not_dropped(self):
        self.add(**{"tcp.analysis.retransmission": "1"})
        self.add(
            **{"frame.number": "2", "frame.time_epoch": "180", "tcp.flags": "0x0004"}
        )
        bursts = report(self.db, [], threshold=1)["bursts"]
        self.assertEqual({b["start"] for b in bursts}, {120, 180})
        self.assertEqual(sum(b["event_packets"] for b in bursts), 2)

    def test_repeated_headers_are_ambiguous(self):
        self.add()
        self.add("B", **{"frame.time_epoch": "121"})
        self.assertEqual(len(report(self.db, [])["comparison"]["evidence"]), 1)
        self.add(**{"frame.number": "2", "frame.time_epoch": "122"})
        comparison = report(self.db, [])["comparison"]
        self.assertEqual(comparison["evidence"], [])
        self.assertEqual(comparison["counts"][0]["ambiguous_signatures"], 1)

    def test_missing_tcp_header_skipped(self):
        self.assertIsNone(parse_row(row(**{"tcp.seq_raw": ""}), "A", "a.pcap"))

    def test_offset_and_ipv6(self):
        packet = parse_row(
            row(**{"ip.src": "", "ipv6.src": "2001:db8::1"}), "B", "b", -2
        )
        self.assertEqual(packet[3], 118)
        self.assertEqual(packet[6], "2001:db8::1")

    def test_report_escapes_paths(self):
        self.add()
        data = report(self.db, [{"file": "<script>alert(1)</script>"}])
        with tempfile.TemporaryDirectory() as tmp:
            write_report(data, Path(tmp))
            page = (Path(tmp) / "report.html").read_text()
            self.assertNotIn("<script>", page)
            self.assertIn("&lt;script&gt;", page)

    def test_failed_tshark_is_not_success(self):
        with patch("sherlock.subprocess.Popen") as popen:
            process = popen.return_value
            process.stdout = io.StringIO("")
            process.wait.return_value = 2
            process.poll.return_value = 2
            with self.assertRaisesRegex(RuntimeError, "tshark failed"):
                ingest(self.db, "A", "bad.pcap")

    def test_ingestion_counts_truncation(self):
        with patch("sherlock.subprocess.Popen") as popen:
            process = popen.return_value
            process.stdout = io.StringIO("\t".join(row()) + "\n")
            process.wait.return_value = 0
            process.poll.return_value = 0
            quality = ingest(self.db, "A", "a.pcap")
            self.assertEqual(quality["truncated"], 1)
            self.assertEqual(quality["packets"], 1)


if __name__ == "__main__":
    unittest.main()
