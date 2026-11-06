import sqlite3
import subprocess
import unittest
import io
import tempfile
from pathlib import Path
from unittest.mock import patch

from sherlock import (
    FIELDS,
    initialize,
    parse_row,
    report,
    ingest,
    write_report,
    export_bursts,
)


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
            "tcp.hdr_len": "20",
            "tcp.checksum": "0x0000",
            "tcp.urgent_pointer": "0",
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

    def test_partial_tcp_options_skipped(self):
        self.assertIsNone(
            parse_row(row(**{"tcp.hdr_len": "32", "tcp.options": "0101"}), "A", "a")
        )
        self.assertIsNotNone(
            parse_row(
                row(**{"tcp.hdr_len": "24", "tcp.options": "02:04:05:b4"}), "A", "a"
            )
        )

    def test_unmatched_signatures_have_zero_matches(self):
        self.add()
        self.add("B", **{"tcp.seq_raw": "8000"})
        for item in report(self.db, [])["comparison"]["counts"]:
            self.assertEqual(item["unique_exact_matches"], 0)
            self.assertEqual(item["signatures_not_observed_at_peer"], 1)

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

    def test_quality_includes_skipped_headers_and_clock_regressions(self):
        rows = [
            row(),
            row(
                **{
                    "frame.number": "2",
                    "frame.time_epoch": "110",
                    "tcp.urgent_pointer": "",
                }
            ),
        ]
        with patch("sherlock.subprocess.Popen") as popen:
            process = popen.return_value
            process.stdout = io.StringIO("\n".join("\t".join(r) for r in rows) + "\n")
            process.wait.return_value = 0
            process.poll.return_value = 0
            quality = ingest(self.db, "A", "a.pcap", 10)
        self.assertEqual(quality["decoded_tcp_packets"], 2)
        self.assertEqual(quality["packets"], 1)
        self.assertEqual(quality["truncated"], 2)
        self.assertEqual(quality["incomplete_headers"], 1)
        self.assertEqual(quality["timestamp_regressions"], 1)
        self.assertEqual((quality["raw_start"], quality["raw_end"]), (110, 120))

    def export_data(self):
        self.add("B", **{"tcp.flags": "0x0004"})
        return report(
            self.db,
            [{"source": "B", "file": "B.pcap", "offset_seconds": 0.25}],
            threshold=1,
        )

    def test_export_uses_raw_time_and_context(self):
        data = self.export_data()

        def fake_export(command, **kwargs):
            self.assertIn(
                "tcp.stream == 0 && frame.time_epoch >= 114.750000000 && frame.time_epoch < 184.750000000",
                command,
            )
            Path(command[command.index("-w") + 1]).write_bytes(b"pcapng")
            return subprocess.CompletedProcess(command, 0)

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("sherlock.subprocess.run", side_effect=fake_export),
        ):
            exports = export_bursts(data, Path(tmp), 1, 5)
            self.assertEqual(exports[0]["status"], "ok")
            self.assertEqual((Path(tmp) / exports[0]["path"]).read_bytes(), b"pcapng")
            data["exports"] = exports
            write_report(data, Path(tmp))
            self.assertIn(
                'href="evidence/burst-001-B.pcapng"',
                (Path(tmp) / "report.html").read_text(),
            )

    def test_failed_export_leaves_no_partial_capture(self):
        def failed_export(command, **kwargs):
            Path(command[command.index("-w") + 1]).write_bytes(b"partial")
            kwargs["stderr"].write("corrupt input")
            return subprocess.CompletedProcess(command, 2)

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("sherlock.subprocess.run", side_effect=failed_export),
        ):
            exports = export_bursts(self.export_data(), Path(tmp), 1, 5)
            self.assertEqual(exports[0]["status"], "failed")
            self.assertEqual(exports[0]["diagnostics"], "corrupt input")
            self.assertEqual(list((Path(tmp) / "evidence").iterdir()), [])

    def test_export_disabled_has_no_side_effects(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("sherlock.subprocess.run") as run,
        ):
            self.assertEqual(export_bursts(self.export_data(), Path(tmp), 0, 5), [])
            self.assertEqual(list(Path(tmp).iterdir()), [])
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
