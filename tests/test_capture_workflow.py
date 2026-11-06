"""Real tshark coverage using small, generated Ethernet/IPv4/TCP captures."""

import contextlib
import io
import json
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import unittest

from sherlock import main


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def packet(reverse, seq, ack, flags, payload=b""):
    src, dst = socket.inet_aton("192.0.2.1"), socket.inet_aton("192.0.2.2")
    sport, dport = 12345, 9000
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 4096, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 1, 0, 64, 6, 0, src, dst
    )
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return b"\x00" * 12 + b"\x08\x00" + ip + tcp + payload


def capture(path, offset=0):
    packets = [
        packet(False, 100, 0, 2),
        packet(True, 200, 101, 18),
        packet(False, 101, 201, 16),
        packet(False, 101, 201, 24, b"x" * 32),
        packet(True, 201, 133, 20),
    ]
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 54, 1))
        for index, raw in enumerate(packets):
            timestamp = 120 + index * 0.1 + offset
            seconds = int(timestamp)
            output.write(
                struct.pack(
                    "<IIII",
                    seconds,
                    round((timestamp - seconds) * 1e6),
                    min(len(raw), 54),
                    len(raw),
                )
            )
            output.write(raw[:54])


@unittest.skipUnless(shutil.which("tshark"), "tshark is not installed")
class CaptureWorkflowTests(unittest.TestCase):
    def test_two_point_report_and_evidence_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            a, b, output = root / "a.pcap", root / "b.pcap", root / "analysis"
            capture(a)
            capture(b, 0.25)
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(
                    [
                        "--a",
                        str(a),
                        "--b",
                        str(b),
                        "--offset-b",
                        "-0.25",
                        "--threshold",
                        "1",
                        "--export-bursts",
                        "2",
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(code, 0)
            data = json.loads((output / "report.json").read_text())
            self.assertEqual([item["packets"] for item in data["inputs"]], [5, 5])
            self.assertEqual([item["truncated"] for item in data["inputs"]], [1, 1])
            self.assertEqual(
                [item["unique_exact_matches"] for item in data["comparison"]["counts"]],
                [5, 5],
            )
            self.assertEqual(len(data["exports"]), 2)
            for item in data["exports"]:
                self.assertEqual(item["status"], "ok")
                result = subprocess.run(
                    [
                        "tshark",
                        "-n",
                        "-r",
                        str(output / item["path"]),
                        "-T",
                        "fields",
                        "-e",
                        "frame.time_epoch",
                        "-e",
                        "frame.cap_len",
                        "-e",
                        "frame.len",
                    ],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                rows = [line.split("\t") for line in result.stdout.splitlines()]
                self.assertEqual(len(rows), 5)
                expected_start = 120 if item["source"] == "A" else 120.25
                self.assertAlmostEqual(float(rows[0][0]), expected_start)
                self.assertEqual(rows[3][1:], ["54", "86"])

    def test_corrupt_capture_fails_without_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture_path = root / "bad.pcap"
            capture_path.write_bytes(b"not a capture file")
            output = root / "analysis"
            with contextlib.redirect_stderr(io.StringIO()):
                code = main(["--a", str(capture_path), "--output", str(output)])
            self.assertEqual(code, 1)
            self.assertFalse((output / "report.html").exists())


if __name__ == "__main__":
    unittest.main()
