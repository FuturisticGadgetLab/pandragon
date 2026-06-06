"""
Tests for the payload builder module.

Verifies that build_payload() produces binary payloads matching
the exact format expected by beacon handlers.
"""

import struct
import os
import tempfile
import pytest
from protocol.constants import S2BOpcode
from protocol.payload_builder import build_payload


class TestSleep:
    def test_seconds_only(self):
        payload = build_payload(S2BOpcode.SLEEP, b"60")
        sleep_ms, jitter = struct.unpack('<IB', payload)
        assert sleep_ms == 60000
        assert jitter == 0

    def test_seconds_and_jitter(self):
        payload = build_payload(S2BOpcode.SLEEP, b"30 25")
        sleep_ms, jitter = struct.unpack('<IB', payload)
        assert sleep_ms == 30000
        assert jitter == 25

    def test_binary_passthrough(self):
        binary = struct.pack('<IB', 120000, 10)
        result = build_payload(S2BOpcode.SLEEP, binary)
        assert result == binary

class TestFileDownload:
    def test_basic_path(self):
        """Test FILE_DOWNLOAD_START passes path through (chunked protocol)."""
        path = "C:\\secret.txt"
        payload = build_payload(S2BOpcode.FILE_DOWNLOAD_START, path.encode())
        # Pass-through: payload should be unchanged
        assert payload == path.encode()


class TestFileUpload:
    def test_basic_upload(self):
        """Test FILE_UPLOAD_START passes path through (chunked protocol)."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
            f.write(b'\x4d\x5a' + b'\x00' * 50)
            local_path = f.name

        try:
            remote = "C:\\Users\\Public\\tool.exe"
            payload_text = f"{local_path} {remote}"
            payload = build_payload(S2BOpcode.FILE_UPLOAD_START, payload_text.encode())
            # Pass-through: payload should be unchanged
            assert payload == payload_text.encode()
        finally:
            os.unlink(local_path)


class TestPassthrough:
    def test_unknown_opcode_passthrough(self):
        """Unknown opcodes should pass payload through unchanged"""
        payload = build_payload(0xFF, b"\x00\x01\x02")
        assert payload == b"\x00\x01\x02"
