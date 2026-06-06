"""
Unit Tests for Protocol Parser

Tests for packet parsing, serialization, and crypto operations.
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from protocol.parser import parse_packet, parse_header, serialize_response, decrypt_payload
from protocol.constants import PANDRAGON_MAGIC, B2SOpcode, S2BOpcode


class TestParseHeader:
    """Test header parsing"""

    def test_valid_header(self, sample_packet):
        """Test parsing valid packet header"""
        header, err = parse_header(sample_packet)
        assert header is not None
        assert err == ""
        assert header['magic'] == PANDRAGON_MAGIC
        assert header['version'] == 0
        assert header['opcode'] == B2SOpcode.BEACON_CHECK_IN

    def test_buffer_too_small(self):
        """Test parsing truncated buffer"""
        header, err = parse_header(b"short")
        assert header is None
        assert "Buffer too small" in err

    def test_invalid_magic(self, crypto_key, beacon_id):
        """Test parsing packet with invalid magic"""
        packet = serialize_response(
            opcode=B2SOpcode.BEACON_CHECK_IN,
            beacon_id=beacon_id,
            seq_num=0,
            payload=b"test",
            key=crypto_key
        )
        # Corrupt magic
        corrupted = bytearray(packet)
        corrupted[0:4] = b'\x00\x00\x00\x00'
        
        header, err = parse_header(bytes(corrupted))
        assert header is not None
        assert header['magic'] == 0


class TestParsePacket:
    """Test full packet parsing"""

    def test_valid_packet(self, sample_packet, crypto_key):
        """Test parsing valid encrypted packet"""
        parsed, err = parse_packet(sample_packet, crypto_key, direction_s2b=False)
        assert parsed is not None
        assert err == ""
        assert parsed.opcode == B2SOpcode.BEACON_CHECK_IN
        assert parsed.payload == b"test payload"

    def test_wrong_key(self, sample_packet, beacon_id):
        """Test parsing with wrong crypto key"""
        wrong_key = b'x' * 32
        parsed, err = parse_packet(sample_packet, wrong_key, direction_s2b=False)
        assert parsed is None
        assert "Decryption failed" in err

    def test_empty_data(self, crypto_key):
        """Test parsing empty data"""
        parsed, err = parse_packet(b"", crypto_key, direction_s2b=False)
        assert parsed is None
        assert "Empty data" in err

    def test_truncated_packet(self, sample_packet, crypto_key):
        """Test parsing truncated packet"""
        parsed, err = parse_packet(sample_packet[:40], crypto_key, direction_s2b=False)
        assert parsed is None
        assert "Packet too small" in err


class TestSerializeResponse:
    """Test packet serialization"""

    def test_serialize_and_parse_roundtrip(self, crypto_key, beacon_id):
        """Test serializing then parsing returns original data"""
        original_payload = b"Hello, World!"
        
        # Serialize
        packet = serialize_response(
            opcode=S2BOpcode.ECHO,
            beacon_id=beacon_id,
            seq_num=42,
            payload=original_payload,
            key=crypto_key
        )
        
        # Parse
        parsed, err = parse_packet(packet, crypto_key, direction_s2b=True)
        
        assert parsed is not None
        assert parsed.opcode == S2BOpcode.ECHO
        assert parsed.seq_num == 42
        assert parsed.payload == original_payload

    def test_invalid_key_length(self, beacon_id):
        """Test serialization with invalid key length"""
        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            serialize_response(
                opcode=S2BOpcode.ECHO,
                beacon_id=beacon_id,
                seq_num=0,
                payload=b"test",
                key=b"short"
            )

    def test_invalid_beacon_id_length(self, crypto_key):
        """Test serialization with invalid beacon ID length"""
        with pytest.raises(ValueError, match="Beacon ID must be 8 bytes"):
            serialize_response(
                opcode=S2BOpcode.ECHO,
                beacon_id=b"short",
                seq_num=0,
                payload=b"test",
                key=crypto_key
            )

    def test_padding(self, crypto_key, beacon_id):
        """Test serialization with padding"""
        packet_no_padding = serialize_response(
            opcode=S2BOpcode.ECHO,
            beacon_id=beacon_id,
            seq_num=0,
            payload=b"test",
            key=crypto_key,
            pad = False,
            pad_max=0
        )
        
        packet_with_padding = serialize_response(
            opcode=S2BOpcode.ECHO,
            beacon_id=beacon_id,
            seq_num=0,
            payload=b"test",
            key=crypto_key,
            pad = True,
            pad_max=32
        )
        
        # Packet with padding should be larger
        assert len(packet_with_padding) > len(packet_no_padding) and len(packet_with_padding) <= len(packet_no_padding) + 32


class TestDecryptPayload:
    """Test payload decryption"""

    def test_valid_decryption(self, crypto_key):
        """Test valid decryption"""
        import os
        from Crypto.Cipher import ChaCha20_Poly1305
        
        nonce = os.urandom(24)
        plaintext = b"secret message"
        
        cipher = ChaCha20_Poly1305.new(key=crypto_key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        ciphertext_with_mac = ciphertext + tag
        
        success, result = decrypt_payload(ciphertext_with_mac, nonce, crypto_key)
        
        assert success is True
        assert result == plaintext

    def test_invalid_nonce_length(self, crypto_key):
        """Test decryption with invalid nonce length"""
        success, result = decrypt_payload(b"data", b"short", crypto_key)
        assert success is False
        assert result == b""

    def test_invalid_key_length(self):
        """Test decryption with invalid key length"""
        success, result = decrypt_payload(b"data", b"n" * 24, b"short")
        assert success is False
        assert result == b""

    def test_tampered_data(self, crypto_key):
        """Test decryption detects tampering"""
        import os
        from Crypto.Cipher import ChaCha20_Poly1305
        
        nonce = os.urandom(24)
        plaintext = b"secret message"
        
        cipher = ChaCha20_Poly1305.new(key=crypto_key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        ciphertext_with_mac = ciphertext + tag
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext_with_mac)
        tampered[0] ^= 0xFF
        
        success, result = decrypt_payload(bytes(tampered), nonce, crypto_key)
        
        assert success is False
        assert result == b""
