"""
Pandragon Server Test Suite

Pytest configuration and fixtures.
"""

import pytest
import os
import sys
import tempfile
import shutil

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files"""
    dirpath = tempfile.mkdtemp()
    yield dirpath
    shutil.rmtree(dirpath)


@pytest.fixture
def temp_file(temp_dir):
    """Create a temporary file"""
    filepath = os.path.join(temp_dir, 'test.txt')
    with open(filepath, 'w') as f:
        f.write('test content')
    yield filepath


@pytest.fixture
def crypto_key():
    """Generate a random 32-byte crypto key"""
    import os
    return os.urandom(32)


@pytest.fixture
def beacon_id(crypto_key):
    """Derive beacon ID from crypto key"""
    import hashlib
    return hashlib.sha256(crypto_key).digest()[:8]


@pytest.fixture
def sample_packet(crypto_key, beacon_id):
    """Create a sample encrypted packet"""
    from protocol.parser import serialize_response
    from protocol.constants import B2SOpcode
    
    return serialize_response(
        opcode=B2SOpcode.BEACON_CHECK_IN,
        beacon_id=beacon_id,
        seq_num=0,
        payload=b"test payload",
        key=crypto_key
    )


@pytest.fixture
def beacon_registry():
    """Create a beacon registry for testing"""
    from beacon.registry import BeaconRegistry
    return BeaconRegistry()


@pytest.fixture
def operator_manager(temp_dir):
    """Create an operator manager with temp credentials file"""
    from operators.manager import OperatorManager
    cred_file = os.path.join(temp_dir, 'operators.json')
    return OperatorManager(cred_file=cred_file)


@pytest.fixture
def file_transfer_manager():
    """Create a file transfer manager for testing"""
    from transfers.manager import FileTransferManager
    return FileTransferManager(chunk_size=1024)


@pytest.fixture
def lru_cache():
    """Create an LRU cache for testing"""
    from security.replay_protection import LRUCache
    return LRUCache(capacity=100)
