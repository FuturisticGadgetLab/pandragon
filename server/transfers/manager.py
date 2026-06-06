"""
File Transfer Manager

Manages chunked file transfers between beacons and server.
"""

import os
import time
import uuid
import shutil
import tempfile
import threading
import logging
from typing import Optional, Dict, List, Tuple

# Use absolute import within server package
from core.config import get_logger


# Transfer timeout settings
TRANSFER_TIMEOUT_SECONDS = 300  # 5 minutes timeout for stalled transfers
TRANSFER_CLEANUP_INTERVAL = 60  # Check for stalled transfers every 60 seconds


logger = get_logger()


class FileTransferSession:
    """
    Track a single file transfer session.

    Attributes:
        transfer_id: Unique transfer identifier
        beacon_id: Target beacon ID
        direction: 'download' (beacon->server) or 'upload' (server->beacon)
        file_path: Remote file path
        file_size: Total file size in bytes
        chunk_size: Size of each chunk
        chunks_received: Dictionary of received chunks
        bytes_transferred: Total bytes transferred
        status: Transfer status (active, complete, error)
    """

    def __init__(
        self,
        transfer_id: str,
        beacon_id: str,
        direction: str,
        file_path: str,
        file_size: int,
        chunk_size: int = 4096,
        local_save_path: str = None
    ):
        """
        Initialize file transfer session.

        Args:
            transfer_id: Unique transfer ID
            beacon_id: Beacon identifier
            direction: Transfer direction
            file_path: File path
            file_size: File size in bytes
            chunk_size: Chunk size in bytes
            local_save_path: Local path to save downloaded file
        """
        self.transfer_id = transfer_id
        self.beacon_id = beacon_id
        self.direction = direction
        self.file_path = file_path
        self.file_size = file_size
        self.chunk_size = chunk_size
        self.local_save_path = local_save_path
        self.chunks_received: Dict[int, int] = {}
        self.bytes_transferred = 0
        self.started_at = time.time()
        self.last_activity = time.time()
        self.status = 'active'
        self.chunk_count = 0
        self._file_data: Optional[bytes] = None
        self._temp_file = tempfile.NamedTemporaryFile(delete=False)
        self._temp_path = self._temp_file.name

    def add_chunk(self, chunk_index: int, offset: int, data: bytes) -> None:
        """
        Add a received chunk.

        Args:
            chunk_index: Chunk index
            offset: Offset in file
            data: Chunk data
        """
        self._temp_file.seek(offset)
        self._temp_file.write(data)
        self.chunks_received[chunk_index] = len(data)
        self.bytes_transferred += len(data)
        self.last_activity = time.time()
        self.chunk_count += 1

    def get_file_data(self) -> bytes:
        """
        Reassemble file from chunks.

        Returns:
            Reassembled file data
        """
        self._temp_file.flush()
        with open(self._temp_path, 'rb') as f:
            return f.read()

    def is_stalled(self, timeout_seconds: int = TRANSFER_TIMEOUT_SECONDS) -> bool:
        """
        Check if transfer has stalled.

        Args:
            timeout_seconds: Timeout in seconds

        Returns:
            True if transfer stalled
        """
        return (time.time() - self.last_activity) > timeout_seconds

    def _cleanup_temp_file(self) -> None:
        """Close and remove the temporary file on disk."""
        try:
            self._temp_file.close()
        except Exception:
            pass
        try:
            os.unlink(self._temp_path)
        except Exception:
            pass

    def get_elapsed_time(self) -> float:
        """
        Get time since transfer started.

        Returns:
            Elapsed time in seconds
        """
        return time.time() - self.started_at

    def get_progress(self) -> float:
        """
        Get transfer progress.

        Returns:
            Progress as float 0.0-1.0
        """
        if self.file_size <= 0:
            return 0.0
        return self.bytes_transferred / self.file_size


class FileTransferManager:
    """
    Manage chunked file transfers.

    Handles multiple concurrent file transfers with chunking,
    progress tracking, and stall detection.

    Example:
        manager = FileTransferManager()
        transfer_id = manager.start_download(beacon_id, "/path/to/file")
    """

    def __init__(self, chunk_size: int = 4096):
        """
        Initialize file transfer manager.

        Args:
            chunk_size: Default chunk size in bytes
        """
        self.transfers: Dict[str, FileTransferSession] = {}
        self.beacon_downloads: Dict[str, str] = {}
        self.beacon_uploads: Dict[str, str] = {}
        self._lock = threading.Lock()
        self.chunk_size = chunk_size

    def start_download(
        self,
        beacon_id: str,
        file_path: str,
        chunk_size: int = None,
        local_save_path: str = None
    ) -> str:
        """
        Start a file download (beacon -> server).

        Args:
            beacon_id: Beacon identifier
            file_path: Remote file path
            chunk_size: Chunk size in bytes
            local_save_path: Local save path

        Returns:
            Transfer ID
        """
        with self._lock:
            transfer_id = str(uuid.uuid4())[:8]
            session = FileTransferSession(
                transfer_id=transfer_id,
                beacon_id=beacon_id,
                direction='download',
                file_path=file_path,
                file_size=0,
                chunk_size=chunk_size or self.chunk_size,
                local_save_path=local_save_path
            )
            self.transfers[transfer_id] = session
            self.beacon_downloads[beacon_id] = transfer_id
            logger.info(f"Started download: {file_path} from {beacon_id} ({transfer_id})")
            return transfer_id

    def start_upload(
        self,
        beacon_id: str,
        file_path: str,
        file_data: bytes,
        chunk_size: int = None
    ) -> str:
        """
        Start a file upload (server -> beacon).

        Args:
            beacon_id: Beacon identifier
            file_path: Remote file path
            file_data: File data to upload
            chunk_size: Chunk size in bytes

        Returns:
            Transfer ID
        """
        with self._lock:
            transfer_id = str(uuid.uuid4())[:8]
            session = FileTransferSession(
                transfer_id=transfer_id,
                beacon_id=beacon_id,
                direction='upload',
                file_path=file_path,
                file_size=len(file_data),
                chunk_size=chunk_size or self.chunk_size
            )
            session._file_data = file_data
            self.transfers[transfer_id] = session
            self.beacon_uploads[beacon_id] = transfer_id
            logger.info(f"Started upload: {file_path} to {beacon_id} ({transfer_id}, {len(file_data)} bytes)")
            return transfer_id

    def get_upload_chunk(
        self,
        transfer_id: str,
        chunk_index: int
    ) -> Tuple[Optional[str], int, bytes, bool]:
        """
        Get chunk data for upload.

        Args:
            transfer_id: Transfer ID
            chunk_index: Chunk index

        Returns:
            Tuple of (transfer_id, offset, data, is_last)
        """
        with self._lock:
            if transfer_id not in self.transfers:
                return None, 0, b'', False

            session = self.transfers[transfer_id]
            offset = chunk_index * session.chunk_size
            remaining = session.file_size - offset
            chunk_size = min(session.chunk_size, remaining)

            if offset >= session.file_size:
                return None, 0, b'', True

            data = session._file_data[offset:offset + chunk_size]
            is_last = (offset + chunk_size) >= session.file_size

            return transfer_id, offset, data, is_last

    def complete_download(self, beacon_id: str) -> Optional[bytes]:
        """
        Complete a download and return reassembled file data.

        Args:
            beacon_id: Beacon identifier

        Returns:
            Reassembled file data or None
        """
        with self._lock:
            transfer_id = self.beacon_downloads.get(beacon_id)
            if not transfer_id or transfer_id not in self.transfers:
                return None

            session = self.transfers[transfer_id]
            session.status = 'complete'
            file_data = session.get_file_data()

            del self.beacon_downloads[beacon_id]
            del self.transfers[transfer_id]

            logger.info(f"Download complete: {session.file_path} ({len(file_data)} bytes)")
            return file_data

    def get_transfer_status(self, transfer_id: str) -> Optional[dict]:
        """
        Get transfer status.

        Args:
            transfer_id: Transfer ID

        Returns:
            Status dictionary or None
        """
        with self._lock:
            if transfer_id not in self.transfers:
                return None

            session = self.transfers[transfer_id]
            return {
                'transfer_id': transfer_id,
                'beacon_id': session.beacon_id,
                'direction': session.direction,
                'file_path': session.file_path,
                'file_size': session.file_size,
                'bytes_transferred': session.bytes_transferred,
                'chunks_received': len(session.chunks_received),
                'status': session.status,
                'progress': session.get_progress(),
                'elapsed_time': session.get_elapsed_time(),
                'is_stalled': session.is_stalled()
            }

    def cleanup_stalled_transfers(self) -> List[str]:
        """
        Clean up stalled transfers.

        Returns:
            List of cleaned transfer IDs
        """
        cleaned = []
        with self._lock:
            stalled_transfers = [
                (tid, session)
                for tid, session in list(self.transfers.items())
                if session.is_stalled() and session.status == 'active'
            ]

            for transfer_id, session in stalled_transfers:
                logger.warning(f"Cleaning up stalled transfer {transfer_id}")

                if session.direction == 'download':
                    self.beacon_downloads.pop(session.beacon_id, None)
                elif session.direction == 'upload':
                    self.beacon_uploads.pop(session.beacon_id, None)

            session._cleanup_temp_file()
            session.status = 'error'
            del self.transfers[transfer_id]
            cleaned.append(transfer_id)

        return cleaned

    def cancel_transfer(self, transfer_id: str) -> bool:
        """
        Manually cancel a transfer.

        Args:
            transfer_id: Transfer ID

        Returns:
            True if cancelled
        """
        with self._lock:
            if transfer_id not in self.transfers:
                return False

            session = self.transfers[transfer_id]
            session._cleanup_temp_file()
            session.status = 'error'

            if session.direction == 'download':
                self.beacon_downloads.pop(session.beacon_id, None)
            elif session.direction == 'upload':
                self.beacon_uploads.pop(session.beacon_id, None)

            del self.transfers[transfer_id]
            logger.info(f"Cancelled transfer: {transfer_id}")
            return True

    def get_stats(self) -> Dict:
        """
        Get transfer statistics.

        Returns:
            Dictionary with transfer stats
        """
        with self._lock:
            active = sum(1 for t in self.transfers.values() if t.status == 'active')
            complete = sum(1 for t in self.transfers.values() if t.status == 'complete')
            stalled = sum(1 for t in self.transfers.values() if t.is_stalled())

            return {
                'total_transfers': len(self.transfers),
                'active': active,
                'complete': complete,
                'stalled': stalled,
                'active_downloads': len(self.beacon_downloads),
                'active_uploads': len(self.beacon_uploads),
            }

    def set_download_file_size(self, transfer_id: str, file_size: int) -> bool:
        """
        Set the file size for a download transfer (from FILE_DOWNLOAD_ACK).

        Args:
            transfer_id: Transfer ID
            file_size: Total file size in bytes

        Returns:
            True if successful, False if transfer not found
        """
        with self._lock:
            if transfer_id not in self.transfers:
                return False

            session = self.transfers[transfer_id]
            session.file_size = file_size
            logger.info(f"Set file size for transfer {transfer_id}: {file_size} bytes")
            return True

    def add_chunk_with_status(
        self,
        transfer_id: str,
        chunk_index: int,
        offset: int,
        data: bytes,
        status: int
    ) -> Optional[str]:
        """
        Add a chunk with status information from beacon's FILE_CHUNK_DATA response.

        Args:
            transfer_id: Transfer ID
            chunk_index: Chunk index
            offset: Byte offset in file
            data: Chunk data
            status: Chunk status (0=OK, 1=EOF, 2=ERROR)

        Returns:
            Status string: 'ok', 'complete', 'error', or None on failure
        """
        with self._lock:
            if transfer_id not in self.transfers:
                logger.warning(f"add_chunk_with_status: transfer {transfer_id} not found")
                return None

            session = self.transfers[transfer_id]

            if status == 2:  # ERROR
                session.status = 'error'
                logger.error(f"Chunk error for transfer {transfer_id}, chunk {chunk_index}")
                return 'error'

            session.add_chunk(chunk_index, offset, data)

            if status == 1:  # EOF (final chunk)
                session.status = 'complete'
                logger.info(
                    f"Download complete for transfer {transfer_id}: "
                    f"{session.file_path} ({session.bytes_transferred} bytes, "
                    f"{session.chunk_count} chunks)"
                )
                return 'complete'

            return 'ok'

    def assemble_download_file(
        self,
        transfer_id: str,
        output_dir: str
    ) -> Optional[str]:
        """
        Assemble downloaded chunks and write to disk.

        Args:
            transfer_id: Transfer ID
            output_dir: Directory to write the assembled file

        Returns:
            Path to written file, or None on failure
        """
        with self._lock:
            if transfer_id not in self.transfers:
                logger.warning(f"assemble_download_file: transfer {transfer_id} not found")
                return None

            session = self.transfers[transfer_id]

            if session.direction != 'download':
                logger.error(f"Transfer {transfer_id} is not a download")
                return None

            if session.status != 'complete':
                logger.warning(
                    f"Transfer {transfer_id} not complete (status={session.status})"
                )
                return None

        # Derive output filename from remote path if no local_save_path set
        if session.local_save_path:
            output_path = session.local_save_path
        else:
            # Sanitize remote filename: strip directory separators
            remote_name = os.path.basename(session.file_path.replace('\\', '/'))
            if not remote_name:
                remote_name = f"download_{transfer_id}"
            output_path = os.path.join(output_dir, remote_name)

        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)

        try:
            session._temp_file.close()
            shutil.copy2(session._temp_path, output_path)
            os.unlink(session._temp_path)
            file_size = os.path.getsize(output_path)
            logger.info(
                f"Assembled download {transfer_id} to {output_path} "
                f"({file_size} bytes)"
            )
            return output_path
        except OSError as e:
            logger.error(f"Failed to assemble download {output_path}: {e}")
            return None


