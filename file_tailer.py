#!/usr/bin/env python3
"""
Shared JSONL file tailing module for streaming pipeline.

Provides:
- JSONLTailer: Tails a JSONL file, yields parsed JSON objects with state persistence
- append_jsonl(): Writes one JSON object as a line + flush

Used by all downstream pipeline scripts in --follow mode.
"""

import json
import os
import sys
import time
from typing import Any, Dict, Generator, Optional


class JSONLTailer:
    """
    Tail a JSONL file, yielding parsed JSON objects.

    Features:
    - follow() generator: scans existing data, then polls for new lines
    - read_one(): non-blocking single read (for dual-input polling)
    - State persistence: saves {position, inode} to a state file every N events
    - File rotation detection via inode comparison
    - Resumes from saved position on restart
    - Waits for input file to appear if it doesn't exist yet
    """

    def __init__(
        self,
        filepath: str,
        state_file: Optional[str] = None,
        poll_interval: float = 0.5,
        save_every: int = 10,
    ):
        self.filepath = filepath
        self.state_file = state_file
        self.poll_interval = poll_interval
        self.save_every = save_every

        self._file = None
        self._inode = None
        self._position = 0
        self._event_counter = 0
        self._stopped = False
        self._partial = ""
        self._max_partial = 1024 * 1024  # 1 MB cap on partial line buffer

        # Restore state
        if self.state_file:
            self._load_state()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def follow(self) -> Generator[Dict[str, Any], None, None]:
        """
        Generator that yields parsed JSON objects.

        First drains all existing lines (catch-up), then polls for new lines
        until stop() is called.
        """
        self._wait_for_file()

        while not self._stopped:
            line = self._readline()
            if line is not None:
                obj = self._parse_line(line)
                if obj is not None:
                    self._event_counter += 1
                    if self.state_file and self._event_counter % self.save_every == 0:
                        self._save_state()
                    yield obj
            else:
                # No data available – poll
                time.sleep(self.poll_interval)
                # Check for file rotation
                if self._check_rotation():
                    self._reopen()

    def read_one(self) -> Optional[Dict[str, Any]]:
        """
        Non-blocking: try to read and parse one JSONL line.

        Returns parsed object or None if nothing available.
        Used by fusion's dual-input polling loop.
        """
        if self._file is None:
            if not os.path.exists(self.filepath):
                return None
            self._open()
            if self._file is None:
                return None

        if self._check_rotation():
            self._reopen()
            if self._file is None:
                return None

        line = self._readline()
        if line is not None:
            obj = self._parse_line(line)
            if obj is not None:
                self._event_counter += 1
                if self.state_file and self._event_counter % self.save_every == 0:
                    self._save_state()
            return obj
        return None

    def stop(self):
        """Signal the tailer to stop."""
        self._stopped = True

    def close(self):
        """Flush state and close the file handle."""
        if self.state_file and self._inode is not None:
            self._save_state()
        if self._file:
            self._file.close()
            self._file = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _wait_for_file(self):
        """Block until the input file appears on disk."""
        while not self._stopped and not os.path.exists(self.filepath):
            print(
                f"[JSONLTailer] Waiting for {self.filepath}...",
                file=sys.stderr,
            )
            time.sleep(self.poll_interval * 4)

        if not self._stopped:
            self._open()

    def _open(self):
        """Open (or reopen) the file, seeking to saved position if valid."""
        try:
            if self._file:
                self._file.close()

            self._file = open(self.filepath, "r", encoding="utf-8", errors="replace")
            stat = os.stat(self.filepath)
            new_inode = stat.st_ino

            # If inode matches saved state, seek to saved position
            if self._inode == new_inode and self._position > 0:
                file_size = stat.st_size
                seek_to = min(self._position, file_size)
                self._file.seek(seek_to)
            else:
                # New file or first open – start from beginning
                self._position = 0

            self._inode = new_inode
            self._partial = ""
        except FileNotFoundError:
            self._file = None
            self._inode = None

    def _reopen(self):
        """Reopen after rotation detected."""
        self._position = 0
        self._partial = ""
        self._open()

    def _readline(self) -> Optional[str]:
        """
        Read one complete line from the file.

        Returns the stripped line content, or None if no complete line available.
        Handles partial lines by buffering.
        """
        if self._file is None:
            return None

        raw = self._file.readline()
        if not raw:
            return None

        # readline() returns '' at EOF, or a string possibly without trailing \n
        if not raw.endswith("\n"):
            # Partial line – buffer it and signal no complete line
            self._partial += raw
            # Discard if buffer exceeds cap (malformed data protection)
            if len(self._partial) > self._max_partial:
                self._partial = ""
            return None

        line = self._partial + raw
        self._partial = ""
        self._position = self._file.tell()
        stripped = line.strip()
        return stripped if stripped else None

    def _parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a JSONL line into a dict. Returns None on failure."""
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None

    def _check_rotation(self) -> bool:
        """Detect file rotation by inode change or size shrink."""
        if self._file is None:
            return False
        try:
            stat = os.stat(self.filepath)
            if stat.st_ino != self._inode or stat.st_size < self._position:
                return True
        except FileNotFoundError:
            return True
        return False

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def _load_state(self):
        """Load saved position and inode from state file."""
        if not self.state_file or not os.path.exists(self.state_file):
            return
        try:
            with open(self.state_file, "r") as f:
                state = json.load(f)
                self._position = state.get("position", 0)
                self._inode = state.get("inode")
        except Exception:
            pass

    def _save_state(self):
        """Persist current position and inode."""
        if not self.state_file:
            return
        try:
            os.makedirs(os.path.dirname(self.state_file) or ".", exist_ok=True)
            with open(self.state_file, "w") as f:
                json.dump({"position": self._position, "inode": self._inode}, f)
        except Exception as e:
            print(
                f"[JSONLTailer] Warning: could not save state: {e}",
                file=sys.stderr,
            )


# ======================================================================
# Helper: atomic JSONL append
# ======================================================================

def append_jsonl(fileobj, obj: Dict[str, Any]):
    """Write one JSON object as a compact JSONL line and flush."""
    fileobj.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n")
    fileobj.flush()
