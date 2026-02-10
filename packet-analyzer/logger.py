import threading
from pathlib import Path
from typing import Optional


class PacketLogger:

    def __init__(self, filepath: str):
        self._filepath = Path(filepath)
        self._lock = threading.Lock()
        self._file = None

    def open(self) -> None:
        self._file = self._filepath.open("a", encoding="utf-8", buffering=1)

    def write(self, line: str) -> None:
        if self._file is None:
            return
        with self._lock:
            self._file.write(line + "\n")

    def close(self) -> None:
        if self._file:
            with self._lock:
                try:
                    self._file.flush()
                    self._file.close()
                except OSError:
                    pass
                self._file = None
