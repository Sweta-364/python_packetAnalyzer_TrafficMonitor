import socket
import time
import threading
from typing import Callable, Optional

ETH_P_ALL = 0x0003
BUFFER_SIZE = 65535


class PacketSniffer:

    def __init__(
        self,
        interface: Optional[str] = None,
        callback: Optional[Callable[[bytes, float], None]] = None,
    ):
        self._interface = interface
        self._callback = callback
        self._running = threading.Event()
        self._socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None

    def _create_socket(self) -> socket.socket:
        sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
        )
        sock.settimeout(1.0)
        if self._interface:
            sock.bind((self._interface, 0))
        return sock

    def _capture_loop(self) -> None:
        while self._running.is_set():
            try:
                raw_data, _ = self._socket.recvfrom(BUFFER_SIZE)
                timestamp = time.time()
                if self._callback:
                    self._callback(raw_data, timestamp)
            except socket.timeout:
                continue
            except OSError:
                if self._running.is_set():
                    continue
                break

    def start(self) -> None:
        self._socket = self._create_socket()
        self._running.set()
        self._thread = threading.Thread(
            target=self._capture_loop, daemon=True, name="sniffer"
        )
        self._thread.start()

    def stop(self) -> None:
        self._running.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

    @property
    def is_running(self) -> bool:
        return self._running.is_set()
