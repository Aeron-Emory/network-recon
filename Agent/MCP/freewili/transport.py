"""Serial port discovery, locking, and a recoverable byte-level transport.

Independent reimplementation. No code or imports from the parent workshop
scripts. Behavior (VID/PID values, timing) is informed by reading the
parent project's own README/REPAIR-REPORT as reference documentation of the
real hardware, not by reusing its code.
"""
from __future__ import annotations

import json
import os
import platform
import re
import time
import subprocess
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import serial
from serial.tools import list_ports

# Free-WILi OG MAIN/DISPLAY USB identifiers.
OG_VID = 0x093C
OG_PID_MAIN = 0x2054
OG_PID_DISPLAY = 0x2055

# Bottlenose's own ESP32-C6 USB debug/JTAG serial port (direct connection,
# bypassing the OG). Used only when the user explicitly connects to it.
ESP_VID = 0x303A
ESP_USB_PID = 0x1001

LOCK_DIR = Path(__file__).resolve().parent.parent / "results" / ".port-locks"
_deadline = ContextVar('hardware_deadline', default=None)


@contextmanager
def operation_deadline(seconds: float):
    token = _deadline.set(time.monotonic() + seconds)
    try:
        yield
    finally:
        _deadline.reset(token)


def check_deadline():
    deadline = _deadline.get()
    if deadline is not None and time.monotonic() >= deadline:
        raise DeviceCommunicationError('Hardware operation exceeded its deadline; connection closed.')


class PortBusyError(RuntimeError):
    """Raised when another process (or another tool call) holds the port lock."""


class DeviceNotFoundError(RuntimeError):
    """Raised when no matching serial device is present."""


class DeviceCommunicationError(RuntimeError):
    """Raised for I/O failures distinct from 'device not present'."""


@dataclass
class PortInfo:
    port: str
    description: str
    hardware_id: str
    vid: Optional[int] = None
    pid: Optional[int] = None
    product: str = ""

    @property
    def is_og_main(self) -> bool:
        return self.vid == OG_VID and self.pid == OG_PID_MAIN

    @property
    def is_og_display(self) -> bool:
        return self.vid == OG_VID and self.pid == OG_PID_DISPLAY

    @property
    def is_bottlenose_usb(self) -> bool:
        return self.vid == ESP_VID and self.pid == ESP_USB_PID

    @property
    def is_raw_bridge(self) -> bool:
        return self.is_og_main and self.product.startswith('FWOG main bnbridge ')

    def to_dict(self) -> dict:
        return dict(port=self.port, description=self.description, hardware_id=self.hardware_id,
                    vid=self.vid, pid=self.pid, product=self.product,
                    role=("og_main" if self.is_og_main else "og_display" if self.is_og_display
                          else "bottlenose_usb" if self.is_bottlenose_usb else "unknown"))


def enumerate_ports() -> list[PortInfo]:
    """List serial ports visible to the OS, independent of any other tool."""
    check_deadline()
    if platform.system() == 'Windows':
        # Bound Windows discovery and read the USB product string from the
        # composite device's parent, rather than its generic CDC interface.
        script = r'''
        $ErrorActionPreference='Stop'
        $rows=@(Get-CimInstance Win32_PnPEntity -Filter "PNPClass = 'Ports'" | ForEach-Object {
          if ($_.Name -match '\((COM\d+)\)') {
            $com=$matches[1]; $product=''
            if ($_.PNPDeviceID -like 'USB\VID_093C*') {
              $parent=(Get-PnpDeviceProperty -InstanceId $_.PNPDeviceID -KeyName DEVPKEY_Device_Parent -ErrorAction SilentlyContinue).Data
              if ($parent) { $product=(Get-PnpDeviceProperty -InstanceId $parent -KeyName DEVPKEY_Device_BusReportedDeviceDesc -ErrorAction SilentlyContinue).Data }
            }
            [pscustomobject]@{port=$com; description=$_.Name; hardware_id=$_.PNPDeviceID; product=$product}
          }
        })
        ConvertTo-Json -InputObject $rows -Compress
        '''
        try:
            result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                                    capture_output=True, text=True, timeout=15, check=True,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            rows = json.loads(result.stdout or '[]')
        except (subprocess.SubprocessError, ValueError) as exc:
            raise DeviceCommunicationError(f'Windows serial discovery failed: {exc}') from exc
        ports = []
        for row in rows:
            match = re.search(r'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})', row['hardware_id'])
            ports.append(PortInfo(**row, vid=int(match[1], 16) if match else None,
                                  pid=int(match[2], 16) if match else None))
        check_deadline()
        return ports
    results = []
    for p in list_ports.comports():
        hwid = p.hwid or ""
        match = re.search(r"VID:PID=([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4})", hwid)
        vid = int(match[1], 16) if match else p.vid
        pid = int(match[2], 16) if match else p.pid
        results.append(PortInfo(port=p.device, description=p.description or "", hardware_id=hwid,
                                vid=vid, pid=pid, product=p.product or ""))
    return results


def find_og_main(explicit_port: Optional[str] = None) -> PortInfo:
    ports = enumerate_ports()
    if explicit_port:
        for p in ports:
            if p.port.lower() == explicit_port.lower() and p.is_og_main:
                return p
        raise DeviceNotFoundError(f'{explicit_port} is not a detected OG MAIN port (093C:2054).')
    candidates = [p for p in ports if p.is_og_main]
    if not candidates:
        raise DeviceNotFoundError(
            "No Free-WILi OG MAIN USB port (VID 0x093C PID 0x2054) was found. "
            "Connect the OG's USB-C port to this PC, or pass an explicit port.")
    if len(candidates) > 1:
        raise DeviceNotFoundError(
            f"Multiple OG MAIN ports found ({[p.port for p in candidates]}); "
            "pass an explicit port to disambiguate.")
    return candidates[0]


def find_bottlenose_usb(explicit_port: Optional[str] = None) -> PortInfo:
    ports = enumerate_ports()
    if explicit_port:
        for p in ports:
            if p.port.lower() == explicit_port.lower() and p.is_bottlenose_usb:
                return p
        raise DeviceNotFoundError(f'{explicit_port} is not a detected Bottlenose USB port (303A:1001).')
    candidates = [p for p in ports if p.is_bottlenose_usb]
    if not candidates:
        raise DeviceNotFoundError(
            "No Bottlenose direct USB port (VID 0x303A PID 0x1001) was found. "
            "Connect Bottlenose's own USB-C port, keeping it powered through the OG, "
            "or use the OG-bridged connection instead.")
    if len(candidates) > 1:
        raise DeviceNotFoundError(
            f"Multiple Bottlenose USB ports found ({[p.port for p in candidates]}); "
            "pass an explicit port to disambiguate.")
    return candidates[0]


class PortLock:
    """Kernel-held advisory lock; a process exit always releases it.

    The persistent file is only a lock anchor. Its age never permits taking
    an active owner's lock, and COM port names are case insensitive.
    """
    def __init__(self, port: str, timeout_s: float = 5.0):
        self.port, self.timeout_s = port, timeout_s
        safe = re.sub(r"[^A-Za-z0-9_-]", "_", port.upper())
        # COM8.lock is still a reserved DOS device name on Windows.
        self.lock_path = LOCK_DIR / f"port-{safe}.lock"
        self._file = None

    def acquire(self):
        LOCK_DIR.mkdir(parents=True, exist_ok=True)
        self._file = self.lock_path.open('a+b')
        self._file.seek(0, 2)
        if self._file.tell() == 0:
            self._file.write(b'0'); self._file.flush()
        end = time.monotonic() + self.timeout_s
        try:
            while True:
                check_deadline()
                self._file.seek(0)
                try:
                    if os.name == 'nt':
                        import msvcrt
                        msvcrt.locking(self._file.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return
                except OSError as exc:
                    if time.monotonic() >= end:
                        raise PortBusyError(f'{self.port} is in use by another MCP operation.') from exc
                    time.sleep(.05)
        except BaseException:
            self._file.close(); self._file = None
            raise

    def release(self):
        if self._file is not None:
            self._file.close(); self._file = None

    def __enter__(self):
        self.acquire(); return self

    def __exit__(self, *_exc):
        self.release()


@dataclass
class TranscriptEntry:
    direction: str  # "tx" or "rx"
    text: str
    host_unix: float = field(default_factory=time.time)


class SerialLink:
    """Byte-level serial connection with basic error recovery.

    Independent of pyserial usage patterns in the parent project; written
    directly against pyserial's own documented API.
    """

    def __init__(self, port: str, baudrate: int = 115200, rtscts: bool = False,
                timeout: float = 0.1):
        self.port = port
        self.baudrate = baudrate
        self.rtscts = rtscts
        self.timeout = timeout
        self.stream: Optional[serial.Serial] = None
        self.transcript: list[TranscriptEntry] = []

    def open(self) -> None:
        check_deadline()
        try:
            self.stream = serial.Serial(
                port=None, baudrate=self.baudrate, timeout=self.timeout,
                write_timeout=2, rtscts=self.rtscts, xonxoff=False, dsrdtr=False)
            self.stream.port = self.port
            self.stream.dtr = True
            self.stream.rts = False
            self.stream.open()
        except serial.SerialException as exc:
            raise DeviceCommunicationError(f"Could not open {self.port}: {exc}") from exc

    def close(self) -> None:
        if self.stream and self.stream.is_open:
            try:
                self.stream.close()
            except serial.SerialException:
                pass

    def reconnect(self, attempts: int = 3, delay_s: float = 1.0) -> None:
        """Attempt to recover from a dropped connection (e.g. the OG or
        Bottlenose reset itself mid-operation)."""
        self.close()
        last_exc: Optional[Exception] = None
        for _ in range(attempts):
            time.sleep(delay_s)
            try:
                self.open()
                return
            except DeviceCommunicationError as exc:
                last_exc = exc
        raise DeviceCommunicationError(
            f"Could not reconnect to {self.port} after {attempts} attempts: {last_exc}")

    def read_for(self, seconds: float, max_bytes: int = 4_000_000) -> bytes:
        if not self.stream:
            raise DeviceCommunicationError(f"{self.port} is not open.")
        end = time.monotonic() + seconds
        chunks = []
        total = 0
        try:
            while time.monotonic() < end:
                check_deadline()
                chunk = self.stream.read(min(self.stream.in_waiting or 1, 4096))
                if chunk:
                    total += len(chunk)
                    if total > max_bytes:
                        raise DeviceCommunicationError(
                            f"Read exceeded the {max_bytes}-byte safety limit for one operation.")
                    chunks.append(chunk)
        except serial.SerialException as exc:
            raise DeviceCommunicationError(f"Read from {self.port} failed: {exc}") from exc
        finally:
            data = b"".join(chunks)
            if data:
                self.transcript.append(TranscriptEntry("rx", data.decode("utf-8", errors="replace")))
        return b"".join(chunks)

    def write(self, data: bytes) -> None:
        check_deadline()
        if not self.stream:
            raise DeviceCommunicationError(f"{self.port} is not open.")
        self.transcript.append(TranscriptEntry("tx", data.decode("ascii", errors="replace")))
        try:
            self.stream.write(data)
        except serial.SerialException as exc:
            raise DeviceCommunicationError(f"Write to {self.port} failed: {exc}") from exc

    def send(self, data: bytes, seconds: float = 0.65) -> bytes:
        self.write(data)
        return self.read_for(seconds)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *_exc):
        self.close()
