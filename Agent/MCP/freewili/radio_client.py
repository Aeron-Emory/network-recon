"""Receive-only CC1101 controls on bnbridge DISPLAY USB; independent of PCAP USB."""
from __future__ import annotations
import re
import time
import math
from .transport import (SerialLink, DeviceNotFoundError, DeviceCommunicationError,
                        enumerate_ports, operation_deadline)

MODULATIONS = {'ook': 0, '2fsk': 1, 'gfsk': 2}


def frequency_hz(mhz):
    if isinstance(mhz, bool) or not isinstance(mhz, (int, float)) or not math.isfinite(mhz):
        raise ValueError('frequency_mhz must be a number.')
    hz = round(mhz * 1_000_000)
    if not any(low <= hz <= high for low, high in [(300_000_000, 348_000_000),
            (387_000_000, 464_000_000), (779_000_000, 928_000_000)]):
        raise ValueError('Frequency must lie in 300–348, 387–464 or 779–928 MHz.')
    return hz


def find_radio_port(port=None):
    ports = enumerate_ports()
    displays = [p for p in ports if p.is_og_display and p.product.startswith('FWOG display bnbridge ')]
    if port:
        selected = [p for p in ports if p.port.lower() == port.lower()]
        if not selected or not (selected[0].is_raw_bridge or selected[0] in displays):
            raise DeviceNotFoundError('Select a bnbridge MAIN or DISPLAY USB port.')
        if selected[0] in displays:
            displays = selected
        elif len([p for p in ports if p.is_og_main]) != 1:
            raise DeviceNotFoundError('Multiple boards: select the intended DISPLAY port explicitly.')
    if len(displays) != 1:
        raise DeviceNotFoundError('Select exactly one bnbridge DISPLAY port for radio controls.')
    version = displays[0].product.rsplit(' ', 1)[-1]
    if not version.isdigit() or int(version) < 3:
        raise DeviceNotFoundError('Sub-GHz support requires bnbridge version 003 or later.')
    return displays[0]


class RadioClient:
    def __init__(self, port):
        self.link = SerialLink(port, timeout=.05)
        self.pending = ''
        self.seq = 0
        self.responses = []
        self.events = []
        self.bridge = []
        self.errors = []

    def __enter__(self):
        self.link.open()
        try:
            self.read(1.1)
        except BaseException:
            self.link.close(); raise
        return self

    def __exit__(self, *_):
        self.link.close()

    def feed(self, data):
        self.pending += data.decode('ascii', errors='replace')
        while '\n' in self.pending:
            line, self.pending = self.pending.split('\n', 1)
            values = {k: int(v) for k, v in re.findall(r'(\w+)=(-?\d+)', line)}
            if line.startswith('RADIO '):
                self.responses.append(values)
            elif line.startswith('RADIO_ERROR '):
                self.errors.append(line.strip())
            elif line.startswith('BNBRIDGE '):
                self.bridge.append(values)
            elif line.startswith('RADIO_RX '):
                match = re.search(r' data=([0-9a-f]*|-)\r?$', line)
                if not match or 'radio' not in values or 'ms' not in values:
                    raise DeviceCommunicationError('Malformed radio event received.')
                try:
                    payload = bytes.fromhex(match[1]) if match[1] != '-' else b''
                except ValueError as exc:
                    raise DeviceCommunicationError('Malformed radio hex data.') from exc
                self.events.append(dict(radio_index=values['radio'], uptime_ms=values['ms'],
                                        rssi_dbm=values.get('rssi') if values.get('valid') else None,
                                        marcstate=values.get('marc'), payload=payload.hex()))
        if len(self.pending) > 4096:
            raise DeviceCommunicationError('Radio control line exceeded its limit.')

    def read(self, seconds):
        self.feed(self.link.read_for(seconds))

    def command(self, op, radio, hz=0, duration=0, mod=0):
        if type(radio) is not int or radio not in (1, 2):
            raise ValueError('radio_index must be 1 or 2.')
        if op not in (1, 2, 3) or (op != 2 and (hz or duration or mod)):
            raise ValueError('Unsupported radio operation.')
        if op == 2:
            frequency_hz(hz / 1_000_000)
            if type(duration) is not int or not 1000 <= duration <= 30000 or mod not in (0, 1, 2):
                raise ValueError('Invalid receive duration or modulation.')
        self.seq = self.seq % 255 + 1
        self.link.write(f'radio {self.seq} {op} {radio} {hz} {duration} {mod}\n'.encode('ascii'))
        start = len(self.responses)
        errors = len(self.errors)
        end = time.monotonic() + 3
        while time.monotonic() < end:
            self.read(.05)
            if len(self.errors) > errors:
                raise DeviceCommunicationError(self.errors[-1])
            for response in self.responses[start:]:
                if (response.get('seq'), response.get('op'), response.get('radio')) == (self.seq, op, radio):
                    if not response.get('ok'):
                        raise DeviceCommunicationError(f'Radio operation failed: {response}')
                    return response
        raise DeviceCommunicationError('Radio did not acknowledge the request.')

    def status(self, radio):
        result = self.command(1, radio)
        return dict(status='ok', radio_index=radio, hardware=result,
                    rssi_dbm=[result['rssi']] if result.get('valid') else [],
                    frequency_hz=result['actual'] if result.get('configured') else None,
                    note='RSSI is meaningful in RX; the chip/antenna RF link needs a known transmitter to verify.')

    def listen(self, radio, seconds=8, frequency_mhz=None, modulation='ook'):
        if type(seconds) is not int or not 1 <= seconds <= 30:
            raise ValueError('seconds must be an integer from 1 through 30.')
        if modulation not in MODULATIONS:
            raise ValueError('modulation must be ook, 2fsk or gfsk.')
        hz = frequency_hz(frequency_mhz if frequency_mhz is not None else (433.92 if radio == 1 else 915.0))
        before = self.command(1, radio)
        first = len(self.events)
        started = False
        try:
            # Mark before sending so cleanup also handles an ACK timeout.
            started = True
            active = self.command(2, radio, hz, seconds * 1000, MODULATIONS[modulation])
            if not active.get('active') or not active.get('configured') or abs(active['actual'] - hz) > 500:
                raise DeviceCommunicationError(f'Receiver frequency/state readback failed: {active}')
            self.read(seconds)
        finally:
            if started:
                with operation_deadline(4):
                    stopped = self.command(3, radio)
        events = [e for e in self.events[first:] if e['radio_index'] == radio]
        deltas = {k: stopped[k] - before[k] for k in ['samples', 'bytes', 'overflows', 'io_errors']}
        return dict(status='ok' if deltas['samples'] and not deltas['io_errors'] else 'inconclusive',
                    radio_index=radio, frequency_hz=active['actual'], requested_frequency_hz=hz,
                    modulation=modulation, data_rate_baud=4800, rx_bandwidth_khz=203.125,
                    content_mode='unframed_demodulated', events=events,
                    rssi_dbm=[e['rssi_dbm'] for e in events if e['rssi_dbm'] is not None],
                    counters=deltas, stopped=not stopped['active'],
                    hardware_before=before, hardware_after=stopped,
                    bridge_before=self.bridge[0] if self.bridge else None,
                    bridge_after=self.bridge[-1] if self.bridge else None,
                    rf_link_validation='inconclusive_no_known_transmitter',
                    note='Raw demodulator bytes can be noise. They are not decoded packets or proof of a received transmission.')
