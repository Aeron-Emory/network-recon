import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch
from datetime import timedelta
import sys

import analysis
import server
from freewili import device, transport, results_store
from freewili.ghostesp_client import GhostEspLink, GhostEspIdentity
from freewili.og_client import UnsupportedFeature
from freewili.parsers import extract_radiotap_pcap

OG = transport.PortInfo('COM8', 'OG', '', 0x093c, 0x2054, 'FWOG main bnbridge 002')
DISPLAY = transport.PortInfo('COM9', 'Display', '', 0x093c, 0x2055)
IDENTITY = GhostEspIdentity('GhostESP Revival v2.2.2', 'ESP32-C6', True, {})
HEADER = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 127)
FRAME = bytes.fromhex('000010002c00000001006c090b00d600') + b'\x80\x00' + bytes(22)


def record(payload=FRAME):
    return struct.pack('<IIII', 1, 200, len(payload), len(payload)) + payload


class TransportTests(unittest.TestCase):
    def test_explicit_display_cannot_be_used_as_main(self):
        with patch.object(transport, 'enumerate_ports', return_value=[OG, DISPLAY]):
            with self.assertRaises(transport.DeviceNotFoundError):
                transport.find_og_main('COM9')
            with self.assertRaises(transport.DeviceNotFoundError):
                transport.find_bottlenose_usb('COM8')
            with self.assertRaises(transport.DeviceNotFoundError):
                transport.find_og_main('COM123')

    def test_kernel_lock_cannot_be_stolen_by_age_or_port_case(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(transport, 'LOCK_DIR', Path(temp)):
            first = transport.PortLock('com8', timeout_s=.01)
            with first:
                os.utime(first.lock_path, (1, 1))
                with self.assertRaises(transport.PortBusyError):
                    with transport.PortLock('COM8', timeout_s=.01):
                        self.fail('Concurrent lock was acquired')
            with transport.PortLock('COM8', timeout_s=.01):
                pass

    def test_timed_out_call_closes_port_and_has_no_worker(self):
        fake = Mock()
        with patch.object(transport.serial, 'Serial', return_value=fake):
            def run():
                with transport.SerialLink('COM8') as link:
                    with transport.operation_deadline(-1):
                        link.read_for(10)
            result = server._wrap_hardware_errors(run)
        self.assertEqual(result['status'], 'error')
        fake.close.assert_called_once()

    def test_legacy_menu_client_rejects_raw_bridge_without_writing_keys(self):
        from freewili.og_client import OgConsole
        with patch.object(transport, 'find_og_main', return_value=OG), patch.object(transport.SerialLink, 'open') as opened:
            with self.assertRaises(UnsupportedFeature):
                with OgConsole('COM8'):
                    pass
            opened.assert_not_called()


class GhostTests(unittest.TestCase):
    def test_raw_bridge_sends_plain_cli_commands(self):
        with patch('freewili.ghostesp_client.find_og_main', return_value=OG), patch('freewili.ghostesp_client.SerialLink') as serial_type:
            serial_type.return_value.read_for.return_value = b'Firmware: GhostESP Revival v2.2.2\nModel: ESP32-C6\nCHIPINFO_END\n'
            with GhostEspLink(True, 'COM8') as link:
                self.assertTrue(link.identify().matches_expected)
            serial_type.return_value.write.assert_called_once_with(b'chipinfo\n')
            serial_type.return_value.close.assert_called_once()

    def test_command_grammar_rejects_suffixes_and_control_characters(self):
        link = GhostEspLink(False, 'COM12')
        link.direct = Mock()
        for command in ['stop; reboot', 'chipinfoevil', 'scanap -1', 'capture -wireshark -c 99', 'listadv\nstop']:
            with self.subTest(command=command), self.assertRaises(PermissionError):
                link._send_allowed(command)
        link.direct.write.assert_not_called()

    def test_capture_stops_if_read_fails(self):
        link = GhostEspLink(False, 'COM12')
        link._send_allowed = Mock(side_effect=[transport.DeviceCommunicationError('USB disconnected'), b'stopped'])
        with self.assertRaises(transport.DeviceCommunicationError):
            link.capture(6, 3)
        self.assertEqual(link._send_allowed.call_args_list[-1].args[0], 'capture -stop')

    def test_ble_stops_if_read_fails(self):
        link = GhostEspLink(False, 'COM12')
        link._send_allowed = Mock(side_effect=[transport.DeviceCommunicationError('USB disconnected'), b'stopped'])
        with self.assertRaises(transport.DeviceCommunicationError):
            link.ble_advertiser_scan(3)
        self.assertEqual(link._send_allowed.call_args_list[-1].args[0], 'blescan -s')

    def test_invalid_duration_or_channel_sends_nothing(self):
        link = GhostEspLink(False, 'COM12')
        link._send_allowed = Mock()
        for seconds in [-1, 0, 31, True, 2.5]:
            with self.assertRaises(ValueError):
                link.wifi_scan(seconds)
        with self.assertRaises(ValueError):
            link.capture(12, 3)
        link._send_allowed.assert_not_called()

    def test_gatt_and_reset_require_confirmation(self):
        link = GhostEspLink(False, 'COM12')
        link._send_allowed = Mock()
        with self.assertRaises(PermissionError):
            link.gatt_enumerate(0, False)
        link._send_allowed.assert_not_called()
        self.assertEqual(server.gatt_enumerate_device(0, False)['status'], 'refused')
        self.assertEqual(server.reset_og_main_processor(False)['status'], 'refused')


class CaptureTests(unittest.TestCase):
    def test_prompt_between_packets_and_identical_bytes_inside_payload(self):
        prompt = b'\x1b[38;5;36mghost\x1b[0m> '
        first, second = record(FRAME + prompt), record()
        pcap, packets, details = extract_radiotap_pcap(HEADER + first + prompt + second)
        self.assertEqual(pcap, HEADER + first + second)
        self.assertEqual(len(packets), 2)
        self.assertEqual(details['diagnostic_bytes'], len(prompt))
        self.assertEqual(details['tail_kind'], 'none')

    def test_missing_bytes_do_not_produce_guessed_packets(self):
        _, packets, details = extract_radiotap_pcap(HEADER + record() + b'\x00\x01broken' + record())
        self.assertEqual(len(packets), 1)
        self.assertEqual(details['tail_kind'], 'unparsed_binary')

    def test_capture_saves_raw_transport_and_valid_pcap(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(results_store, 'RESULTS_ROOT', Path(temp)), \
             patch.object(transport, 'find_og_main', return_value=OG), patch.object(transport, 'PortLock'), \
             patch('server.GhostEspLink') as client:
            client.return_value.__enter__.return_value.identify.return_value = IDENTITY
            client.return_value.__enter__.return_value.capture.return_value = dict(
                pcap_bytes=HEADER + record() * 150, raw_capture_bytes=b'raw-wire',
                packets=[dict(frame_type=0, frame_subtype=8)] * 150, monitor_stopped_cleanly=True)
            result = server.capture_wifi_packets(seconds=3, port='COM8')
            folder = Path(temp) / result['saved_to']
            self.assertEqual((folder / 'capture-wire.bin').read_bytes(), b'raw-wire')
            self.assertEqual((folder / 'capture.pcap').read_bytes(), HEADER + record() * 150)
            saved = json.loads((folder / 'observation.json').read_text())
            self.assertNotIn('raw_capture_bytes', saved)
            self.assertEqual(len(saved['packets']), 150)
            self.assertEqual(len(result['packets']), 50)
            self.assertEqual(result['packet_count'], 150)


class ObservationTests(unittest.TestCase):
    def test_missing_security_is_not_reported_as_open_network(self):
        result = analysis.analyze_wifi([dict(ssid='Unknown security', bssid='00:11:22:33:44:55')])
        self.assertEqual(result['summary']['open_count'], 0)
        self.assertFalse(any('Open network' in f['title'] for f in result['findings']))

    def test_run_names_are_unique_and_cannot_escape_results(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(results_store, 'RESULTS_ROOT', Path(temp)):
            with patch.object(results_store, 'datetime') as clock:
                clock.now.return_value.strftime.return_value = 'same-clock-reading'
                self.assertNotEqual(results_store.new_run_dir('wifi'), results_store.new_run_dir('wifi'))
            with self.assertRaises(ValueError):
                results_store.load_observation('../../outside')


class StdioProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_stdio_registration_and_refusals_without_hardware(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        root = Path(__file__).resolve().parents[1]
        params = StdioServerParameters(command=sys.executable, args=[str(root / 'server.py')], cwd=root)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=15)) as client:
                await client.initialize()
                listed = await client.list_tools()
                self.assertEqual(len(listed.tools), 22)
                self.assertIn('get_bridge_status', {t.name for t in listed.tools})
                for name, arguments in [('gatt_enumerate_device', dict(device_index=0, confirm_active_connection=False)),
                                        ('reset_og_main_processor', dict(confirm=False))]:
                    reply = await client.call_tool(name, arguments)
                    self.assertFalse(reply.isError)
                    self.assertEqual(reply.structuredContent['status'], 'refused')


if __name__ == '__main__':
    unittest.main()
