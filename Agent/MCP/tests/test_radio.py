import unittest
from unittest.mock import Mock, patch
import analysis
from freewili.radio_client import RadioClient, find_radio_port, frequency_hz
from freewili.transport import PortInfo, DeviceNotFoundError, DeviceCommunicationError


class RadioTests(unittest.TestCase):
    def test_frequency_limits_and_invalid_values(self):
        self.assertEqual(frequency_hz(433.92), 433920000)
        self.assertEqual(frequency_hz(915), 915000000)
        for value in [299, 350, 500, 929, float('nan'), float('inf'), True, '433;tx']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                frequency_hz(value)

    def test_old_bridge_refused_without_sending_commands(self):
        ports = [PortInfo('COM9', '', '', 0x093c, 0x2055, 'FWOG display bnbridge 002')]
        with patch('freewili.radio_client.enumerate_ports', return_value=ports):
            with self.assertRaises(DeviceNotFoundError):
                find_radio_port()

    def test_multiple_boards_require_explicit_display(self):
        ports = [PortInfo('COM8', '', '', 0x093c, 0x2054, 'FWOG main bnbridge 003'),
                 PortInfo('COM9', '', '', 0x093c, 0x2055, 'FWOG display bnbridge 003'),
                 PortInfo('COM18', '', '', 0x093c, 0x2054, 'FWOG main bnbridge 003')]
        with patch('freewili.radio_client.enumerate_ports', return_value=ports):
            with self.assertRaises(DeviceNotFoundError):
                find_radio_port('COM8')
            self.assertEqual(find_radio_port('COM9').port, 'COM9')

    def test_streaming_parser_preserves_split_responses_and_raw_bytes(self):
        client = RadioClient('COM9')
        client.feed(b'BNBRIDGE drops=0 errors=1\nRADIO_RX radio=2 ms=50 rssi=-90 valid=1 marc=13 data=01')
        self.assertEqual(client.events, [])
        client.feed(b'ff\nRADIO seq=4 op=1 radio=2 ok=1 actual=915000000\n')
        self.assertEqual(client.events[0]['payload'], '01ff')
        self.assertEqual(client.events[0]['rssi_dbm'], -90)
        self.assertEqual(client.responses[0]['seq'], 4)

    def test_stale_reply_is_not_an_acknowledgement(self):
        client = RadioClient('COM9')
        client.link = Mock()
        client.link.read_for.side_effect = [b'RADIO seq=99 op=1 radio=1 ok=1\n',
                                           b'RADIO seq=1 op=1 radio=1 ok=1 active=0\n']
        self.assertEqual(client.command(1, 1)['seq'], 1)
        client.link.write.assert_called_once_with(b'radio 1 1 1 0 0 0\n')

    def test_unknown_operation_sends_nothing(self):
        client = RadioClient('COM9'); client.link = Mock()
        for op in [0, 4, 5]:
            with self.assertRaises(ValueError):
                client.command(op, 1)
        client.link.write.assert_not_called()

    def test_read_failure_still_sends_stop(self):
        client = RadioClient('COM9')
        client.command = Mock(side_effect=[{}, {'active': 1, 'configured': 1, 'actual': 433919830}, {'active': 0}])
        client.read = Mock(side_effect=DeviceCommunicationError('disconnected'))
        with self.assertRaises(DeviceCommunicationError):
            client.listen(1, 3)
        self.assertEqual(client.command.call_args_list[-1].args, (3, 1))

    def test_bad_frequency_readback_stops_without_collecting_data(self):
        client = RadioClient('COM9')
        client.command = Mock(side_effect=[{}, {'active': 1, 'configured': 1, 'actual': 800000000}, {'active': 0}])
        client.read = Mock()
        with self.assertRaises(DeviceCommunicationError):
            client.listen(1, 3)
        self.assertEqual(client.command.call_args_list[-1].args, (3, 1))
        client.read.assert_not_called()

    def test_unframed_noise_is_not_classified_as_fixed_codes(self):
        result = analysis.analyze_subghz(dict(content_mode='unframed_demodulated',
                                            events=[dict(payload='aaaa')]*10, rssi_dbm=[-92, -81]))
        self.assertEqual(result['rssi_max_dbm'], -81)
        self.assertTrue(all(f['severity'] == 'info' for f in result['findings']))
        self.assertEqual(analysis.analyze_subghz(None)['record_count'], 0)
