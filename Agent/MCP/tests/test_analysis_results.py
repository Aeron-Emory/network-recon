import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import analysis
import server
from freewili import results_store
from freewili.parsers import ghostesp_gatt_service_records

GATT = '''Connected! Discovering services...
  Service: Unknown (80000080-...) handles 1-4
  Service: Unknown (80000080-...) handles 20-24
  Service: Unknown (80000080-...) handles 154-159
  Service: Unknown (80000080-...) handles 160-163
Service discovery complete. Found 4 services.
Initiating pairing...
Encryption failed: 7
Disconnected.
'''


class AnalysisRegressionTests(unittest.TestCase):
    def test_numeric_zero_management_and_subtype_are_counted(self):
        rows = [dict(frame_type=0, frame_subtype=4)] * 33 + [dict(frame_type=0, frame_subtype=8)] * 574
        rows += [dict(frame_type=2, frame_subtype=0)] * 2
        result = analysis.analyze_packets(rows)
        self.assertEqual(result['summary']['management_frames'], 607)
        self.assertEqual(result['summary']['data_frames'], 2)
        self.assertEqual(result['summary']['subtype_breakdown']['2/0'], 2)
        self.assertEqual(result['summary']['probe_request_frames'], 33)
        self.assertTrue(any(f['evidence'].get('probe_requests') == 33 for f in result['findings']))

    def test_deauth_disassoc_and_missing_types_remain_distinct(self):
        rows = [dict(frame_type=0, frame_subtype=12), dict(frame_type='0', frame_subtype='10'),
                dict(frame_type=0, frame_subtype=0), dict(frame_type=None, frame_subtype=None),
                dict(frame_type=1, frame_subtype=13)]
        summary = analysis.analyze_packets(rows)['summary']
        self.assertEqual((summary['deauth_frames'], summary['disassociation_frames']), (1, 1))
        self.assertEqual(summary['subtype_breakdown']['0/0'], 1)
        self.assertEqual(summary['management_frames'], 3)
        self.assertEqual(summary['control_frames'], 1)
        self.assertEqual(summary['other_or_unknown_frames'], 1)

    def test_hidden_markers_are_not_grouped_as_one_real_ssid(self):
        rows = [dict(ssid='', bssid='00:11:22:33:44:01', security='WPA2'),
                dict(ssid='(Hidden)', bssid='00:11:22:33:44:02', security='open'),
                dict(ssid='<hidden>', bssid='00:11:22:33:44:03', security='WPA3'),
                dict(bssid='00:11:22:33:44:04')]
        result = analysis.analyze_wifi(rows)
        self.assertEqual(sum(f['title'] == 'Hidden SSID' for f in result['findings']), 3)
        self.assertFalse(any('inconsistent security' in f['title'] for f in result['findings']))
        self.assertEqual(result['summary']['unique_ssids'], 0)

    def test_gatt_retains_services_and_pairing_error_without_inventing_values(self):
        result = ghostesp_gatt_service_records(GATT)
        self.assertEqual(len(result['services']), 4)
        self.assertTrue(all(s['uuid_is_truncated'] for s in result['services']))
        self.assertTrue(all(not s['characteristics'] for s in result['services']))
        self.assertEqual(result['services'][-1]['handle_range'], [160, 163])
        self.assertEqual(result['pairing_error'], '7')
        self.assertFalse(result['connection_failed'])
        self.assertEqual(result['status'], 'partial')

    def test_gatt_supports_brackets_full_uuid_and_zero_battery(self):
        result = ghostesp_gatt_service_records('''  Service: Battery Service (0x180F) [handles 12-15]
    Battery Level: 0%
  Service: Unknown (12345678-1234-5678-9abc-123456789abc) handles 20-25
Service discovery complete. Found 2 services.
''')
        self.assertEqual(result['services'][0]['characteristics']['Battery Level'], '0%')
        self.assertFalse(result['services'][1]['uuid_is_truncated'])
        self.assertEqual(result['status'], 'ok')

    def test_gatt_analyzer_recovers_old_saved_parser_output(self):
        result = analysis.analyze_gatt(dict(services=[], connection_failed=False, raw_text=GATT))
        self.assertEqual(result['record_count'], 4)
        self.assertEqual(result['summary']['services_with_decoded_characteristics'], 0)
        self.assertTrue(result['summary']['pairing_failed'])
        self.assertEqual(result['status'], 'partial')


class SavedResultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = patch.object(results_store, 'RESULTS_ROOT', Path(self.temp.name))
        root.start(); self.addCleanup(root.stop)

    def test_list_metadata_is_paginated_without_full_observations(self):
        for _ in range(3):
            folder = results_store.new_run_dir('capture')
            results_store.save_json(folder, 'observation.json', dict(packets=[dict(frame_type=0)] * 5000, raw_text='x'*200000))
        result = server.list_saved_runs(limit=2)
        self.assertEqual((result['total'], len(result['runs']), result['next_offset']), (3, 2, 2))
        self.assertTrue(all(row['counts']['packets'] == 5000 for row in result['runs']))
        self.assertLess(len(json.dumps(result)), 1500)
        self.assertNotIn('observation', result['runs'][0])
        self.assertEqual(len(server.list_saved_runs(offset=2)['runs']), 1)

    def test_pages_are_bounded_and_analysis_reads_the_full_file(self):
        folder = results_store.new_run_dir('capture')
        rows = [dict(frame_type=0, frame_subtype=8)] * 607 + [dict(frame_type=2, frame_subtype=0)] * 2
        results_store.save_json(folder, 'observation.json', dict(packets=rows, raw_text='x'*200000))
        reply = server.get_saved_observation(folder.name)
        self.assertEqual((len(reply['packets']), reply['packet_count']), (50, 609))
        self.assertNotIn('raw_text', reply)
        self.assertEqual(len(server.get_saved_observation(folder.name, field='packets', offset=600)['packets']), 9)
        result = server.analyze_packet_capture(run_name=folder.name)
        self.assertEqual(result['summary']['management_frames'], 607)
        self.assertEqual(result['record_count'], 609)

    def test_analysis_rejects_ambiguous_missing_and_outside_inputs(self):
        for kwargs in [{}, dict(packets=[], run_name='test'), dict(run_name='../../outside')]:
            with self.assertRaises(ValueError):
                server.analyze_packet_capture(**kwargs)
        for kwargs in [dict(limit=0), dict(limit=201), dict(offset=-1)]:
            with self.assertRaises(ValueError):
                server.list_saved_runs(**kwargs)

    def test_radio_reply_preserves_full_statistics_without_raw_dump(self):
        data = dict(events=[dict(payload='abcd')] * 3000, rssi_dbm=[-100, -80, None] * 1000,
                    raw_control_text='large dump'*10000, content_mode='unframed_demodulated')
        result = results_store.observation_page(data)
        self.assertEqual(result['event_count'], 3000)
        self.assertEqual(result['rssi_summary']['average'], -90)
        self.assertEqual(result['rssi_summary']['count'], 2000)
        self.assertEqual(result['pagination']['events']['next_offset'], 50)
        self.assertNotIn('raw_control_text', result)
        self.assertLess(len(json.dumps(result)), 6000)
