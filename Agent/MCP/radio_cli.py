"""Standalone CC1101 status/receive helper; uses the same client as MCP."""
import argparse
import json
from freewili.radio_client import RadioClient, find_radio_port
from freewili.transport import PortLock
from freewili.results_store import new_run_dir, save_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['status', 'listen'])
    parser.add_argument('--radio', type=int, choices=[1, 2], required=True)
    parser.add_argument('--seconds', type=int, choices=range(1, 31), default=8)
    parser.add_argument('--frequency', type=float, help='MHz; default 433.92 for radio 1, 915 for radio 2')
    parser.add_argument('--modulation', choices=['ook', '2fsk', 'gfsk'], default='ook')
    parser.add_argument('--port', default='COM8', help='MAIN port (one board) or explicit DISPLAY port')
    args = parser.parse_args()
    try:
        info = find_radio_port(args.port)
        with PortLock(info.port), RadioClient(info.port) as client:
            result = client.status(args.radio) if args.mode == 'status' else client.listen(
                args.radio, args.seconds, args.frequency, args.modulation)
            raw = ''.join(e.text for e in client.link.transcript if e.direction == 'rx')
        out = new_run_dir(f'radio-cli-{args.mode}')
        save_json(out, 'observation.json', result)
        (out / 'control-wire.txt').write_text(raw)
        result.pop('events', None)
        result.pop('rssi_dbm', None)
        result['saved_to'] = str(out)
        print(json.dumps(result, indent=2))
        return 0 if result['status'] == 'ok' else 2
    except (ValueError, RuntimeError) as exc:
        print(json.dumps(dict(status='error', reason=str(exc))))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
