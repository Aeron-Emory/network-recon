"""Opt-in live radio/PCAP coexistence check. Uses receive mode only."""
import asyncio
from datetime import timedelta
import json
from pathlib import Path
import sys
import threading
import time
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from freewili.radio_client import RadioClient, find_radio_port
from freewili.transport import PortLock
from freewili.results_store import new_run_dir


async def main():
    root = Path(__file__).resolve().parent
    output = new_run_dir('radio-coexistence')
    results = {}
    ready = threading.Event()

    def dual_receive():
        info = find_radio_port('COM8')
        with PortLock(info.port), RadioClient(info.port) as radio:
            baseline = [radio.command(1, i) for i in (1, 2)]
            active = []
            stop = []
            try:
                for i, hz in [(1, 433920000), (2, 915000000)]:
                    active.append(radio.command(2, i, hz, 30000, 0))
                ready.set()
                radio.read(30)
            finally:
                for i in (1, 2):
                    stop.append(radio.command(3, i))
            data = dict(active=active, stopped=stop, events=radio.events,
                        counters=[{k: stop[i][k] - baseline[i][k]
                                   for k in ['samples', 'bytes', 'overflows', 'io_errors']} for i in range(2)])
            (output / 'dual-radio-control.txt').write_text(''.join(e.text for e in radio.link.transcript if e.direction == 'rx'))
            return data

    config = StdioServerParameters(command=sys.executable, args=[str(root / 'server.py')], cwd=root)
    async with stdio_client(config) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=110)) as client:
            await client.initialize()
            async def call(name, arguments, key=None):
                start = time.monotonic()
                reply = await client.call_tool(name, arguments)
                if reply.isError:
                    raise RuntimeError(str(reply.content))
                data = reply.structuredContent
                if data is None:
                    data = json.loads(next(c.text for c in reply.content if c.type == 'text'))
                results[key or name] = dict(elapsed_s=round(time.monotonic()-start, 2), data=data)
                (output / 'report.json').write_text(json.dumps(results, indent=2))
                print(json.dumps(dict(tool=name, status=data.get('status'),
                                      records=data.get('record_count', len(data.get('records', []))), packets=data.get('packet_count', len(data.get('packets', []))),
                                      saved_to=data.get('saved_to'))), flush=True)
                if data.get('status') in ('error', 'refused', 'unavailable'):
                    raise RuntimeError(str(data))
                return data
            await call('identify_og', dict(port='COM8'))
            await call('subghz_radio_status', dict(radio_index=1, port='COM8'), 'radio1')
            await call('subghz_radio_status', dict(radio_index=2, port='COM8'), 'radio2')
            await call('subghz_listen', dict(radio_index=1, seconds=3, port='COM8'), 'mcp_rx433')
            await call('subghz_listen', dict(radio_index=2, seconds=3, port='COM8'), 'mcp_rx915')
            before = await call('get_bridge_status', dict(port='COM9'), 'bridge_before')
            task = asyncio.create_task(asyncio.to_thread(dual_receive))
            try:
                for _ in range(200):
                    if task.done():
                        task.result()
                    if ready.is_set():
                        break
                    await asyncio.sleep(.05)
                if not ready.is_set():
                    raise RuntimeError('Dual receiver did not start.')
                capture = await call('capture_wifi_packets', dict(channel=6, seconds=8, port='COM8'))
            finally:
                dual = await task
                results['dual_receive'] = dual
            after = await call('get_bridge_status', dict(port='COM9'), 'bridge_after')
            delta = {k: after['counters'][k] - before['counters'][k]
                     for k in ['rx', 'usb', 'drops', 'errors', 'disconnected', 'control_drops']}
            results['bridge_delta'] = delta
            wifi = await call('scan_wifi_via_og', dict(seconds=4, port='COM8'))
            ble = await call('scan_ble_via_og', dict(seconds=4, port='COM8'))
            results['passed'] = bool(capture['packets'] and capture['capture_stream_intact']
                and capture['monitor_stopped_cleanly'] and wifi['records'] and ble['records']
                and all(d['samples'] > 0 and d['overflows'] == 0 and d['io_errors'] == 0 for d in dual['counters'])
                and all(s['active'] == 0 for s in dual['stopped'])
                and delta['rx'] == delta['usb'] and not any(delta[k] for k in ['drops', 'errors', 'control_drops']))
    (output / 'report.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(dict(passed=results['passed'], bridge_delta=results['bridge_delta'],
                          counters=dual['counters'], output=str(output))), flush=True)
    return 0 if results['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))
