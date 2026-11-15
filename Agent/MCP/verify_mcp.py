"""Opt-in live validation through the actual MCP stdio client/server.

Runs bounded Wi-Fi/BLE discovery and passive capture over OG USB.
No firmware writes, reset, network joining or BLE connections.
"""
import asyncio
from datetime import timedelta
import json
from pathlib import Path
import sys
import time

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from freewili.results_store import new_run_dir


async def main():
    root = Path(__file__).resolve().parent
    out = new_run_dir('mcp-live-validation')
    results = {}
    config = StdioServerParameters(command=sys.executable, args=[str(root / 'server.py')], cwd=root)
    async with stdio_client(config) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=110)) as client:
            await client.initialize()
            tools = await client.list_tools()
            results['tools'] = [t.name for t in tools.tools]
            async def call(name, arguments):
                start = time.monotonic()
                response = await client.call_tool(name, arguments)
                if response.isError:
                    raise RuntimeError(str(response.content))
                data = response.structuredContent
                if data is None:
                    data = json.loads(next(c.text for c in response.content if c.type == 'text'))
                results[name] = dict(elapsed_s=round(time.monotonic()-start, 2), data=data)
                (out / 'report.json').write_text(json.dumps(results, indent=2))
                print(json.dumps(dict(tool=name, elapsed_s=results[name]['elapsed_s'], status=data.get('status'),
                                      records=data.get('record_count', len(data.get('records', []))), packets=data.get('packet_count', len(data.get('packets', []))),
                                      saved_to=data.get('saved_to'))), flush=True)
                if data.get('status') in ('error', 'refused'):
                    raise RuntimeError(f'{name}: {data}')
                return data
            await call('identify_og', dict(port='COM8'))
            before = await call('get_bridge_status', dict(port='COM9'))
            results['bridge_before'] = before
            wifi = await call('scan_wifi_via_og', dict(seconds=4, port='COM8'))
            ble = await call('scan_ble_via_og', dict(seconds=4, port='COM8'))
            capture = await call('capture_wifi_packets', dict(channel=6, seconds=15, port='COM8'))
            after = await call('get_bridge_status', dict(port='COM9'))
            results['bridge_delta'] = {k: after['counters'][k] - before['counters'][k]
                                       for k in ['rx', 'usb', 'tx', 'drops', 'errors', 'disconnected']}
            # Verify scans still work after monitor stop, through the same cable.
            wifi_after = await call('scan_wifi_via_ghostesp', dict(seconds=4, port='COM8'))
            ble_after = await call('scan_ble_via_ghostesp', dict(seconds=4, port='COM8'))
            radio = await call('subghz_radio_status', dict(radio_index=1, port='COM8'))
            results['passed'] = bool(wifi['records'] and ble['records'] and capture['packets']
                and capture['monitor_stopped_cleanly'] and capture['capture_stream_intact']
                and wifi_after['records'] and ble_after['records']
                and radio.get('status') == 'ok'
                and all(results['bridge_delta'][k] == 0 for k in ['drops', 'errors']))
    (out / 'report.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(dict(passed=results['passed'], bridge_delta=results['bridge_delta'], output=str(out))), flush=True)
    return 0 if results['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))
