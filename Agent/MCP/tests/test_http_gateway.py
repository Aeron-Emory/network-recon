import os
import unittest
from unittest.mock import patch

from starlette.testclient import TestClient
from serve_http import BearerGate, build_app


class GatewayTests(unittest.TestCase):
    def test_auth_gate_blocks_missing_and_wrong_tokens(self):
        async def downstream(scope, receive, send):
            from starlette.responses import Response
            await Response('accepted')(scope, receive, send)
        client = TestClient(BearerGate(downstream, 'a' * 40))
        self.assertEqual(client.get('/mcp').status_code, 401)
        self.assertEqual(client.get('/mcp', headers={'Authorization': 'Bearer wrong'}).status_code, 401)
        self.assertEqual(client.get('/mcp', headers={'Authorization': 'Bearer ' + 'a' * 40}).status_code, 200)

    def test_authenticated_http_tool_catalog(self):
        # Isolate tool filtering from the stdio server used by other tests.
        import subprocess
        import sys
        code = '''
import os
from starlette.testclient import TestClient
from serve_http import build_app
os.environ['FREEWILI_MCP_TOKEN'] = 'a' * 40
os.environ['FREEWILI_MCP_URL'] = 'https://demo.example/mcp'
with TestClient(build_app(), base_url='https://demo.example') as c:
    assert c.post('/mcp').status_code == 401
    headers = {'Authorization': 'Bearer ' + 'a' * 40,
               'Accept': 'application/json, text/event-stream'}
    init = c.post('/mcp', headers=headers, json={'jsonrpc':'2.0','id':1,
        'method':'initialize','params':{'protocolVersion':'2025-03-26',
        'capabilities':{},'clientInfo':{'name':'test','version':'1'}}})
    assert init.status_code == 200, init.text
    r = c.post('/mcp', headers=headers, json={'jsonrpc':'2.0','id':2,'method':'tools/list'})
    assert r.status_code == 200, r.text
    names = {t['name'] for t in r.json()['result']['tools']}
    assert len(names) == 20, names
    assert 'gatt_enumerate_device' not in names
    assert 'reset_og_main_processor' not in names
    r = c.post('/mcp', headers=headers, json={'jsonrpc':'2.0','id':3,
        'method':'tools/call','params':{'name':'reset_og_main_processor','arguments':{'confirm':True}}})
    assert r.json()['result']['isError'], r.text
'''
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_fail_closed_configuration(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                build_app()
