"""Single-operator HTTP gateway. Terminate public TLS at an authenticated tunnel."""
import hmac
import os
from urllib.parse import urlparse

import uvicorn
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import Response

from server import mcp


class BearerGate:
    def __init__(self, app, token):
        self.app, self.token = app, token

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'http':
            values = [v for k, v in scope['headers'] if k.lower() == b'authorization']
            expected = ('Bearer ' + self.token).encode()
            if len(values) != 1 or not hmac.compare_digest(values[0], expected):
                await Response(status_code=401, headers={'WWW-Authenticate': 'Bearer'})(scope, receive, send)
                return
        await self.app(scope, receive, send)


def build_app():
    token = os.environ.get('FREEWILI_MCP_TOKEN', '')
    if len(token) < 32:
        raise ValueError('Set FREEWILI_MCP_TOKEN to a randomly generated secret of at least 32 characters')
    url = urlparse(os.environ.get('FREEWILI_MCP_URL', ''))
    if (url.scheme != 'https' or not url.hostname or url.username or url.password
            or url.path != '/mcp' or url.query or url.fragment):
        raise ValueError('Set FREEWILI_MCP_URL to https://your-tunnel-host/mcp')
    # Cloud profile deliberately excludes device reset and active BLE connections.
    for name in ('gatt_enumerate_device', 'reset_og_main_processor'):
        mcp.remove_tool(name)
    mcp.settings.stateless_http = True
    mcp.settings.json_response = True
    mcp.settings.transport_security = TransportSecuritySettings(
        allowed_hosts=[url.netloc, '127.0.0.1:8765', 'localhost:8765'],
        allowed_origins=[f'https://{url.netloc}'],
    )
    return BearerGate(mcp.streamable_http_app(), token)


if __name__ == '__main__':
    uvicorn.run(build_app(), host='127.0.0.1', port=8765, access_log=False)
