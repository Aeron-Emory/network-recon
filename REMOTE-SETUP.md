# AWS agent with local USB hardware

AWS runs the Strands agent and calls Bedrock. Your Windows PC runs the MCP server and keeps exclusive access to the USB hardware. No USB forwarding or firmware changes are needed.

## Windows gateway

From `Agent/MCP`, create a virtual environment and install requirements. Keep existing local stdio clients disconnected while using the remote gateway. Port locks prevent conflicting hardware access, but this is a single-operator demo, not a multi-user service.

Use a trusted HTTPS tunnel (for example ngrok) forwarding to `http://127.0.0.1:8765`. For ngrok, run `ngrok http 8765` in another terminal after configuring your ngrok account. Use its HTTPS URL below. Do not open a router port. Tunnel setup/account authorization is separate from the application bearer token.

In PowerShell:

```powershell
# From the bundle root:
cd Agent/MCP
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:FREEWILI_MCP_TOKEN = .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
$env:FREEWILI_MCP_URL = "https://YOUR-TUNNEL-HOST/mcp"
# Optional: copy the private token so you can paste it into the AWS terminal prompt.
Set-Clipboard -Value $env:FREEWILI_MCP_TOKEN
.\.venv\Scripts\python.exe serve_http.py
```

Generate the token in the same terminal used to run the server. Securely transfer its value to your AWS environment; never commit it or paste it into prompts/logs. The endpoint requires `Authorization: Bearer <token>` for every request. This is a pre-shared-token demo, not an OAuth login service. Restart with a new token to revoke the old one. Close the tunnel and server when done. Public TLS terminates at your tunnel provider; the local listener binds only to loopback. DNS rebinding checks remain enabled for the configured host.

Paste the copied token only at the AWS terminal's hidden `MCP token:` input below, not into an AI chat. Clear the clipboard afterward. The generated token is separate from your ngrok account authtoken. If you restart ngrok and its hostname changes, update the URL on both machines and restart the gateway.

Connect the hardware before the first scan. A normal unauthenticated browser request to `/mcp` returns HTTP 401; that is expected. Stop the gateway with Ctrl+C in its terminal and stop the tunnel separately.

The remote profile exposes 20 tools: active GATT and processor reset are omitted. Local `python server.py` still exposes the existing 22-tool stdio interface. Scans may emit standard discovery traffic; capture and sub-GHz reception are passive. Authorized testing only.

## AWS Workshop Studio

Copy `Agent/network-analyst-pentester` (including skills, excluding `.venv`) to Workshop Studio. Install its requirements in a Linux virtual environment. It does not need the hardware MCP source or pyserial in AWS.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export FREEWILI_MCP_URL=https://YOUR-TUNNEL-HOST/mcp
read -rsp 'MCP token: ' FREEWILI_MCP_TOKEN; echo
export FREEWILI_MCP_TOKEN
export AWS_REGION=YOUR_WORKSHOP_REGION
export BEDROCK_MODEL_ID=YOUR_ENABLED_MODEL_OR_INFERENCE_PROFILE_ID
python agent.py
```

Use the workshop's provisioned AWS identity and its enabled model/region. Model choice is explicit; this package makes no claim about which models event credits cover. Do not put AWS credentials on the Windows gateway. Observation previews and requested analysis results travel to AWS/Bedrock; full saved runs stay on the PC unless requested through tools.

First ask the agent to identify hardware, then request an authorized Wi-Fi scan. A failed HTTP authentication or tool listing is a connectivity problem, not evidence of radio failure.

## AgentCore

The managed-runtime entrypoint is supplied in
[Agent/network-analyst-pentester/agentcore-deploy/](Agent/network-analyst-pentester/agentcore-deploy/README.md).
Follow that folder's guide for the Workshop Studio/AgentCore flow. Its
`pyproject.toml` is the deployment dependency source. The adjacent `agent.py`
remains the interactive CLI and supports both remote HTTP and local stdio.

The AgentCore entrypoint has not been live-tested or deployed as part of this
package cleanup. It still needs your workshop identity, configured model,
private MCP token, HTTPS egress and an end-to-end test against your gateway.
