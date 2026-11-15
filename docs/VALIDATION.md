# Package validation

Checked on Windows with Python 3.12 on 2026-11-15. No hardware was reset/flashed/scanned, no live tunnel was contacted and no Bedrock requests were made while creating this package.

- Installed both application requirement sets into a new temporary virtual environment successfully. The interactive CLI and MCP direct dependencies are pinned to the tested versions; the subsequently added AgentCore deployment has its own dependency ranges and was not covered by this install check.
- Copied the application directories to a separate temporary location and ran all **38 MCP offline tests** successfully. Tests include stdio protocol checks, HTTP authentication failures/success, remote tool discovery and refusal of the excluded reset tool.
- Imported the relocated Strands agent and checked remote transport configuration, authorization-header construction, explicit model/region selection, and rejection of insecure/credential-bearing endpoint URLs with external calls mocked.
- Ran the parameterized Bottlenose patch CLI from a separate location against the pinned upstream release application. Its output matched the bundled adjusted firmware byte-for-byte.
- Matched all five supplied firmware SHA-256 digests to the final demonstrated images.
- Configured and built OG `bnbridge_main` and `bl_display` successfully using the portable CMake inputs, the pinned BSP/SDK and Arm GNU 13.3.Rel1. All generated files remained in a temporary directory outside the package. The original verified firmware images remain the distributed binaries.
- Parsed packaged Python and PowerShell source, checked local Markdown links, and checked for virtual environments/caches/results/build directories and common credential patterns. No private device backups or live ngrok hostname are included.

The root `SHA256SUMS.txt` records the final distributed files. Run `python scripts/verify_package.py` to check them after copying or extracting.

## Not established by these checks

Live AWS/Bedrock-to-ngrok-to-USB operation still needs an end-to-end test using your workshop identity, selected model and private token. The included CLI can run in Workshop Studio. An AgentCore Runtime entrypoint is now supplied in `Agent/network-analyst-pentester/agentcore-deploy/`, but the earlier 38-test suite does not validate it. Its Python syntax and dependency metadata were checked during cleanup; its dependencies, runtime behavior and live deployment remain untested. Hardware reception can vary with RF conditions, and CC1101 reception still lacks a known-transmitter check. The exact customized ESP-IDF environment used for the upstream GhostESP release was not obtained; see BUILDING.md for source-rebuild limitations.

## Agent-folder cleanup

Removed the duplicate deployment ZIP and the deployment `requirements.txt`;
`agentcore-deploy/pyproject.toml` is its dependency source. Kept both agent
entrypoints and their distinct skills. Corrected gateway paths, discovery
traffic descriptions and links to the new runtime. Refreshed the complete
package inventory after checking syntax, metadata and local Markdown links.
