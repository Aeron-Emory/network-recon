"""Standalone Free-WILi hardware client used by the MCP/ server.

This package is fully independent of the parent "FreeWlli workshop" project.
It does not import, execute, or depend at runtime on wireless_tests.py,
ghostesp_tests.py, or any file outside MCP/. It was written by reading the
parent project's documentation and test results purely as reference material
describing the OG-to-Bottlenose hardware architecture and the GhostESP
command protocol; none of that code is reused here.

Everything that touches the serial port lives in this package. The MCP
server (server.py) only calls into this package; it never opens a serial
port itself.
"""
