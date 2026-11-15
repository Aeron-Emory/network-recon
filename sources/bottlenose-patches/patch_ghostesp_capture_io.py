"""Bounded I/O correction for the pinned GhostESP C6 application.

Use 460800 UART baud to stay below the measured OG receive-overrun rate.
Give USB-JTAG capture writes 10 RTOS ticks rather than dropping their tail
immediately when its 512-byte transmit ring fills. Version-specific binary
patch; the base release SHA and all affected instruction bytes are checked.
"""
from pathlib import Path
import hashlib
import json
import struct

from patch_ghostesp_uart import patch as base_patch


def patch(data):
    base, base_report = base_patch(data)
    result = bytearray(base)
    changes = []
    for record in base_report['instructions']:
        offset = record['file_offset']
        # LUI a5,0xe1 followed by C.SRLI a5,1 -> 921600 / 2.
        result[offset:offset + 6] = bytes.fromhex('b7170e008583')
        changes.append(dict(address=record['address'], file_offset=offset,
                            before=data[offset:offset + 6].hex(),
                            after=result[offset:offset + 6].hex()))
    cursor = 24
    usb_sites = []
    for _ in range(data[1]):
        address, length = struct.unpack_from('<II', data, cursor)
        target = 0x420AF986  # serial_manager_write_bytes, USB timeout argument a2
        if address <= target < address + length:
            offset = cursor + 8 + target - address
            if data[offset:offset + 2] != b'\x01\x46':  # C.LI a2,0
                raise ValueError('Expected USB timeout instruction did not match.')
            result[offset:offset + 2] = b'\x29\x46'  # C.LI a2,10 ticks
            usb_sites.append(offset)
            changes.append(dict(address=hex(target), file_offset=offset,
                                before='0146', after='2946'))
        cursor += 8 + length
    if len(usb_sites) != 1:
        raise ValueError('USB timeout location was not uniquely identified.')
    checksum = 0xEF
    cursor = 24
    for _ in range(data[1]):
        _, length = struct.unpack_from('<II', data, cursor)
        for value in result[cursor + 8:cursor + 8 + length]:
            checksum ^= value
        cursor += 8 + length
    result[base_report['checksum_offset']] = checksum
    result[-32:] = hashlib.sha256(result[:-32]).digest()
    return bytes(result), dict(original_sha256=base_report['original_sha256'],
                               patched_sha256=hashlib.sha256(result).hexdigest(),
                               baud_after=460800, usb_capture_write_timeout_ticks=10,
                               instructions=changes, checksum_offset=base_report['checksum_offset'],
                               source_rebuild=False)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True, help='Unmodified pinned C6 release application')
    parser.add_argument('--output', type=Path, required=True, help='New output file; existing files are refused')
    args = parser.parse_args()
    report_path = args.output.with_suffix('.patch.json')
    if args.output.exists() or report_path.exists():
        parser.error('Output or report already exists; choose a new destination')
    result, report = patch(args.input.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(result)
    report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))
