"""Version-locked UART-rate patch for the verified GhostESP v2.2.2 C6 image.

Changes only the baud constants in serial_manager_init/reacquire_uart from
115200 to 921600. This is a binary patch, not a source rebuild. No addresses,
instruction lengths, GPIOs, radio logic, partition table or bootloader change.
Both RISC-V instruction pairs are checked byte-for-byte before replacement.
"""
from pathlib import Path
import hashlib
import json
import struct

EXPECTED_SHA = 'df56e655c2ac4a06e88b8eb335bdd534d288801dce9457eeb31a0ee87f577295'
ADDRESSES = [0x420AFB94, 0x420AFE36]
OLD = bytes.fromhex('f16793870720')  # c.lui a5,0x1c; addi a5,a5,0x200
NEW = bytes.fromhex('b7170e000100')  # lui a5,0xe1; c.nop => 0xe1000=921600


def patch(data):
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA:
        raise ValueError('Input is not the pinned, verified release application.')
    if data[0] != 0xE9 or data[23] != 1 or int.from_bytes(data[12:14], 'little') != 13:
        raise ValueError('Expected unsigned C6 image with appended SHA-256.')
    result = bytearray(data)
    cursor, checksum = 24, 0xEF
    changes = []
    for _ in range(data[1]):
        address, length = struct.unpack_from('<II', data, cursor)
        start = cursor + 8
        for target in ADDRESSES:
            if address <= target and target + len(OLD) <= address + length:
                offset = start + target - address
                if data[offset:offset + len(OLD)] != OLD:
                    raise ValueError('Expected baud-load instructions did not match.')
                result[offset:offset + len(OLD)] = NEW
                changes.append(dict(address=hex(target), file_offset=offset,
                                    before=OLD.hex(), after=NEW.hex()))
        cursor = start + length
    if len(changes) != 2:
        raise ValueError('Both UART initializer locations must be found exactly once.')
    checksum_offset = (cursor // 16 + 1) * 16 - 1
    if len(data) != checksum_offset + 33:
        raise ValueError('Unexpected image footer layout.')
    original_checksum = 0xEF
    cursor = 24
    for _ in range(data[1]):
        _, length = struct.unpack_from('<II', data, cursor)
        for v in data[cursor + 8:cursor + 8 + length]:
            original_checksum ^= v
        for v in result[cursor + 8:cursor + 8 + length]:
            checksum ^= v
        cursor += 8 + length
    if original_checksum != data[checksum_offset] or hashlib.sha256(data[:checksum_offset + 1]).digest() != data[-32:]:
        raise ValueError('Original image checksum/digest did not validate.')
    result[checksum_offset] = checksum
    result[-32:] = hashlib.sha256(result[:checksum_offset + 1]).digest()
    return bytes(result), dict(original_sha256=EXPECTED_SHA,
                               patched_sha256=hashlib.sha256(result).hexdigest(),
                               baud_before=115200, baud_after=921600,
                               instructions=changes, checksum_offset=checksum_offset,
                               source_rebuild=False)


if __name__ == '__main__':
    raise SystemExit('This is a patch helper. Run patch_ghostesp_capture_io.py --help for the final 460800-baud image.')
