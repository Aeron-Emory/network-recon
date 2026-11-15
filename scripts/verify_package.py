"""Verify the distributed inventory; no dependencies or hardware access."""
import hashlib
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    failures = []
    checked = 0
    for line in (root / 'SHA256SUMS.txt').read_text(encoding='utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        expected, name = line.split('  ', 1)
        target = (root / name).resolve()
        if not target.is_relative_to(root) or not target.is_file():
            failures.append(f'Missing/invalid path: {name}')
            continue
        with target.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != expected:
            failures.append(f'Checksum mismatch: {name}')
        checked += 1
    if failures:
        print('\n'.join(failures))
        return 1
    print(f'OK: {checked} distributed files match SHA-256 inventory.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
