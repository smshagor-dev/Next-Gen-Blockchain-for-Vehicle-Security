"""Strict label-free classic SocketCAN candump ingestion; never authorizes actuation."""
import argparse
import hashlib
import json
import re
from pathlib import Path

LINE = re.compile(r'^\((\d+\.\d{1,9})\) ([A-Za-z0-9_.-]+) ([0-9A-Fa-f]{3,8})#([0-9A-Fa-f]{0,16})$')


def parse_trace(path, *, max_bytes=100_000_000):
    source = Path(path)
    if not source.is_file() or source.is_symlink():
        raise ValueError('source must be a regular, non-symlink file')
    if source.stat().st_size > max_bytes:
        raise ValueError('source exceeds configured byte limit')
    digest = hashlib.sha256()
    rows = []
    last_time = None
    with source.open('rb') as stream:
        for line_no, raw in enumerate(stream, 1):
            digest.update(raw)
            if len(raw) > 4096:
                raise ValueError(f'line {line_no}: oversized record')
            try:
                line = raw.decode('ascii').rstrip('\r\n')
            except UnicodeDecodeError as exc:
                raise ValueError(f'line {line_no}: non-ASCII input') from exc
            match = LINE.fullmatch(line)
            if not match:
                raise ValueError(f'line {line_no}: invalid classic CAN candump record')
            seconds, interface, identifier, payload = match.groups()
            timestamp_ns = int(seconds.split('.')[0]) * 1_000_000_000 + int(seconds.split('.')[1].ljust(9, '0'))
            if last_time is not None and timestamp_ns < last_time:
                raise ValueError(f'line {line_no}: decreasing timestamps')
            last_time = timestamp_ns
            can_id = int(identifier, 16)
            if can_id > 0x1FFFFFFF:
                raise ValueError(f'line {line_no}: CAN identifier out of range')
            if len(identifier) == 3 and can_id > 0x7FF:
                raise ValueError(f'line {line_no}: invalid standard CAN identifier')
            if len(payload) % 2:
                raise ValueError(f'line {line_no}: odd payload hex length')
            rows.append({'timestamp_ns': timestamp_ns, 'interface': interface,
                         'can_id': can_id, 'extended': len(identifier) > 3,
                         'data_hex': payload.lower(), 'dlc': len(payload) // 2})
    return {'source_sha256': digest.hexdigest(), 'source_bytes': source.stat().st_size,
            'format': 'socketcan-candump-classic', 'label_status': 'unverified_unlabelled',
            'clock_status': 'source_reported_unverified', 'records': rows}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('source')
    parser.add_argument('--max-bytes', type=int, default=100_000_000)
    args = parser.parse_args()
    if args.max_bytes < 0:
        parser.error('--max-bytes must be nonnegative')
    print(json.dumps(parse_trace(args.source, max_bytes=args.max_bytes), sort_keys=True))


if __name__ == '__main__':
    main()
