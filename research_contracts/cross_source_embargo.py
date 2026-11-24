"""Preflight cross-file identity leakage and temporal embargo for frozen V2X splits.

Global identities and timestamps must be independently resolved by the operator.
"""
import csv
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path

FIELDS = ('record_id', 'source_sha256', 'global_incident_id', 'global_vehicle_id',
          'global_session_id', 'split', 'event_time_s')
SPLITS = frozenset(('train', 'validation', 'test'))


def validate(path, embargo_seconds=0.0):
    if isinstance(embargo_seconds, bool) or not isinstance(embargo_seconds, (int, float)):
        raise ValueError('embargo must be a nonnegative finite number')
    embargo = float(embargo_seconds)
    if not math.isfinite(embargo) or embargo < 0:
        raise ValueError('embargo must be a nonnegative finite number')
    path = Path(path)
    raw = path.read_bytes()
    with path.open('r', encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or len(reader.fieldnames) != len(set(reader.fieldnames)) or set(reader.fieldnames) != set(FIELDS):
            raise ValueError('invalid or duplicate schema fields')
        rows = list(reader)
    if not rows:
        raise ValueError('empty split manifest')
    identities = defaultdict(set)
    times = defaultdict(list)
    seen = set()
    for row in rows:
        if None in row or any(not isinstance(v, str) or not v or v != v.strip() for v in row.values()):
            raise ValueError('missing, padded, or extra values')
        if row['split'] not in SPLITS:
            raise ValueError('invalid split')
        digest = row['source_sha256']
        if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('invalid source digest')
        key = (digest, row['record_id'])
        if key in seen:
            raise ValueError('duplicate source record')
        seen.add(key)
        for field in ('global_incident_id', 'global_vehicle_id', 'global_session_id'):
            identities[(field, row[field])].add(row['split'])
        try:
            timestamp = float(row['event_time_s'])
        except ValueError as exc:
            raise ValueError('invalid event timestamp') from exc
        if not math.isfinite(timestamp):
            raise ValueError('nonfinite event timestamp')
        times[row['split']].append(timestamp)
    overlaps = [key for key, splits in identities.items() if len(splits) > 1]
    if overlaps:
        raise ValueError('cross-source global identity leakage: ' + repr(sorted(overlaps)[:3]))
    active = [s for s in ('train', 'validation', 'test') if times[s]]
    for left, right in zip(active, active[1:]):
        if min(times[right]) - max(times[left]) <= embargo:
            raise ValueError('chronological split order or embargo violation')
    return {'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'records': len(rows),
            'embargo_seconds': embargo, 'split_counts': {s: len(times[s]) for s in sorted(SPLITS)},
            'limitations': 'Global identity linkage and timestamps are operator supplied; no provenance or label authenticity is established'}


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('manifest')
    parser.add_argument('--embargo-seconds', type=float, default=0.0)
    args = parser.parse_args()
    print(json.dumps(validate(args.manifest, args.embargo_seconds), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
