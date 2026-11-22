"""Validate V2X/CAN incident split manifests without treating fixtures as research evidence."""
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path

REQUIRED = ('record_id', 'source_sha256', 'incident_id', 'vehicle_id', 'session_id', 'split', 'label')
SPLITS = {'train', 'validation', 'test'}

def validate(path):
    path = Path(path)
    raw = path.read_bytes()
    with path.open('r', encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames is None or len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError('missing or duplicate headers')
        if set(reader.fieldnames) != set(REQUIRED):
            raise ValueError('schema mismatch')
        records = list(reader)
    if not records:
        raise ValueError('empty manifest')
    seen = set()
    groups = defaultdict(set)
    counts = defaultdict(int)
    for row in records:
        if None in row or any(type(v) is not str or not v or v.strip() != v for v in row.values()):
            raise ValueError('empty, padded or surplus field')
        if row['split'] not in SPLITS or row['label'] not in {'0', '1'}:
            raise ValueError('invalid split or binary label')
        digest = row['source_sha256']
        if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('invalid source sha256')
        key = (digest, row['record_id'])
        if key in seen:
            raise ValueError('duplicate source record')
        seen.add(key)
        for kind in ('incident_id', 'vehicle_id', 'session_id'):
            groups[(kind, digest, row[kind])].add(row['split'])
        counts[(row['split'], row['label'])] += 1
    leakage = [(k, sorted(s)) for k, s in groups.items() if len(s) > 1]
    if leakage:
        raise ValueError('cross-split incident/vehicle/session leakage: ' + repr(leakage[:3]))
    return {'manifest_sha256': hashlib.sha256(raw).hexdigest(),
            'records': len(records),
            'counts': {f'{s}:{l}': counts[(s,l)] for s in sorted(SPLITS) for l in ('0','1')},
            'group_policy': 'source-sha256 scoped incident, vehicle and session disjointness',
            'limitations': 'No independent label authenticity, temporal embargo, or dataset origin verification'}

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('manifest')
    args = parser.parse_args()
    print(json.dumps(validate(args.manifest), sort_keys=True, indent=2))

if __name__ == '__main__':
    main()
