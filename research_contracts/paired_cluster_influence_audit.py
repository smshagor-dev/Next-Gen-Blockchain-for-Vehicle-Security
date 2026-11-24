"""Non-actuating, paired scenario-cluster sensitivity audit.

Input CSV columns: scenario_id,incident_id,truth,baseline,proposed. All labels 0/1.
Each incident must occur exactly once. No synthetic observations are generated.
"""
import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path

FIELDS = ('scenario_id', 'incident_id', 'truth', 'baseline', 'proposed')


def load(path):
    raw = Path(path).read_bytes()
    rows = []
    seen = set()
    with Path(path).open(newline='', encoding='utf-8-sig') as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or any(f not in reader.fieldnames for f in FIELDS):
            raise ValueError('required columns missing')
        for line, row in enumerate(reader, 2):
            if any(row.get(f) is None or not str(row[f]).strip() for f in FIELDS):
                raise ValueError(f'missing value at line {line}')
            key = (row['scenario_id'], row['incident_id'])
            if key in seen:
                raise ValueError(f'duplicate incident {key}')
            seen.add(key)
            try:
                labels = tuple(int(row[f]) for f in FIELDS[2:])
            except ValueError as exc:
                raise ValueError(f'nonbinary label at line {line}') from exc
            if any(x not in (0, 1) or str(x) != row[f].strip() for x, f in zip(labels, FIELDS[2:])):
                raise ValueError(f'nonbinary label at line {line}')
            rows.append((key[0], key[1], *labels))
    if not rows:
        raise ValueError('empty incident table')
    return rows, hashlib.sha256(raw).hexdigest()


def balanced_accuracy(rows, column):
    scores = []
    for truth in (0, 1):
        subset = [r for r in rows if r[2] == truth]
        if not subset:
            raise ValueError('both truth classes required')
        scores.append(sum(r[column] == truth for r in subset) / len(subset))
    return sum(scores) / 2


def audit(rows, digest):
    clusters = defaultdict(list)
    for row in rows:
        clusters[row[0]].append(row)
    if len(clusters) < 3:
        raise ValueError('at least three independent scenarios required')
    base = balanced_accuracy(rows, 3)
    proposed = balanced_accuracy(rows, 4)
    full = proposed - base
    loo = []
    for scenario in sorted(clusters):
        remaining = [r for r in rows if r[0] != scenario]
        try:
            effect = balanced_accuracy(remaining, 4) - balanced_accuracy(remaining, 3)
        except ValueError:
            loo.append({'omitted_scenario': scenario, 'effect': None, 'reason': 'missing truth class'})
        else:
            loo.append({'omitted_scenario': scenario, 'effect': effect, 'reason': None})
    valid = [r['effect'] for r in loo if r['effect'] is not None]
    return {'sha256': digest, 'incidents': len(rows), 'scenarios': len(clusters),
            'baseline_balanced_accuracy': base, 'proposed_balanced_accuracy': proposed,
            'paired_effect': full, 'leave_one_scenario_out': loo,
            'effect_sign_stable': len(valid) == len(loo) and all((x > 0) == (full > 0) and (x < 0) == (full < 0) for x in valid),
            'interpretation': 'descriptive sensitivity only; not significance, finality, or physical safety evidence'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('csv_path')
    parser.add_argument('--output', help='write JSON report')
    args = parser.parse_args()
    rows, digest = load(args.csv_path)
    report = audit(rows, digest)
    serialized = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output:
        Path(args.output).write_text(serialized, encoding='utf-8')
    else:
        print(serialized, end='')

if __name__ == '__main__':
    main()
