"""Strict independent-truth join for simulation-only replay; no inferred labels."""
import argparse, csv, hashlib, io, json
from pathlib import Path

MAX_BYTES = 16 * 1024 * 1024
FIELDS = ['incident_id', 'cluster_id', 'should_alert']

def strict_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError('duplicate JSON key')
        obj[key] = value
    return obj

def join(truth_raw, replay_raw, expected_input_sha256):
    if len(truth_raw) > MAX_BYTES or len(replay_raw) > MAX_BYTES:
        raise ValueError('oversized input')
    reader = csv.DictReader(io.StringIO(truth_raw.decode('utf-8-sig'), newline=''), strict=True)
    if reader.fieldnames != FIELDS:
        raise ValueError('invalid truth schema')
    truth = {}
    for row in reader:
        if None in row or any(v is None for v in row.values()):
            raise ValueError('ragged truth row')
        incident, cluster, label = (row[k] for k in FIELDS)
        if not incident or not cluster or len(incident) > 128 or len(cluster) > 128 or label not in ('0', '1') or incident in truth:
            raise ValueError('invalid or duplicate truth incident')
        truth[incident] = (cluster, int(label))
    if not truth:
        raise ValueError('empty truth')
    replay = json.loads(replay_raw, object_pairs_hook=strict_object,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    if type(replay) is not dict or type(replay.get('events')) is not list:
        raise ValueError('invalid replay')
    if len(expected_input_sha256) != 64 or any(c not in '0123456789abcdef' for c in expected_input_sha256) or replay.get('input_sha256') != expected_input_sha256:
        raise ValueError('input digest mismatch')
    if type(replay.get('count')) is not int or replay['count'] != len(replay['events']):
        raise ValueError('replay count mismatch')
    allowed = {'simulated_alert', 'blocked_local_emergency', 'blocked_actuation_or_reset', 'blocked_authentication', 'blocked_replay', 'blocked_evidence'}
    decisions = {}
    for event in replay['events']:
        if type(event) is not dict or set(event) != {'incident_id', 'verdict'}:
            raise ValueError('invalid replay event')
        incident, verdict = event['incident_id'], event['verdict']
        if type(incident) is not str or incident not in truth or incident in decisions or verdict not in allowed:
            raise ValueError('unexpected, duplicate or invalid replay event')
        decisions[incident] = int(verdict == 'simulated_alert')
    if type(replay.get('simulated_alerts')) is not int or replay['simulated_alerts'] != sum(decisions.values()):
        raise ValueError('alert count mismatch')
    counts = {'tp': 0, 'tn': 0, 'fp': 0, 'fn': 0}
    incidents = []
    for incident, (cluster, actual) in sorted(truth.items()):
        predicted = decisions.get(incident, 0)
        counts[('t' if predicted == actual else 'f') + ('p' if predicted else 'n')] += 1
        incidents.append({'incident_id': incident, 'cluster_id': cluster, 'truth': actual, 'predicted': predicted, 'observed': incident in decisions})
    return {'truth_sha256': hashlib.sha256(truth_raw).hexdigest(),
            'replay_sha256': hashlib.sha256(replay_raw).hexdigest(),
            'replay_input_sha256': expected_input_sha256, 'counts': counts,
            'missing_decisions': len(truth) - len(decisions), 'incidents': incidents,
            'evidence_class': 'requires_independently_verified_truth_and_capture'}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--truth', type=Path, required=True)
    parser.add_argument('--replay', type=Path, required=True)
    parser.add_argument('--expected-input-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    for path in (args.truth, args.replay):
        if path.stat().st_size > MAX_BYTES:
            parser.error('input exceeds limit')
    result = join(args.truth.read_bytes(), args.replay.read_bytes(), args.expected_input_sha256)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n', encoding='utf-8')

if __name__ == '__main__':
    main()
