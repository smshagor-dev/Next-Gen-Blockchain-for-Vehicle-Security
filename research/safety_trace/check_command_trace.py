#!/usr/bin/env python3
"""Fail-closed offline safety audit of recorded V2X command decisions.

JSONL fields: event_id, decision, origin, evidence_valid, local_override,
actuator_write. This audits traces, not physical safety or trace completeness.
"""
import argparse
import json
import sys

REQUIRED = {'event_id', 'decision', 'origin', 'evidence_valid', 'local_override', 'actuator_write'}

def check(lines):
    failures, seen, count = [], set(), 0
    for number, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        count += 1
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            failures.append({'line': number, 'property': 'invalid_json'})
            continue
        if not isinstance(event, dict) or not REQUIRED <= event.keys():
            failures.append({'line': number, 'property': 'missing_fields'})
            continue
        valid = (isinstance(event['event_id'], str) and bool(event['event_id'])
                 and event['decision'] in ('allow', 'deny')
                 and event['origin'] in ('network', 'local')
                 and all(type(event[k]) is bool for k in ('evidence_valid', 'local_override', 'actuator_write')))
        if not valid:
            failures.append({'line': number, 'property': 'invalid_schema'})
            continue
        def violation(name):
            failures.append({'line': number, 'property': name})
        if event['event_id'] in seen:
            violation('duplicate_event_id')
        seen.add(event['event_id'])
        if event['origin'] == 'network' and event['actuator_write']:
            violation('network_actuator_write')
        if event['decision'] == 'deny' and event['actuator_write']:
            violation('denied_actuator_write')
        if event['origin'] == 'network' and event['decision'] == 'allow' and not event['evidence_valid']:
            violation('ungated_network_allow')
        if event['origin'] == 'network' and event['local_override']:
            violation('forged_local_override')
        if event['origin'] == 'local' and event['local_override'] and event['decision'] != 'allow':
            violation('local_override_blocked')
    return {'records': count, 'violations': failures, 'pass': count > 0 and not failures}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('jsonl', help='JSONL path or - for stdin')
    args = parser.parse_args()
    if args.jsonl == '-':
        result = check(sys.stdin)
    else:
        with open(args.jsonl, encoding='utf-8') as stream:
            result = check(stream)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['pass'] else 1

if __name__ == '__main__':
    sys.exit(main())
