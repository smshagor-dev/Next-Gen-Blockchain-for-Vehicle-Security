"""Simulation-only challenge-bound admission receipts; never physical actuation ACKs."""
import hashlib
import hmac
import json
import re

DOMAIN = b'OMNIGUARD_SIM_ADMISSION_ACK_V1\0'
HEX = re.compile(r'^[0-9a-f]{32,128}$')


def _valid_hex(value):
    return type(value) is str and bool(HEX.fullmatch(value)) and len(value) % 2 == 0


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _key(secret):
    if type(secret) is not str or len(secret) < 32:
        raise ValueError('ack key must be at least 32 characters')
    return hmac.new(secret.encode(), DOMAIN + b'RECEIVER_TO_REQUESTER', hashlib.sha256).digest()


def issue_receipt(secret, *, device_id, command_nonce, challenge, admitted):
    """Sign a receipt only for a completed simulator admission decision."""
    if not device_id or len(device_id) > 96 or not all(c.isalnum() or c in '_.:@-' for c in device_id):
        raise ValueError('invalid device identity')
    if not _valid_hex(command_nonce) or not _valid_hex(challenge):
        raise ValueError('nonce/challenge must be 16-64 random bytes encoded as lowercase hex')
    if type(admitted) is not bool:
        raise ValueError('admitted must be boolean')
    body = {'version': 1, 'kind': 'SIMULATED_ADMISSION_RECEIPT', 'device_id': device_id,
            'command_nonce': command_nonce, 'challenge': challenge, 'admitted': admitted,
            'actuation_performed': False, 'physical_acknowledgment': False}
    return {**body, 'mac': hmac.new(_key(secret), DOMAIN + _canonical(body), hashlib.sha256).hexdigest()}


def verify_receipt(secret, receipt, *, device_id, command_nonce, challenge):
    if type(receipt) is not dict or set(receipt) != {'version', 'kind', 'device_id', 'command_nonce', 'challenge', 'admitted', 'actuation_performed', 'physical_acknowledgment', 'mac'}:
        return False
    if receipt['device_id'] != device_id or receipt['command_nonce'] != command_nonce or receipt['challenge'] != challenge:
        return False
    if receipt['version'] != 1 or type(receipt['version']) is not int or receipt['kind'] != 'SIMULATED_ADMISSION_RECEIPT':
        return False
    if type(receipt['admitted']) is not bool or receipt['actuation_performed'] is not False or receipt['physical_acknowledgment'] is not False:
        return False
    mac = receipt['mac']
    if type(mac) is not str or not re.fullmatch('[0-9a-f]{64}', mac):
        return False
    expected = hmac.new(_key(secret), DOMAIN + _canonical({k: v for k, v in receipt.items() if k != 'mac'}), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, expected)
