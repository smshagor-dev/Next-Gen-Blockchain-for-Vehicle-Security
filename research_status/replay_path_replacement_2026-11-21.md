# Replay database path replacement guard — 2026-11-21

| Workstream | Status | Evidence / limitation |
| --- | --- | --- |
| Authenticated hardware ingress | Partial | Stacked draft #161; no physical validation |
| Durable nonce replay state | Partial | Stacked draft #160; no verified exact-checkout run |
| Live database unlink/replacement guard | Implemented, unverified | `durable_hardware_replay.py`; three new regression controls |
| Historical valid snapshot rollback | Vulnerable under privileged replacement | Negative control draft #162; new path guard does not protect restart after replacement |
| Safety-isolated local emergency stop | Blocked | No hardware access; remote actuation must remain disabled |
| Ledger crash consistency / distributed finality | Partial / unproven | Local mock receipt does not prove consensus |
| Authentic CAM/CAN dataset evaluation | Partial / insufficient | CAM labels are not independently verified incident ground truth |
| Matched independent incident trials | Pending | No publication-ready outcome |
| Scientific claim ledger | Blocked | No independent validated effectiveness measurements |

## Scope

The guard pins the on-disk device/inode of the opened SQLite replay database and rejects nonce admission if its pathname is missing, a symlink, or replaced. It checks before starting a transaction and before committing a newly accepted nonce. This narrows an unsafe live-process window but is **not** an atomic anti-rollback protocol: a privileged adversary may restore a snapshot before startup, mutate same-inode bytes, or race the final path check. An external authenticated monotonic anchor and transactional integration remain necessary.

## Reproduction

```bash
python -m unittest discover -s tests -p 'test_replay_path_replacement.py' -v
python -m unittest discover -s tests -p 'test_replay_snapshot_rollback_negative_control.py' -v
python -m unittest discover -s tests -v
```

GitHub file commits were confirmed, but exact-checkout tests have not been executed. Do not merge until regressions run. Next: replace the pathname check with an independently anchored generation protocol and test concurrent replacement at commit boundaries. No physical safety, power-cut durability, or publishable attack effectiveness is claimed.
