# Historical Credential and Git-History Remediation

This runbook is intentionally operational. It does **not** contain historical secret values and no automated release job rewrites shared Git history.

## Why this is separate

Removing a secret from the current tree does not revoke a credential that was previously committed. A shared-history rewrite can also invalidate clones, open branches, commit SHAs, signed references, CI caches, and external links. Therefore remediation requires an owner-approved coordinated maintenance window.

## Required sequence

1. Inventory credential domains that were ever exposed without printing values into logs.
2. Rotate/revoke those credentials at their authoritative service/provider first.
3. Invalidate derived sessions/tokens where applicable.
4. Confirm applications and CI have moved to the new independent credentials.
5. Freeze repository writes for the coordinated rewrite window if history removal is approved.
6. Use a reviewed history-rewrite tool and path/value rules maintained outside public logs.
7. Force-update affected branches/tags only after owner approval.
8. Re-run current-tree secret scanning and inspect rewritten history with a dedicated secret-scanning product/tool.
9. Invalidate caches/artifacts that may contain old material.
10. Require collaborators to re-clone or carefully reset to rewritten references.
11. Re-run Security Baseline on the resulting protected `main` commit before any release tag.

## Do not

- Do not paste historical credentials into issues, PR bodies, CI logs, commands captured by public build logs, or documentation.
- Do not treat history removal as credential revocation.
- Do not rewrite shared history while other release/publication operations are running.
- Do not reuse one replacement secret across multiple security domains.

## v3.0.3 boundary

The v3.0.3 source tree adds current-tree prohibited-secret scanning and removes known hardcoded legacy/default material where safely addressable. Actual credential rotation and any coordinated history rewrite remain owner-controlled deployment/repository operations.
