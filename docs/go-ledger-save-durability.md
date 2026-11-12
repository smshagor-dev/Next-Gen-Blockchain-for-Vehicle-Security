# Production Go /save crash-consistency boundary

**Scope:** fix the authenticated local Go API's explicit `POST /save` operation.
Issue #95. This change does not modify any vehicle actuation decision or
claim an original scientific breakthrough.

## Failure repaired

The previous Go implementation fsynced a temporary chain file, then tried
`os.Rename(temp, target)`. If rename failed, it deleted the existing target
and retried. If the retry failed (or the process crashed), the previously
valid saved chain could be lost. The directory containing the new entry was
not fsynced.

The replacement performs the following steps:

1. Serialize **concurrent /save requests in the same Go server process**.
2. Verify the current in-memory blockchain while holding the state read lock;
   reject an invalid chain with HTTP 409 rather than persisting it.
3. Serialize the current chain to JSON and resolve its configured target.
4. Create a temporary file in the target directory with mode 0600.
5. Write the complete serialized payload, fsync the temporary file and close.
6. Make **one** atomic rename attempt without ever deleting the old target
   on failure. On failure, remove only the temporary file; previous chain
   remains accessible.
7. On POSIX, fsync the directory to request durability of its rename entry.
   Go's portable Windows API does **not** provide directory fsync here.
8. Return success only after the configured steps succeed. If directory
   fsync fails **after successful rename**, HTTP 500 indicates an uncertain
   durability state; the new target may already be visible and the program
   must not claim rollback.

The change uses a fail-injectable file writer for regression tests.
CI runs Go 1.22 tests and vet on Linux and Windows plus the race detector
on Linux, validating errors and existing-file retention without destructive
power cycling.

## Explicit limitations and future research work

- **Manual persistence:** mutations do not auto-save every block. A power
  cut before the next explicit `/save` can lose unsaved in-memory data.
- **Startup recovery:** `/init` still initializes a new genesis; this PR
  does not implement authenticated loading of an existing chain after
  process restart. That requires separate verified startup recovery and a
  well-defined generation/identity contract.
- **Multiple processes:** locking only covers save calls in this server
  process. The file is not a multi-writer transaction log.
- **Hardware:** `fsync` and `rename` tests are software-level checks, not
  physically induced power-loss / SSD firmware or HIL validation.
- **Security:** prior chain content can be rolled back by an attacker who
  controls the host filesystem. There is no trusted monotonic external
  anchor or server-signed consensus receipt. A local block hash does not
  imply distributed finality, reliable Byzantine quorum or sensor truth.
- **Windows:** a failed overwrite rename must preserve the old file; the
  API returns failure rather than deleting it. Full crash durability and
  directory fsync parity on Windows are outside this patch.
- **No physical actuator path** is changed or enabled.

Do not cite the Go persistence regression tests as experimental proof of
vehicle safety, blockchain consensus finality or a publishable research
contribution. They provide a demonstrable correctness repair and reproducible
fault-injection evidence only.
