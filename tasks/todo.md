## CopyIssues Freeze + Performance Fix

- [x] Confirm root cause of Burp freeze on startup/proxy browsing
- [x] Move periodic scan-issue counting off Swing UI thread
- [x] Add cached issue grouping to avoid repeated full scans
- [x] Make issue loading non-blocking and safe against stale async updates
- [x] Generate copy prompt lazily on double-click instead of eagerly for every issue
- [x] Validate behavior with static checks and targeted run-through
- [x] Document findings and verification notes

## Next Improvements (Implementation Pass)

- [x] Make export asynchronous with cancel/progress UX
- [x] Add scanner-listener cache invalidation to reduce polling latency
- [x] Fix grouped-row interactions (header-safe select/copy/status + stable unique markers)
- [x] Update docs/changelog to match behavior
- [x] Run syntax verification and summarize results

## Review

- Root cause: `Timer(3000)` executed `_update_button_counts()` on Swing EDT, and that method called `callbacks.getScanIssues(None)` directly, which blocks Burp UI under heavy traffic/issue volume.
- Fix: converted count refresh to async worker thread with cache (5s TTL), stale-refresh coalescing, and UI-safe updates via `SwingUtilities.invokeLater`.
- Performance: `load_issues()` now runs asynchronously and uses grouped cache; prompt generation moved to lazy-on-copy path to avoid per-issue upfront prompt building.
- Stability: added `IExtensionStateListener` and `extensionUnloaded()` to stop timer cleanly.
- Verification: `python3 -m py_compile CopyIssues.py` passed.

- Improvement pass: `export_all()` now executes in a background worker, supports cancellation, and updates status text.
- Improvement pass: scanner events now invalidate issue cache and trigger throttled count refresh.
- Improvement pass: list rendering now uses row metadata (header vs issue) to keep copy/status/unique marker behavior correct in grouped view.
- Improvement pass verification: `python3 -m py_compile CopyIssues.py` passed after changes.
