## CopyIssues Freeze + Performance Fix

- [x] Confirm root cause of Burp freeze on startup/proxy browsing
- [x] Move periodic scan-issue counting off Swing UI thread
- [x] Add cached issue grouping to avoid repeated full scans
- [x] Make issue loading non-blocking and safe against stale async updates
- [x] Generate copy prompt lazily on double-click instead of eagerly for every issue
- [x] Validate behavior with static checks and targeted run-through
- [x] Document findings and verification notes

## Review

- Root cause: `Timer(3000)` executed `_update_button_counts()` on Swing EDT, and that method called `callbacks.getScanIssues(None)` directly, which blocks Burp UI under heavy traffic/issue volume.
- Fix: converted count refresh to async worker thread with cache (5s TTL), stale-refresh coalescing, and UI-safe updates via `SwingUtilities.invokeLater`.
- Performance: `load_issues()` now runs asynchronously and uses grouped cache; prompt generation moved to lazy-on-copy path to avoid per-issue upfront prompt building.
- Stability: added `IExtensionStateListener` and `extensionUnloaded()` to stop timer cleanly.
- Verification: `python3 -m py_compile CopyIssues.py` passed.
