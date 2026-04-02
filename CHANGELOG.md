# Changelog

All notable changes to BurpCopyIssues will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-04-02

### Added
- Auto-refresh timer that updates button counts every 3 seconds
- Comprehensive exception logging to Burp debugger for all error cases

### Changed
- Refresh button now updates all vulnerability counts, not just current filter
- Enhanced exception handling with specific error messages for debugging

### Fixed
- Fixed SonarQube code quality warnings (bare except clauses)
- Button counts now update automatically without requiring Burp reload
- All exceptions now properly logged to Burp console/debugger

## [1.0.0] - 2025

### Added
- Initial release
- Filter by severity (High/Medium) and confidence (Certain/Firm/Tentative)
- Double-click to copy issue details to clipboard
- Color-coded UI with alternating row backgrounds
- Status tracking (Tested/Exploited/False Positive)
- Duplicate detection with [UNIQUE] markers
- JSON export with full HTTP evidence
- curl commands and Python request templates
- Search and sort functionality
- Group by host feature
- Cross-platform support (Windows/Linux/macOS)
- Status persistence across Burp restarts
- Export organized by severity/confidence with statistics
- Ready-to-run test scripts (test.sh/test.bat)

[1.1.0]: https://github.com/Teycir/BurpCopyIssues/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Teycir/BurpCopyIssues/releases/tag/v1.0.0
