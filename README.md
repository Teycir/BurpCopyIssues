# BurpCopyIssues

Burp Suite extension for browsing, copying, and exporting scan findings to use with AI tools.

## Quick Start

1. Burp → Extender → Extensions → Add → Python
2. Select: `CopyIssues.py`
3. Click severity/confidence filter (e.g., "High - Certain")
4. Double-click any issue to copy to clipboard
5. Paste into any AI tool (Amazon Q, ChatGPT, Claude, etc.)

## Requirements

- Burp Suite (Professional or Community Edition)
- Jython Standalone JAR (https://www.jython.org/download)

## Features

Interactive UI extension for browsing, copying, and exporting scan findings.

**Features:**
- Filter by severity (High/Medium) and confidence (Certain/Firm/Tentative)
- Color-coded buttons with brightness gradients
- Alternating row backgrounds for readability
- Double-click to copy full issue details to clipboard
- Copied issues turn light green until refresh
- Refresh button to reload current filter
- Status tracking with checkboxes (Tested/Exploited/False Positive)
- Duplicate highlighting - unique issues show **[UNIQUE]** in bold green on right
- Export all issues to JSON with full HTTP evidence

**Usage:**
- Click severity/confidence filter → Double-click issue → Paste into AI
- Use checkboxes to mark status (Tested/Exploited/False Positive)
- Click "Refresh" to reload findings
- Click "Export All" for JSON export with full HTTP evidence

## Output Structure

```
~/burp_exports/scan_TIMESTAMP/  (or C:\burp_exports\ on Windows)
├── stats.json
├── README.txt
├── test.sh (or test.bat on Windows)
├── High/
│   ├── certain.json
│   ├── firm.json
│   └── tentative.json
└── Medium/
    ├── certain.json
    ├── firm.json
    └── tentative.json
```

## JSON Export Contents

Each issue includes:
- **id** - MD5 hash for deduplication
- **timestamp** - Scan session timestamp
- **severity/confidence** - Risk level and detection confidence
- **host/url/protocol/port** - Target metadata
- **finding** - Vulnerability name
- **description/background/remediation** - Full details
- **insertion_points** - Vulnerable parameters (URL/Body/Cookie)
- **http_evidence** - Complete request/response pairs with headers/bodies
- **base_request** - Full request details with query_params, cookies, headers
- **curl_command** - Ready-to-use curl command
- **python_request_template** - Working Python script with requests library

## Status Tracking

- **Tested**: Mark issues you've manually tested
- **Exploited**: Mark successfully exploited vulnerabilities
- **False Positive**: Mark issues that are false positives
- **Clear**: Remove all status flags for selected issue
- Status persists across Burp restarts

## Duplicate Detection

Issues are grouped by host + vulnerability type:
- **[UNIQUE]** marker appears on right for single occurrences
- Duplicates have no marker
- Helps prioritize unique attack vectors

## Supported Vulnerabilities

Focuses on High/Medium severity:
- SQL injection, XSS, Code/Command injection
- Path traversal, XXE, SSRF, Deserialization
- Authentication bypass, CSRF, CORS
- File upload, Template injection
- Host header attacks, Open redirect
- LDAP injection, HTTP smuggling

## Technical Details

- **Deduplication**: MD5 hash of host+URL+issue_name
- **Encoding**: UTF-8 handling for non-ASCII characters
- **Truncation**: Request/response bodies limited to 5KB
- **Filtering**: Only High and Medium severity issues
- **UI Colors**: 
  - Severity buttons: Dark → light gradients (Certain → Tentative)
  - Copied rows: Light green background
  - Unique issues: Bold green **[UNIQUE]** marker on right
- **Status Persistence**: Saved to `~/burp_exports/issue_status.json` (or `C:\burp_exports\` on Windows)
- **Cross-platform**: Works on Windows, Linux, and macOS
- **Performance**: Limited to first 2 HTTP messages per issue, 20 headers max

## License

Use at your own risk. Authorized testing only.
