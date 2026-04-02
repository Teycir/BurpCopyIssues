<!-- donation:eth:start -->
<div align="center">

## Support Development

If this project helps your work, support ongoing maintenance and new features.

**ETH Donation Wallet**  
`0x11282eE5726B3370c8B480e321b3B2aA13686582`

<a href="https://etherscan.io/address/0x11282eE5726B3370c8B480e321b3B2aA13686582">
  <img src="publiceth.svg" alt="Ethereum donation QR code" width="220" />
</a>

_Scan the QR code or copy the wallet address above._

</div>
<!-- donation:eth:end -->


# BurpCopyIssues

![Python](https://img.shields.io/badge/python-2.7-blue.svg)
![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Pro%20%7C%20Community-orange.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

Burp Suite extension for browsing, copying, and exporting scan findings.

<p align="center">
  <img src="Assets/selecteditem.png" alt="Selected Item">
</p>

## Why BurpCopyIssues?

### Use Cases
- **Penetration Testing Reports**: Quickly copy findings into report templates with full technical details
- **Bug Bounty Hunting**: Export structured vulnerability data with HTTP evidence for submissions
- **Security Research**: Organize and track findings across multiple targets with status flags
- **Team Collaboration**: Share standardized JSON exports with complete request/response data
- **Vulnerability Management**: Track testing progress with Tested/Exploited/False Positive markers
- **Automation & Integration**: Use JSON exports with curl commands and Python templates for validation

### Key Benefits
- **Time Savings**: One-click copy eliminates manual formatting of vulnerability details
- **Complete Context**: Every export includes full HTTP evidence, not just summaries
- **Smart Deduplication**: Automatically identifies unique vs duplicate findings across hosts
- **Persistent Tracking**: Status flags survive Burp restarts for long-term project management
- **Ready-to-Use**: Exports include working curl commands and Python scripts for immediate testing
- **Visual Clarity**: Color-coded UI with alternating rows makes scanning hundreds of findings effortless

### What Makes It Different
- **No Manual Copying**: Double-click to copy complete vulnerability details to clipboard
- **HTTP Evidence Included**: Full request/response pairs with headers and bodies
- **Executable Exports**: curl commands and Python scripts ready to run
- **Status Persistence**: Track your testing workflow across sessions
- **Duplicate Intelligence**: Instantly see which findings are unique vs repeated
- **Organized Exports**: Structured by severity/confidence with statistics and test scripts

## Installation & Quick Start

1. Burp → Extender → Extensions → Add → Python
2. Select: `CopyIssues.py`
3. Click severity/confidence filter (e.g., "High - Certain")
4. Double-click any issue to copy to clipboard
5. Paste into your preferred tool or documentation

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
- Background export with live status and `Cancel Export` support
- Status tracking with checkboxes (Tested/Exploited/False Positive)
- Duplicate highlighting - unique issues show **[UNIQUE]** in bold green on right
- Group-by-host headers are non-actionable rows (copy/status actions stay issue-safe)
- Export all issues to JSON with full HTTP evidence

**Usage:**
- Click severity/confidence filter → Double-click issue → Copy to clipboard
- Use checkboxes to mark status (Tested/Exploited/False Positive)
- Click "Refresh" to reload findings
- Click "Export All" for JSON export with full HTTP evidence (use "Cancel Export" to stop)

<p align="center">
  <img src="Assets/groupbyhost.png" alt="Group by Host">
</p>

<p align="center">
  <img src="Assets/research.png" alt="Research View">
</p>

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

<p align="center">
  <img src="Assets/exportedfolder.png" alt="Exported Folder">
</p>

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

Displays all High and Medium severity issues detected by Burp Scanner, including but not limited to:
- SQL injection, XSS, Code/Command injection
- Path traversal, XXE, SSRF, Deserialization
- Authentication bypass, CSRF, CORS
- File upload, Template injection
- Host header attacks, Open redirect
- LDAP injection, HTTP smuggling
- And any other High/Medium severity findings from Burp's scanner

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
- **Count Refresh**: Background count refresh every 15s + scanner-listener cache invalidation
- **Performance**: Async issue loading/export, prompt generation on-demand, and export limited to first 2 HTTP messages per issue with 20 headers max


## Author

Developed by [Teycir Ben Soltane](https://teycirbensoltane.tn)

## License

MIT License - Free to use for authorized security testing and research purposes.
