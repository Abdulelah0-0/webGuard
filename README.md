# WebGuard

WebGuard is a Windows desktop tool for auditing website security configuration. It helps developers, site owners, and security reviewers see what a web server returns, understand why an observation matters, and verify configuration changes after a fix. The desktop interface is available in Arabic and English.

![WebGuard 2.2.0 dashboard showing findings and remediation in English](docs/dashboard.png)

*WebGuard 2.2.0 with demonstration results.*

## What WebGuard checks

| Area | What you can review |
| --- | --- |
| HTTPS and TLS | Connection and certificate observations, including certificate expiry when available. |
| Security headers | Response headers such as HSTS and Content Security Policy, with recommended configuration changes. |
| Cookies | Security attributes such as `Secure`, `HttpOnly`, and `SameSite`. |
| CORS and HTML | Cross-origin policy observations and indicators such as insecure resources referenced by an HTTPS page. |
| Coverage | The outcome for each URL, including partial coverage and requests that failed. |

## Quick start

1. Start the desktop app using the source instructions below. Windows x64 builds, when published, are available under [Releases](../../releases).
2. Enter a URL you own or are authorized to assess. To review a set of pages, import a saved Sitemap XML or OpenAPI 3 JSON file and select up to 50 same-origin URLs.
3. Run the assessment and select a finding to review the observed evidence, potential impact, and recommended fix. Open **HTTP** to view redacted response evidence.
4. Export a PDF, HTML, or JSON report as needed. The English workspace PDF includes a prioritized remediation plan.
5. After applying fixes, run the assessment again. Use scan history to compare observations for the same unredacted URL without query parameters, or record verification evidence in the workspace.

## Working with findings

WebGuard bases its built-in findings on the responses it receives from the selected URLs. A finding may require additional context to determine its impact. Review the evidence and coverage before closing a finding or treating a check as passed. Authentication workflows and exploit verification are outside the built-in assessment scope.

The workspace can import findings from JSON, CSV, and SARIF and retain each finding’s source and status. The repository includes [example JSON](example_findings.json) and [example CSV](example_findings.csv) files.

## Run, build, and test

Use Python 3.13 with Tkinter on Windows. From the repository folder, run the following in PowerShell:

```powershell
python -m pip install -r requirements-report.txt
python webguard_desktop.py
```

Run `python -m unittest -v` to execute the test suite. Run `build_windows.bat` to build the standalone Windows executable in `dist`.

## Local data and report privacy

Scan history is stored in a local SQLite database under `%LOCALAPPDATA%\WebGuard`. Use the path privacy option when URL paths contain sensitive information. Review reports and imported evidence before sharing them.
