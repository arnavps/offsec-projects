# Cookie Sentinel - Security Audit Report
**Date:** 2026-06-18 18:15:13

## Executive Summary
- **Total Cookies Audited:** 1
- **Total Vulnerabilities / Misconfigurations:** 2

### Severity Breakdown
- **Critical:** 0
- **High:** 1
- **Medium:** 1
- **Low:** 0
- **Info:** 0

## Audited Cookies Table
| Cookie Name | Value (Masked) | HttpOnly | Secure | SameSite | Domain | Path |
| --- | --- | --- | --- | --- | --- | --- |
| session | `******` | ❌ No | ✅ Yes | Lax | .example.com | / |

## Detailed Security Findings
### Cookie: `session`
#### [High] MISSING_HTTPONLY
- **Description:** Cookie appears to be a session identifier but lacks the 'HttpOnly' flag.
- **Remediation:** Configure the 'Set-Cookie' header to include the 'HttpOnly' attribute. This prevents client-side scripts (e.g. XSS) from reading the session cookie.

#### [Medium] OVERLY_BROAD_DOMAIN_DOT
- **Description:** Cookie domain '.example.com' starts with a leading dot, making it accessible to all subdomains.
- **Remediation:** Omit the 'Domain' attribute completely to lock the cookie to the host that set it, or specify the exact hostname without a leading dot.
