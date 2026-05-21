---
description: Audits a Salesforce org for phishing-resistant MFA compliance. Identifies which users will be blocked at Salesforce's June/July 2026 enforcement, which are exempt, and why — based on actual login behavior. Privacy-first: user identities are tokenized locally before any AI analysis.
argument-hint: [org-alias]
allowed-tools: Bash, Read, Write
---

# Salesforce MFA Audit Skill

Audits a Salesforce org for phishing-resistant MFA compliance.
Privacy-first: user identities are tokenized locally before any AI analysis.

## Trigger

User runs `/sf-mfa-audit` optionally followed by an org alias.
Org alias from arguments: `$ARGUMENTS`

---

## Privacy Architecture

```
SF Org → audit.py --collect → anonymized_payload.json   (safe to share)
                             → token_map.json             (local only, never sent)

Claude reads anonymized_payload.json → analysis with tokens only

audit.py --reconcile → maps tokens back → final reports with real names
```

Claude never sees usernames, real names, or Salesforce IDs.

---

## Execution

### Step 1 — Collect

Run queries and tokenize:
```bash
python3 audit.py --collect --org <alias>
```

This produces:
- `mfa-audit-output/anonymized_payload.json` — safe to read and analyze
- `mfa-audit-output/token_map.json` — local only, never read or share

### Step 2 — Analyze the anonymized payload

Read `mfa-audit-output/anonymized_payload.json` and analyze it.

The payload contains:
- `adminUsers` — tokenized admin users with last login
- `loginHistory` — tokenized login patterns with `localVerdict` already applied
- `permissionSetSweep` — admin-equivalent permissions via PS/PSG
- `apiOnlyTokens` — tokens where Salesforce structurally blocks UI logins (PermissionsApiUserOnly); always exempt
- `waivedUsers` — tokens holding the "Waive MFA for Exempt Users" permission (disabled at enforcement)

For each token in `adminUsers` and `permissionSetSweep`, produce a finding:
```json
[
  { "token": "USER_001", "verdict": "breaks",      "reason": "..." },
  { "token": "USER_002", "verdict": "conditional", "reason": "..." },
  { "token": "USER_003", "verdict": "exempt",      "reason": "..." },
  { "token": "USER_004", "verdict": "dormant",     "reason": "..." }
]
```

**Verdict rules:**

| Pattern | Verdict |
|---|---|
| Any `localVerdict: breaks` login | breaks |
| Mix of exempt + breaks on same token | breaks (mixed-use) |
| All logins `localVerdict: conditional` | conditional |
| Mix of conditional + breaks | breaks |
| All logins `localVerdict: exempt` | exempt |
| No logins in payload | dormant |

**API-only exemption:** Tokens in `apiOnlyTokens` should be verdict `exempt` regardless of login history — Salesforce blocks their UI logins structurally.

**Waive MFA flag:** Tokens in `waivedUsers` currently bypass MFA, but that bypass is disabled at enforcement. If already `breaks`, append a note. If not yet classified, verdict `waived`.

**Mixed-use flag:** If a token has both `localVerdict: exempt` and `localVerdict: breaks` logins on the same account, flag as mixed-use in the reason.

**What to look for beyond the rules:**
- Tokens with very high SOAP/API counts but also any browser UI login — mixed-use
- Tokens with only `SAML SSO` logins — conditional, note the ACR/AMR dependency
- Tokens with `Lightning Login` — always breaks, not phishing-resistant
- Tokens in `permissionSetSweep` not in `adminUsers` — non-admin profile users with elevated permissions, check their login history in the payload

Save findings as `mfa-audit-output/claude_findings.json`.

### Step 3 — Reconcile

```bash
python3 audit.py --reconcile --findings mfa-audit-output/claude_findings.json
```

This maps tokens back to real names and generates:
- `mfa-audit-output/mfa-compliance-report.md`
- `mfa-audit-output/mfa-technical-audit.md`

---

## Fully Local Mode (no AI)

For orgs that want zero data leaving their machine:
```bash
python3 audit.py --local --org <alias>
```

Uses deterministic classification rules built into `audit.py`. Same reports, no AI involved.

---

## Enforcement Context

- **Sandbox:** June 22, 2026
- **Production:** July 1, 2026

**In scope:** System Administrator profile + any user with ModifyAllData, ViewAllData, CustomizeApplication, or AuthorApex — via profile, permission set, or permission set group.

**Phishing-resistant only:** FIDO2 security keys, passkeys (Touch ID, Face ID, Windows Hello).

**Exempt:** SOAP API logins, headless OAuth Connected Apps.

**Not phishing-resistant:** TOTP, push notifications, Lightning Login, SMS.
