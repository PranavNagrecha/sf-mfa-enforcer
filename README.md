# sf-mfa-audit

A Claude Code skill that audits Salesforce orgs for phishing-resistant MFA compliance ahead of Salesforce's June/July 2026 enforcement.

## What makes this different

Most tools check what permissions users have. This skill analyses **actual login behavior** from `LoginHistory` to determine which logins will be blocked and which are exempt — including detection of mixed-use accounts where an integration account is also being used by a human.

## What it checks

- System Administrator users and their login patterns
- Integration/service accounts — exempt if API-only, flagged if someone also logs in via browser
- Admin-equivalent permissions granted via Permission Set or Permission Set Group (not just profile)
- SSO login patterns and the Entra/Okta ACR/AMR claim dependency
- Session Settings — whether Built-in Authenticator and U2F are enabled for MFA registration

## What it produces

- Plain-English compliance report (for stakeholders)
- Technical audit with all queries and per-user verdicts (for admins)

## Enforcement dates

| Environment | Date |
|---|---|
| Sandbox | June 22, 2026 (staggered ~7 days) |
| Production | July 1, 2026 (staggered ~30 days) |

## Privacy

Salesforce user data (names, usernames, IDs) never leaves your machine by default.

The tool uses a **tokenization layer** before any AI analysis:

```
SF Org → audit.py → anonymized tokens → Claude (optional)
                  → token_map.json      stays local, never sent
```

- All queries run locally via Salesforce CLI
- Usernames and user IDs are replaced with tokens (`USER_001`, `USER_002`, etc.) before Claude sees anything
- Org-specific strings in app names are scrubbed
- The token map is saved locally only and is never included in the AI payload
- Claude's findings reference tokens only — real names are mapped back locally when generating reports

**Fully local mode** (no AI, no data leaves at all):
```bash
python3 audit.py --local --org MyOrgAlias
```

**AI-assisted mode** (Claude sees anonymized data only):
```bash
python3 audit.py --collect --org MyOrgAlias
# → share mfa-audit-output/anonymized_payload.json with Claude
python3 audit.py --reconcile --findings mfa-audit-output/claude_findings.json
```

Add `mfa-audit-output/` to your `.gitignore` before committing.

---

## Requirements

- [Salesforce CLI](https://developer.salesforce.com/tools/salesforcecli) (`sf`)
- Authenticated org connection (`sf org login`)
- [Claude Code](https://claude.ai/code)

## Usage

```bash
/sf-mfa-audit                    # uses default org
/sf-mfa-audit MyOrgAlias         # targets a specific org
```

## Install as a Claude Code skill

Copy the `sf-mfa-audit/` folder to `~/.claude/skills/` and restart Claude Code.

## Queries

All SOQL queries are in `queries/` and can be run independently against any org using Salesforce CLI or Developer Console.

| File | Purpose |
|---|---|
| `01_admin_users.soql` | Active System Admin users + last login |
| `02_login_history.soql` | Login patterns for admin users (last 30 days) |
| `03_permission_set_sweep.soql` | Admin-equivalent permissions via PS/PSG |
| `04_integration_accounts.soql` | Likely integration accounts by name pattern |
| `05_psg_admin_check.soql` | PSGs containing admin-equivalent permission sets |

## Salesforce Reference Articles

There are **two separate enforcement waves** in 2026, each with its own Salesforce help article. This tool covers the first wave (privileged users only).

### Wave 1 — Phishing-Resistant MFA for Privileged Users (this tool's scope)
**Production: July 1, 2026 · Sandbox: June 22, 2026**

Affects: System Administrator profile + any user with Modify All Data, View All Data, Customize Application, or Author Apex — via profile, permission set, or permission set group.

These users must use **phishing-resistant MFA only** — FIDO2 security keys or passkeys (Touch ID, Face ID, Windows Hello). TOTP apps and Salesforce Authenticator do not satisfy this requirement.

> Salesforce Help Article: [Prepare for Phishing-Resistant MFA Enforcement](https://help.salesforce.com/s/articleView?id=005321563&type=1) (Article 005321563)

### Wave 2 — Standard MFA for All Other Employee Users (outside this tool's scope)
**Production: July 20, 2026 · Sandbox: June 22, 2026**

Affects: All other internal users who don't hold the privileges above.

These users must use **standard MFA or better** — TOTP apps, Salesforce Authenticator, or phishing-resistant methods all qualify.

> Salesforce Help Article: [Prepare for MFA Enforcement for All Employee Users](https://help.salesforce.com/s/articleView?id=005321561&type=1) (Article 005321561)

---

### Why community blogs cite different dates

Many blog posts (Salesforce Ben, Arkus, BrightHelm, etc.) cite **July 1** for production. They are correct — for privileged users. Some cite **July 20**, also correct — for everyone else. The two waves share the same sandbox date (June 22) but have different production cutoffs. This tool only audits Wave 1.

---

### ACR/AMR signal reference (SSO orgs)

For users logging in via SSO, Salesforce evaluates the AMR/ACR claim in the IdP response. Privileged users require a **phishing-resistant** signal — standard MFA signals are not sufficient.

| Tier | SSO Signal Values |
|---|---|
| Phishing-Resistant ✓ (required for privileged users) | `cert` `fido` `fido2` `fpt` `hwk` `iris` `pin` `pki` `pop` `retina` `sc` `Smartcard` `swk` `TLSClient` `user` `vbm` `wia` `X509` |
| Standard MFA ✗ (not enough for privileged users) | `Face` `mobiletwofactorcontract` `multipleauthn` `okta_verify` `passkey` `webauthn` |
| Weak / No MFA ✗ | `pwd` `sms` `tel` `email` |

Source: Salesforce Help Article 005321561, "Determining Authentication Strength & The Evaluation Logic"

## License

MIT
