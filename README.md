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
| Sandbox | June 22, 2026 |
| Production | July 20, 2026 (staggered ~30 days) |

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

## License

MIT
