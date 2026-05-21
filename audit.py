#!/usr/bin/env python3
"""
sf-mfa-audit  —  Salesforce phishing-resistant MFA compliance audit
Privacy-first: user identities are tokenized before any AI analysis.
Token map stays local. Claude only sees tokens + login patterns.

Usage:
  python3 audit.py --org <alias> --collect          # run queries, tokenize, save payload
  python3 audit.py --reconcile --findings <file>    # map tokens back, generate reports
  python3 audit.py --org <alias> --local            # fully local, no AI involved
"""

import argparse, json, os, re, subprocess, sys
from collections import defaultdict
from datetime import datetime, timezone

OUTPUT_DIR     = "mfa-audit-output"
PAYLOAD_FILE   = os.path.join(OUTPUT_DIR, "anonymized_payload.json")
TOKEN_MAP_FILE = os.path.join(OUTPUT_DIR, "token_map.json")   # never sent to AI

# ── Login type classification ─────────────────────────────────────────────────

BREAKING_LOGIN_TYPES = {
    "Application",
    "Remote Access Client",
    "Lightning Login",
    "Employee Login to Community",
}

CONDITIONAL_LOGIN_TYPES = {
    "SAML Sfdc Initiated SSO",
    "SAML Idp Initiated SSO",
}

EXEMPT_LOGIN_TYPES = {
    "Other Apex API",
    "AutomatedProcess",
    "OAuth 2.0",
}

# Empty string excluded: missing browser data is unknown, not proof of headless
HEADLESS_BROWSERS = {"Unknown", "Java", "Java (Salesforce.com)"}

def classify_login(login_type, browser):
    if login_type in CONDITIONAL_LOGIN_TYPES:
        return "conditional"
    if login_type in BREAKING_LOGIN_TYPES:
        return "breaks"
    if login_type == "Remote Access 2.0":
        b = browser or ""
        if not b:
            return "unknown"
        return "exempt" if b in HEADLESS_BROWSERS else "breaks"
    if login_type in EXEMPT_LOGIN_TYPES:
        return "exempt"
    return "unknown"

def is_behaviorally_integration(logins):
    """A user whose entire 30-day login history is exempt patterns is an integration account."""
    if not logins:
        return False
    return all(l["localVerdict"] == "exempt" for l in logins)

def _counts(logins):
    """Return (total, breaking) login counts from aggregated LoginHistory rows."""
    total    = sum(l.get("count") or 1 for l in logins)
    breaking = sum(l.get("count") or 1 for l in logins if l["localVerdict"] == "breaks")
    return total, breaking

# ── Tokenizer ─────────────────────────────────────────────────────────────────

class Tokenizer:
    def __init__(self):
        self.token_map = {}
        self.reverse   = {}
        self._counter  = 1

    def tokenize(self, uid, username="", name=""):
        if not uid:
            return "UNKNOWN"
        if uid not in self.token_map:
            tok = f"USER_{self._counter:03d}"
            self._counter += 1
            self.token_map[uid] = tok
            self.reverse[tok]   = {"userId": uid, "username": username, "name": name}
        return self.token_map[uid]

    def save(self, path):
        with open(path, "w") as f:
            json.dump(self.reverse, f, indent=2)
        print(f"  Token map saved: {path}  (keep local — do not share)")

    def load(self, path):
        with open(path) as f:
            self.reverse = json.load(f)
        self.token_map = {v["userId"]: k for k, v in self.reverse.items()}
        self._counter  = len(self.reverse) + 1

    def reconcile(self, token):
        return self.reverse.get(token, {"name": token, "username": token})

# ── Salesforce query runner ───────────────────────────────────────────────────

def run_query(soql, org):
    try:
        result = subprocess.run(
            ["sf", "data", "query", "--query", soql, "--target-org", org, "--json"],
            capture_output=True, text=True
        )
    except FileNotFoundError:
        print("  ERROR: 'sf' CLI not found. Install Salesforce CLI: https://developer.salesforce.com/tools/salesforcecli")
        sys.exit(1)
    try:
        d = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"  Query failed (no JSON): {result.stderr[:300]}")
        return []
    if d.get("status") != 0:
        print(f"  SOQL error: {d.get('message', str(d))[:300]}")
        sys.exit(1)
    return d.get("result", {}).get("records", [])

# ── Org identity ─────────────────────────────────────────────────────────────

def fetch_org_identity(org):
    records = run_query(
        "SELECT Name, InstanceName, IsSandbox FROM Organization LIMIT 1",
        org
    )
    if not records:
        return {}
    r = records[0]
    return {
        "orgName":      r.get("Name", ""),
        "instanceName": r.get("InstanceName", ""),
        "isSandbox":    r.get("IsSandbox", False),
    }

# ── App name scrubber ─────────────────────────────────────────────────────────

def scrub_app(name, org_terms=()):
    """Remove org-identifying strings from app/connected-app names."""
    if not name:
        return name
    # Scrub full phrases AND individual words (>3 chars) so partial matches are caught.
    # Longest terms first to avoid replacing a word before we replace the full phrase.
    all_terms = set()
    for term in org_terms:
        if term:
            all_terms.add(term)
            for word in term.split():
                if len(word) > 3:
                    all_terms.add(word)
    result = name
    for term in sorted(all_terms, key=len, reverse=True):
        result = re.sub(re.escape(term), "OrgName", result, flags=re.IGNORECASE)
    return result.strip()

# ── Collect phase ─────────────────────────────────────────────────────────────

def collect(org):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    tz = Tokenizer()
    print(f"\nRunning audit against: {org}\n")

    print("  [0/4] Org identity...")
    org_identity = fetch_org_identity(org)
    org_name  = org_identity.get("orgName", "")
    org_terms = (org_name,) if org_name else ()
    if org_name:
        print(f"         {org_name}  ({org_identity.get('instanceName', '')})")

    # Q1 — Admin users: System Administrator profile + any profile with admin-equivalent
    # permissions. The permission checks catch cloned profiles ("Super Admin", "IT Admin", etc.)
    # that don't match the standard profile name but carry the same powers.
    print("  [1/4] Admin users...")
    q1 = run_query("""
        SELECT Id, Name, Username, Profile.Name, Profile.PermissionsApiUserOnly, LastLoginDate
        FROM User
        WHERE IsActive = true
        AND (
            Profile.Name = 'System Administrator'
            OR Profile.PermissionsModifyAllData     = true
            OR Profile.PermissionsViewAllData       = true
            OR Profile.PermissionsCustomizeApplication = true
            OR Profile.PermissionsAuthorApex        = true
        )
        ORDER BY LastLoginDate DESC NULLS LAST
    """, org)
    admin_users     = []
    admin_ids       = set()
    api_only_tokens = set()
    for r in q1:
        tok = tz.tokenize(r["Id"], r.get("Username", ""), r.get("Name", ""))
        admin_ids.add(r["Id"])
        if (r.get("Profile") or {}).get("PermissionsApiUserOnly"):
            api_only_tokens.add(tok)
        admin_users.append({
            "token":     tok,
            "profile":   (r.get("Profile") or {}).get("Name"),
            "lastLogin": r.get("LastLoginDate") or "Never"
        })

    # Q2 — Permission set sweep (PS + PSG components)
    print("  [2/4] Permission set sweep...")
    q2 = run_query("""
        SELECT Assignee.Id, Assignee.Name, Assignee.Username, Assignee.Profile.Name,
               PermissionSet.Name, PermissionSetGroup.MasterLabel,
               PermissionSet.PermissionsModifyAllData, PermissionSet.PermissionsViewAllData,
               PermissionSet.PermissionsCustomizeApplication, PermissionSet.PermissionsAuthorApex,
               PermissionSet.PermissionsApiUserOnly
        FROM PermissionSetAssignment
        WHERE IsActive = true AND Assignee.IsActive = true
        AND (
            PermissionSet.PermissionsModifyAllData     = true
            OR PermissionSet.PermissionsViewAllData    = true
            OR PermissionSet.PermissionsCustomizeApplication = true
            OR PermissionSet.PermissionsAuthorApex     = true
        )
        AND PermissionSet.IsOwnedByProfile = false
        ORDER BY Assignee.Name
    """, org)
    perm_sweep = []
    perm_ids   = set()
    for r in q2:
        assignee = r.get("Assignee") or {}
        uid = assignee.get("Id", "")
        tok = tz.tokenize(uid, assignee.get("Username", ""), assignee.get("Name", ""))
        perm_ids.add(uid)
        ps  = r.get("PermissionSet") or {}
        psg = r.get("PermissionSetGroup") or {}
        if ps.get("PermissionsApiUserOnly"):
            api_only_tokens.add(tok)
        perm_sweep.append({
            "token":              tok,
            "profile":            (assignee.get("Profile") or {}).get("Name"),
            "permissionSet":      ps.get("Name"),
            "permissionSetGroup": psg.get("MasterLabel") or "",
            "modifyAllData":      ps.get("PermissionsModifyAllData"),
            "viewAllData":        ps.get("PermissionsViewAllData"),
            "customizeApp":       ps.get("PermissionsCustomizeApplication"),
            "authorApex":         ps.get("PermissionsAuthorApex"),
        })

    # Q4 — Users with "Waive Multi-Factor Authentication for Exempt Users" permission.
    # After enforcement this exemption is disabled — these users must enroll MFA.
    # Field verified: SELECT PermissionsBypassMFAForUiLogins FROM PermissionSet LIMIT 1
    # Note: FieldDefinition does not index Permission* fields — use direct object query to verify.
    print("  [3/4] Waive MFA exemption holders...")
    q4 = run_query("""
        SELECT Assignee.Id, Assignee.Name, Assignee.Username, Assignee.Profile.Name
        FROM PermissionSetAssignment
        WHERE IsActive = true
        AND Assignee.IsActive = true
        AND PermissionSet.PermissionsBypassMFAForUiLogins = true
        ORDER BY Assignee.Name
    """, org)
    waived_users  = []
    waived_tokens = set()
    for r in q4:
        assignee = r.get("Assignee") or {}
        uid = assignee.get("Id", "")
        tok = tz.tokenize(uid, assignee.get("Username", ""), assignee.get("Name", ""))
        if tok not in waived_tokens:
            waived_tokens.add(tok)
            waived_users.append({
                "token":   tok,
                "profile": (assignee.get("Profile") or {}).get("Name"),
            })

    all_scope_ids = admin_ids | perm_ids
    print(f"  [4/4] Login history ({len(all_scope_ids)} in-scope users)...")

    # Chunk to keep SOQL string length well within the 20K character limit
    def chunks(s, n=200):
        lst = list(s)
        for i in range(0, len(lst), n):
            yield lst[i:i+n]

    login_history = []
    for chunk in chunks(all_scope_ids):
        id_list = "', '".join(chunk)
        rows = run_query(f"""
            SELECT UserId, LoginType, Application, Browser, Platform, COUNT(Id) cnt
            FROM LoginHistory
            WHERE UserId IN ('{id_list}')
            AND LoginTime = LAST_N_DAYS:30
            GROUP BY UserId, LoginType, Application, Browser, Platform
        """, org)
        for r in rows:
            tok     = tz.tokenize(r.get("UserId", ""))
            verdict = classify_login(r.get("LoginType", ""), r.get("Browser", ""))
            login_history.append({
                "token":        tok,
                "loginType":    r.get("LoginType"),
                "application":  scrub_app(r.get("Application") or "", org_terms),
                "browser":      r.get("Browser") or "",
                "platform":     r.get("Platform") or "",
                "count":        r.get("cnt"),
                "localVerdict": verdict
            })

    # orgName and domain are used only for scrubbing above — not included in payload.
    # meta.org is replaced with a placeholder so the AI payload contains nothing org-identifying.
    payload = {
        "meta": {
            "org":              "<redacted>",
            "isSandbox":        org_identity.get("isSandbox", False),
            "instanceName":     org_identity.get("instanceName", ""),
            "generatedAt":      datetime.now(timezone.utc).isoformat(),
            "enforcementDates": {"sandbox": "2026-06-22", "production": "2026-07-01"}
        },
        "apiOnlyTokens":      sorted(api_only_tokens),
        "waivedUsers":        waived_users,
        "adminUsers":         admin_users,
        "loginHistory":       login_history,
        "permissionSetSweep": perm_sweep,
    }

    with open(PAYLOAD_FILE, "w") as f:
        json.dump(payload, f, indent=2)
    tz.save(TOKEN_MAP_FILE)

    print(f"\n  Users in scope:         {len(all_scope_ids)}")
    print(f"  Admin users:            {len(admin_users)}")
    print(f"  Login patterns:         {len(login_history)}")
    print(f"  Perm set assignments:   {len(perm_sweep)}")
    print(f"  Waive MFA holders:      {len(waived_users)}")
    print(f"\n  Anonymized payload:  {PAYLOAD_FILE}")
    print(f"  Token map (local):   {TOKEN_MAP_FILE}")
    return payload, tz

# ── Local classification (no AI) ──────────────────────────────────────────────

def classify_locally(payload):
    login_by_token = defaultdict(list)
    for l in payload["loginHistory"]:
        login_by_token[l["token"]].append(l)

    all_tokens  = {u["token"] for u in payload["adminUsers"]}
    all_tokens |= {p["token"] for p in payload["permissionSetSweep"]}
    api_only    = set(payload.get("apiOnlyTokens", []))
    waived      = {u["token"] for u in payload.get("waivedUsers", [])}

    findings = []
    for tok in all_tokens:
        logins   = login_by_token.get(tok, [])
        verdicts = {l["localVerdict"] for l in logins}

        # Structurally API-only: Salesforce blocks UI logins regardless of MFA setting.
        if tok in api_only:
            total, _ = _counts(logins) if logins else (0, 0)
            login_note = f" ({total:,} historical logins)" if total else " (no recent logins)"
            findings.append({
                "token":   tok,
                "verdict": "exempt",
                "reason":  f"API-only user (PermissionsApiUserOnly){login_note} — Salesforce blocks UI logins, MFA enforcement cannot affect this account."
            })
            continue

        if not logins:
            findings.append({
                "token":   tok,
                "verdict": "dormant",
                "reason":  "No logins in last 30 days. Still in scope — breaks on first login after enforcement."
            })
            continue

        total, breaking = _counts(logins)
        pct     = round(breaking / total * 100) if total else 0
        pct_str = "< 1%" if (breaking > 0 and pct == 0) else f"{pct}%"

        if is_behaviorally_integration(logins):
            findings.append({
                "token":   tok,
                "verdict": "exempt",
                "reason":  f"All {total:,} logins are API/headless OAuth — exempt."
            })
            continue

        if "exempt" in verdicts and "breaks" in verdicts:
            findings.append({
                "token":   tok,
                "verdict": "breaks",
                "reason":  f"{breaking:,}/{total:,} logins ({pct_str}) will break. Mixed-use: API/integration logins exempt, UI logins will break."
            })
        elif "breaks" in verdicts:
            findings.append({
                "token":   tok,
                "verdict": "breaks",
                "reason":  f"{breaking:,}/{total:,} logins ({pct_str}) will break at enforcement."
            })
        elif "unknown" in verdicts and "breaks" not in verdicts:
            unknown_types = sorted({
                l["loginType"] for l in logins
                if l["localVerdict"] == "unknown" and l["loginType"]
            })
            known_str = f" Also has {', '.join(sorted(verdicts - {'unknown'}))} patterns." if verdicts - {"unknown"} else ""
            findings.append({
                "token":   tok,
                "verdict": "review",
                "reason":  f"{total:,} logins — unrecognized types: {', '.join(unknown_types)}. Manual review needed.{known_str}"
            })
        elif "conditional" in verdicts and "breaks" not in verdicts:
            findings.append({
                "token":   tok,
                "verdict": "conditional",
                "reason":  f"{total:,} logins via SAML SSO. Safe only if IdP passes a phishing-resistant ACR/AMR signal — ask your IdP team to confirm one of: cert, fido, fido2, fpt, hwk, iris, pin, pki, pop, retina, sc, Smartcard, swk, TLSClient, user, vbm, wia, X509. Standard MFA signals (okta_verify, passkey, webauthn) are NOT sufficient for privileged users."
            })
        elif verdicts == {"exempt"}:
            findings.append({
                "token":   tok,
                "verdict": "exempt",
                "reason":  f"All {total:,} logins exempt — no breaking patterns detected."
            })
        elif "unknown" in verdicts:
            unknown_types = sorted({
                l["loginType"] for l in logins
                if l["localVerdict"] == "unknown" and l["loginType"]
            })
            findings.append({
                "token":   tok,
                "verdict": "review",
                "reason":  f"{total:,} logins — unrecognized types: {', '.join(unknown_types)}. Manual review needed."
            })
        else:
            findings.append({
                "token":   tok,
                "verdict": "review",
                "reason":  f"{total:,} logins — mixed patterns: {', '.join(sorted(verdicts))}. Manual review needed."
            })

    # Waived users not already in admin/perm scope get their own review finding.
    # Waived users already in scope get a warning appended — they may think they're safe.
    captured = {f["token"] for f in findings}
    for u in payload.get("waivedUsers", []):
        tok = u["token"]
        if tok not in captured:
            findings.append({
                "token":   tok,
                "verdict": "waived",
                "reason":  "Has 'Waive MFA for Exempt Users' permission — exemption is disabled at enforcement. Must enroll MFA or contact Salesforce Support."
            })
        else:
            for f in findings:
                if f["token"] == tok and f["verdict"] not in ("exempt",):
                    f["reason"] += " Also holds 'Waive MFA' exemption — that permission is disabled at enforcement too."
                    break

    return findings

# ── Reconcile + report ────────────────────────────────────────────────────────

def reconcile_and_report(findings, tz, payload, org_label=None):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    org = org_label or payload.get("meta", {}).get("org", "unknown")

    rows = []
    for f in findings:
        real = tz.reconcile(f["token"])
        rows.append({
            "name":     real.get("name", f["token"]),
            "username": real.get("username", f["token"]),
            "verdict":  f["verdict"],
            "reason":   f["reason"]
        })

    rows.sort(key=lambda r: (
        {"breaks": 0, "dormant": 1, "conditional": 2, "waived": 3, "review": 4, "exempt": 5}.get(r["verdict"], 6),
        r["name"]
    ))

    breaks      = [r for r in rows if r["verdict"] == "breaks"]
    dormant     = [r for r in rows if r["verdict"] == "dormant"]
    conditional = [r for r in rows if r["verdict"] == "conditional"]
    waived      = [r for r in rows if r["verdict"] == "waived"]
    exempt      = [r for r in rows if r["verdict"] == "exempt"]
    review      = [r for r in rows if r["verdict"] == "review"]

    report = f"""# MFA Compliance Report
**Generated:** {now} | **Org:** {org}
**Enforcement:** Sandbox June 22 2026 (staggered ~7 days)  ·  Production July 1 2026 (staggered ~30 days)

---

## What Will Break

| User | Username | Why |
|---|---|---|
"""
    for r in breaks:
        report += f"| {r['name']} | {r['username']} | {r['reason']} |\n"

    report += f"""
## Dormant — Breaks on First Login After Enforcement

| User | Username |
|---|---|
"""
    for r in dormant:
        report += f"| {r['name']} | {r['username']} |\n"

    report += f"""
## Conditional — Depends on IdP (Entra ID / Okta)

These users log in via SAML SSO only. Because they are **privileged users**, standard MFA signals
(e.g. `okta_verify`, `passkey`, `webauthn`) are not sufficient — the IdP must pass a
**phishing-resistant** ACR/AMR signal. Ask your identity team to confirm the ID token or SAML
response includes one of these values:

`cert` · `fido` · `fido2` · `fpt` · `hwk` · `iris` · `pin` · `pki` · `pop` · `retina` · `sc` · `Smartcard` · `swk` · `TLSClient` · `user` · `vbm` · `wia` · `X509`

If the IdP cannot confirm this, treat these users the same as **Breaks**.

| User | Username |
|---|---|
"""
    for r in conditional:
        report += f"| {r['name']} | {r['username']} |\n"

    if waived:
        report += f"""
## Waive MFA Exemption — Action Required Before Enforcement

The "Waive Multi-Factor Authentication for Exempt Users" permission (`PermissionsBypassMFAForUiLogins`) is
**disabled by Salesforce at enforcement** — these users will break at their next login unless they enroll in
phishing-resistant MFA. Treat them the same as "Breaks" users: ensure they register a FIDO2 key or passkey,
or contact Salesforce Support only if the exemption is legitimately needed (e.g. an automated testing account).

| User | Username | Profile |
|---|---|---|
"""
        for r in waived:
            report += f"| {r['name']} | {r['username']} | {r['reason']} |\n"

    if review:
        report += f"""
## Needs Manual Review

| User | Username | Pattern |
|---|---|---|
"""
        for r in review:
            report += f"| {r['name']} | {r['username']} | {r['reason']} |\n"

    report += f"""
## Exempt — No Action Needed

| User | Username | Why |
|---|---|---|
"""
    for r in exempt:
        report += f"| {r['name']} | {r['username']} | {r['reason']} |\n"

    report += """
---

## Session Settings — Check Before Anything Else

Before enrolling anyone in phishing-resistant MFA, confirm these are in the
**High Assurance** bucket in Setup > Session Settings:

- Built-in Authenticator (passkeys, Touch ID, Face ID, Windows Hello)
- U2F Security Keys (YubiKey, FIDO2)

If neither is present, no one can register a phishing-resistant method.

---

## Actions

1. Confirm IdP passes a phishing-resistant ACR/AMR signal (fido, fido2, hwk, etc.) — standard MFA signals are not enough for privileged users
2. Enable Built-in Authenticator + U2F in Session Settings > High Assurance
3. Stop UI logins on shared integration accounts — use named admin accounts
4. Enroll or deactivate dormant users before enforcement date
5. Move Lightning Login users to SSO or passkeys
"""

    tech = f"""# MFA Technical Audit
**Generated:** {now} | **Org:** {org}

---

## Summary Table

| User | Username | Verdict | Reason |
|---|---|---|---|
"""
    for r in rows:
        tech += f"| {r['name']} | {r['username']} | {r['verdict']} | {r['reason']} |\n"

    tech += """
---

## Queries Used

### 1. Admin Users
Catches System Administrator profile and any cloned admin profile ("Super Admin",
"IT Admin", etc.) by querying profile-level permissions directly.
```sql
SELECT Id, Name, Username, Profile.Name, LastLoginDate
FROM User
WHERE IsActive = true
AND (
    Profile.Name = 'System Administrator'
    OR Profile.PermissionsModifyAllData     = true
    OR Profile.PermissionsViewAllData       = true
    OR Profile.PermissionsCustomizeApplication = true
    OR Profile.PermissionsAuthorApex        = true
)
ORDER BY LastLoginDate DESC NULLS LAST
```

### 2. Permission Set Sweep (covers PS and PSG components)
```sql
SELECT Assignee.Id, Assignee.Name, Assignee.Username, Assignee.Profile.Name,
       PermissionSet.Name, PermissionSetGroup.MasterLabel,
       PermissionSet.PermissionsModifyAllData, PermissionSet.PermissionsViewAllData,
       PermissionSet.PermissionsCustomizeApplication, PermissionSet.PermissionsAuthorApex
FROM PermissionSetAssignment
WHERE IsActive = true AND Assignee.IsActive = true
AND (
    PermissionSet.PermissionsModifyAllData = true
    OR PermissionSet.PermissionsViewAllData = true
    OR PermissionSet.PermissionsCustomizeApplication = true
    OR PermissionSet.PermissionsAuthorApex = true
)
AND PermissionSet.IsOwnedByProfile = false
ORDER BY Assignee.Name
```

### 3. Login History — all in-scope users (Admin + Perm Sweep union)
```sql
SELECT UserId, LoginType, Application, ApiType, Browser, Platform, COUNT(Id) cnt
FROM LoginHistory
WHERE UserId IN ('<all_in_scope_ids>')
AND LoginTime = LAST_N_DAYS:30
GROUP BY UserId, LoginType, Application, ApiType, Browser, Platform
```
IDs chunked in batches of 200 to stay within the 20K character SOQL string length limit.

---

## Login Type Classification

| LoginType | Browser | Verdict |
|---|---|---|
| Other Apex API (SOAP) | Any | Exempt |
| AutomatedProcess / OAuth 2.0 | Any | Exempt |
| Remote Access 2.0 | Unknown / Java | Exempt |
| Remote Access 2.0 | (missing) | Review |
| Remote Access 2.0 | Chrome / Edge / Safari | Breaks |
| SAML Sfdc/Idp Initiated SSO | Any | Conditional |
| Application | Any | Breaks |
| Remote Access Client | Any | Breaks |
| Lightning Login | Any | Breaks |
| Unrecognized type | Any | Review |

Integration accounts are detected behaviorally: a user whose entire
30-day login history is exempt patterns (SOAP + headless OAuth) is
classified as an integration account regardless of username or profile.
"""

    report_path = os.path.join(OUTPUT_DIR, "mfa-compliance-report.md")
    tech_path   = os.path.join(OUTPUT_DIR, "mfa-technical-audit.md")

    with open(report_path, "w") as f:
        f.write(report)
    with open(tech_path, "w") as f:
        f.write(tech)

    print(f"\n  Reports generated:")
    print(f"  {report_path}")
    print(f"  {tech_path}")
    print(f"\n  Breaks:      {len(breaks)}")
    print(f"  Dormant:     {len(dormant)}")
    print(f"  Conditional: {len(conditional)}")
    if waived:
        print(f"  Waived:      {len(waived)}  ← exemption disabled at enforcement")
    print(f"  Exempt:      {len(exempt)}")
    if review:
        print(f"  Review:      {len(review)}")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Salesforce MFA compliance audit")
    parser.add_argument("--org",       help="Salesforce org alias or username")
    parser.add_argument("--collect",   action="store_true", help="Run queries and tokenize")
    parser.add_argument("--local",     action="store_true", help="Fully local — collect + classify + report")
    parser.add_argument("--reconcile", action="store_true", help="Reconcile AI findings and generate reports")
    parser.add_argument("--findings",  help="JSON file with AI findings (tokens + verdicts)")
    args = parser.parse_args()

    if args.local:
        if not args.org:
            sys.exit("--local requires --org")
        payload, tz = collect(args.org)
        print("\nClassifying locally...")
        findings = classify_locally(payload)
        reconcile_and_report(findings, tz, payload, org_label=args.org)

    elif args.collect:
        if not args.org:
            sys.exit("--collect requires --org")
        collect(args.org)
        print("\nNext: share anonymized_payload.json with Claude for analysis.")
        print("Then run: python3 audit.py --reconcile --findings <claude_findings.json>")

    elif args.reconcile:
        tz = Tokenizer()
        tz.load(TOKEN_MAP_FILE)
        with open(PAYLOAD_FILE) as f:
            payload = json.load(f)
        if args.findings:
            with open(args.findings) as f:
                findings = json.load(f)
        else:
            print("No findings file provided — running local classification.")
            findings = classify_locally(payload)
        reconcile_and_report(findings, tz, payload, org_label=args.org)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
