# Queries

These files can be run manually via Salesforce CLI or Developer Console for one-off investigation.
They are simplified versions of the queries `audit.py` runs internally — see notes per file for differences.

Run via CLI:
```bash
sf data query --query "$(cat 01_admin_users.soql)" --target-org MyAlias
```

---

## 01_admin_users.soql

**What it does:** Returns all active users on the System Administrator profile.

**Downstream use:** Starting point for Wave 1 scope. These users must be using a FIDO2 key or passkey by July 1, 2026 or they get blocked at login.

**Note:** This file only matches the profile name `System Administrator` exactly.
`audit.py` extends this to also catch cloned profiles ("Super Admin", "IT Admin", etc.) by checking profile-level permissions directly:
```
Profile.PermissionsModifyAllData = true
OR Profile.PermissionsViewAllData = true
OR Profile.PermissionsCustomizeApplication = true
OR Profile.PermissionsAuthorApex = true
```
Use this file for a quick count. Use `audit.py` for a complete scope picture.

---

## 02_login_history.soql

**What it does:** Returns aggregated login patterns for System Administrator users over the last 30 days, grouped by login type, browser, and application.

**Downstream use:** The `LoginType` and `Browser` columns drive the break/exempt/conditional classification:
- `Application` + any browser → breaks
- `Other Apex API` → exempt
- `SAML Sfdc Initiated SSO` → conditional (depends on IdP AMR signal)
- `Remote Access 2.0` + `Unknown`/`Java` browser → exempt (headless)
- `Remote Access 2.0` + real browser → breaks

**Note:** This file uses a subquery scoped to System Administrator profile only.
`audit.py` runs the login history query against the union of admin users (Q1) and permission set sweep users (Q2), so it covers non-admin-profile users who hold elevated permissions via a permission set. If you run this file manually you will miss those users.

Also: `audit.py` removes `ApiType` from the SELECT and GROUP BY — it caused query failures in some orgs. If you see errors running this file, remove those columns.

---

## 03_permission_set_sweep.soql

**What it does:** Returns all active users who hold Modify All Data, View All Data, Customize Application, or Author Apex via a permission set or permission set group component — not via their profile.

**Downstream use:** Wave 1 scope is not limited to System Administrator profile. A user on a Standard User profile with a PS granting Modify All Data is equally in scope. This query surfaces those users.

`PermissionSet.IsOwnedByProfile = false` excludes the implicit permission set Salesforce creates for every profile (which would otherwise flood the results).

Permission set group members show up here automatically: Salesforce creates individual `PermissionSetAssignment` records for each component PS in a group, so PSG grants are caught without a separate query.

**Note:** `audit.py` also selects `Assignee.Id` and `PermissionSet.PermissionsApiUserOnly` which are not in this file. The Id is required for the login history lookup. Run this file to explore the permission landscape; use `audit.py` for the full audit.

---

## 04_integration_accounts.soql

**What it does:** Finds likely integration/service accounts by matching username or display name against common patterns (integration, api, boomi, conga, etc.).

**Downstream use:** Informational only. This query has no permission filter — most results will be out of Wave 1 scope entirely.

`audit.py` does not use this query. Instead it detects integration accounts **behaviorally**: if every login in the last 30 days is SOAP API or headless OAuth, the account is classified as exempt regardless of its name. This is more reliable — it catches accounts with generic names and avoids false positives from names that match the pattern but belong to human users.

Use this file if you want a starting point for a manual review of service accounts in your org, independent of the MFA audit.

---

## 05_psg_admin_check.soql

**What it does:** Lists permission set groups that contain a component permission set with admin-equivalent permissions (Modify All Data, View All Data, Customize Application, or Author Apex).

**Downstream use:** Helps you understand which PSGs put their members in Wave 1 scope. If a PSG appears here, every user assigned that PSG is in scope.

`audit.py` does not run this query separately. The permission set sweep (Q2 / `03_permission_set_sweep.soql`) already surfaces the individual users. Use this file when you want to see the PSG structure itself — e.g. to decide whether to restructure a PSG to remove the elevated component PS.
