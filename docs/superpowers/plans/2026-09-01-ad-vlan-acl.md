# AD VLAN ACL Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add AD/PAM authentication plus Manager/VLAN Editor/Read Only authorization with CIDR-scoped DHCP reservation control.

**Architecture:** Keep authentication, ACL persistence, and authorization policy in focused modules. Flask routes call the policy before every read/write and manager-only global operation. SQLite stores manager-owned VLAN mappings, AD principals, assignments, and audit events; the initial database contains no principals or VLAN mappings.

**Tech Stack:** Python 3, Flask, bcrypt, sqlite3, ipaddress, python-pam/Linux PAM/VAS.

**Spec:** `docs/superpowers/specs/2026-09-01-ad-vlan-acl-design.md`

## Global Constraints

- Work from GitHub `main` only; do not touch the default/autodeploy branch.
- VLAN Editor never changes DHCP subnet configuration or PXE/global settings.
- Initial ACL is empty.
- Local Manager and current Read Only paths continue working if PAM/VAS is unavailable.
- Authorization is enforced server-side using reservation IP -> configured VLAN CIDR.

---

### Task 1: ACL persistence

**Files:** Create `access_control.py`; Test `tests/test_access_control.py`.

**Interfaces:** `ACLStore`, `ACLValidationError`, `ROLE_MANAGER`, `ROLE_VLAN_EDITOR`.

- [ ] Write failing tests for empty schema, CIDR validation/overlap, principal assignment, manager/editor IP access, cascade deletion, and audit log.
- [ ] Run tests and verify RED.
- [ ] Implement minimal SQLite ACL store.
- [ ] Run tests and verify GREEN.

### Task 2: Authorization policy

**Files:** Create `authorization.py`; Test `tests/test_authorization.py`.

**Interfaces:** `Identity`, `AuthorizationService.resolve_session`, `can_view_ip`, `can_edit_ip`, `filter_entries`.

- [ ] Write failing tests for Manager, Read Only, VLAN Editor filtering, and immediate AD ACL revocation.
- [ ] Run tests and verify RED.
- [ ] Implement policy.
- [ ] Run tests and verify GREEN.

### Task 3: PAM adapter

**Files:** Create `ad_auth.py`; Test `tests/test_ad_auth.py`.

**Interfaces:** `ADAuthenticator.authenticate(alias, password) -> ADAuthResult`.

- [ ] Write failing tests for missing PAM dependency, success, failure, and configurable service.
- [ ] Run tests and verify RED.
- [ ] Implement adapter using a fresh `pam.pam()` per authentication and `resetcreds=False`.
- [ ] Run tests and verify GREEN.

### Task 4: Flask integration and UI

**Files:** Modify `web.py`, `config.py`, `templates/login.html`, `templates/index.html`, `templates/add_edit.html`; Create `templates/access_control.html`, `templates/forbidden.html`, `requirements-auth.txt`, `data/.gitignore`, `README_AD_ACL.md`.

**Interfaces:** Flask sessions contain `role`, `username`, `auth_source`. AD sessions are re-resolved from ACL on each request.

- [ ] Replace Admin-only reservation CRUD guard with Manager-or-VLAN-Editor plus per-IP checks.
- [ ] Keep PXE/global/service/ACL operations Manager-only.
- [ ] Add AD login and Manager ACL UI.
- [ ] Compile Python files and run all local pure-module tests.

### Task 5: Packaging verification

- [ ] Confirm no SQLite database or AD alias is included.
- [ ] Confirm overlay contains only `main`-branch replacement/new files and documentation.
- [ ] Create ZIP and integrity-test it.


## V1.1 Follow-up

The approved follow-up changes the login landing page to AD-first with a separate local Manager page, and extends VLAN Editor write scope to the Boot Device selector for assigned VLAN CIDRs only. All global PXE/service/ACL operations remain Manager-only.
