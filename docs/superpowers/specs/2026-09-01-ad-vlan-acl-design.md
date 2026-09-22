# AD Authentication and VLAN ACL Design

## Scope

Implement on `zohdi/dhcp_pxe_web_manager` **main branch only**. Do not touch the default/autodeploy branch or alter the existing DHCP subnet configuration.

## Roles

- **Manager**: full application access. Local manager login remains available as a break-glass path. AD principals may also be assigned Manager through the ACL store.
- **VLAN Editor**: authenticated through AD/PAM and can view/add/edit/delete DHCP reservations only when the reservation IP belongs to one of the editor's assigned VLAN CIDRs.
- **Read Only**: retain the current local passwordless read-only login and global visibility; no mutations.

## Authentication

- Local manager authentication continues using bcrypt.
- AD authentication is performed through Linux PAM using `python-pam`; VAS remains responsible for the AD integration in the PAM stack.
- The PAM service is configurable and defaults to `login`.
- AD passwords are never stored.
- A successful AD authentication does not grant access unless an enabled ACL principal exists.

## Authorization

- VLAN ownership is defined in an application SQLite database as `VLAN name -> IPv4 CIDR` mappings. These mappings are authorization metadata only and never modify `dhcpd.conf` subnet blocks.
- The backend derives VLAN ownership from reservation IP addresses. The browser never chooses or asserts ownership.
- VLAN Editor list results are filtered server-side.
- Add checks the proposed IP.
- Edit checks both the current IP and proposed IP so a user cannot move a reservation across team boundaries.
- Delete checks the existing reservation IP before mutation.
- PXE/boot device changes, iPXE installation/snippet, DHCP restart, ACL management, and other global operations remain Manager-only.
- Read-only PXE queries remain available, but VLAN Editors may query only IPs within their assigned scopes.
- AD sessions are revalidated against the ACL database on every request so revocation/role changes take effect immediately.

## ACL Administration

Manager-only UI supports:
- Create/delete VLAN-to-CIDR authorization mappings.
- Create/update/delete AD aliases.
- Assign role Manager or VLAN Editor.
- Assign one or more VLANs to VLAN Editors.
- View recent audit records.

The shipped ACL database is **empty**. No AD alias is preconfigured.

## Audit

Record successful and denied security-sensitive actions including DHCP add/edit/delete and ACL changes. Do not record passwords.

## Safety / Compatibility

- Preserve local Manager and existing Read Only access when PAM/VAS is unavailable.
- Reject overlapping VLAN CIDRs to avoid ambiguous ownership.
- Keep generated SQLite DB out of version control.


## V1.1 Approved Amendment — Login UX + Boot Device

- `/login` is AD-first and contains only AD credentials plus Read Only and Local Manager navigation buttons.
- Local Manager authentication moves to `/local-manager-login`; the local Manager remains break-glass/full access.
- VLAN Editors may change a reservation's Boot Device only when the target IP is inside one of their assigned VLAN CIDRs. The backend must enforce the IP scope; hiding/disabling UI alone is insufficient.
- Read Only cannot change Boot Device.
- iPXE installation/snippet, DHCP restart, ACL administration, subnet configuration, and other global operations remain Manager-only.
