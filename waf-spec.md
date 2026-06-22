# Cloudflare WAF Integration — Agent Harness Bypass & Hardening Spec

**Version:** 1.0.0  
**Date:** 2026-06-14  
**Classification:** Internal / Engineering

---

## 1. Overview & Problem Statement

When an AI agent interacts with a Cloudflare-protected endpoint, it encounters a multi-layered defence stack that inspects traffic at the TLS handshake level, the HTTP request level, the JavaScript execution level, and the behavioural level. Each layer generates signals that feed into a risk score. If the score exceeds a threshold, the request is challenged (CAPTCHA, JavaScript computation, or Turnstile), rate-limited, or outright blocked. For an agent harness builder, understanding these layers is critical both for making your own agents resilient when accessing third-party WAF-protected services, and for hardening your own APIs against adversarial traffic.

This specification document addresses two complementary goals. First, it details the known techniques by which automated agents can traverse or bypass Cloudflare WAF protections, based on current research from GitHub repositories, Reddit discussions, security blogs, and Cloudflare's own documentation. Second, it provides a concrete integration architecture that your agent harness can implement to gracefully handle WAF encounters, maintain session integrity, and operate within the boundaries of legitimate access. The spec also covers hardening your own API endpoints behind Cloudflare so that you can distinguish your own agents from malicious traffic.

---

## 2. How Cloudflare WAF Detects Agents

Cloudflare's bot detection engine is not a single check but a constellation of signals that are fused into a composite risk score. Understanding each signal is the prerequisite for building an agent that either avoids triggering them or handles the resulting challenges gracefully. The following subsections detail the primary detection vectors that an agent will face when communicating with a Cloudflare-protected origin.

### 2.1 TLS Fingerprinting (JA3/JA4)

When a client initiates a TLS handshake, it sends a ClientHello message that lists supported cipher suites, TLS extensions, elliptic curves, and signature algorithms in a specific order. Cloudflare computes a JA3 or JA4 fingerprint from this data. Real browsers (Chrome, Firefox, Safari) produce well-known fingerprints, while Python's `requests` library, Go's `net/http`, and other programmatic HTTP clients produce distinctly different fingerprints that are immediately flagged as non-browser traffic. This is often the very first filter applied, before any HTTP headers are even examined. The JA4+ suite extends fingerprinting to HTTP/2 settings and window sizes, making evasion even harder. If your agent's TLS fingerprint does not match a known browser, it will be scored as suspicious before any other signal is evaluated.

### 2.2 HTTP/2 Fingerprinting

Beyond TLS, Cloudflare inspects the HTTP/2 connection preface parameters: SETTINGS frame values (header table size, initial window size, max concurrent streams, etc.), WINDOW_UPDATE frame sizes, and the order of pseudo-headers (`:method`, `:authority`, `:scheme`, `:path`). Each browser has a unique HTTP/2 fingerprint. Libraries like Python's `httpx` or Go's `net/http` use default values that diverge significantly from any real browser profile. Cloudflare's JA4H fingerprint captures these settings, and a mismatch between the TLS fingerprint (claiming to be Chrome) and the HTTP/2 fingerprint (looking like a library) is an immediate red flag that triggers elevated scrutiny or blocking.

### 2.3 JavaScript Challenge & Cookie Verification

Cloudflare's JavaScript challenge requires the client to execute a computation-heavy JavaScript payload that sets a `cf_clearance` cookie. This cookie is then sent on subsequent requests to prove the client passed the challenge. The challenge itself is obfuscated and includes anti-debugging techniques. Browsers solve it automatically in under a second, but programmatic HTTP clients (`requests`, `httpx`, `aiohttp`) cannot execute JavaScript at all. Even headless browsers can fail if they are detected via WebDriver flags, missing DOM APIs, or performance characteristics that differ from a real browser. The `cf_clearance` cookie has a limited TTL (typically 30 minutes to a few hours), after which the challenge must be re-solved.

### 2.4 Turnstile CAPTCHA

Turnstile is Cloudflare's CAPTCHA replacement. It uses a combination of browser fingerprinting, mouse/keyboard event analysis, and a proof-of-work challenge. Unlike traditional image CAPTCHAs, Turnstile is mostly invisible to legitimate users but very difficult for automated agents. Turnstile can operate in three modes: **managed** (Cloudflare decides whether to challenge), **non-interactive** (proof-of-work only), and **interactive** (requires user action). For an agent harness, the managed and non-interactive modes are the primary targets for bypass, while interactive mode typically requires a CAPTCHA solving service.

### 2.5 IP Reputation & Datacenter Detection

Cloudflare maintains a global IP reputation database. Requests originating from known datacenter IP ranges (AWS, GCP, Azure, Hetzner, DigitalOcean) receive a higher risk score by default. Residential IPs are scored lower. This means that even if your agent perfectly mimics a browser at the TLS and HTTP levels, running from a datacenter IP can still result in challenges or blocks. Cloudflare's bot management also considers ASN (Autonomous System Number) reputation, so a fresh IP from a cloud provider with a history of abuse will be scored more harshly. This is one reason why proxy services offering residential IP rotation are popular for agents that need to access WAF-protected sites.

### 2.6 Behavioural Analysis & Rate Limiting

Cloudflare analyses the timing and pattern of requests. A human browsing a site will have irregular intervals, mouse movements, scroll events, and varied navigation paths. An agent that sends requests at precise intervals, follows a predictable crawl pattern, or hits many pages in rapid succession will be flagged. Rate limiting rules can be configured per IP, per ASN, per country, or per URI pattern. For an agent harness, this means implementing jitter (randomised delays), respecting rate limit headers (429 responses and `Retry-After`), and varying navigation patterns to avoid detection through behavioural fingerprinting.

### 2.7 Bot Management & Verified Bot Framework

Cloudflare's Bot Management product provides the `cf.bot_management.score` field (0–100, where lower means more likely a bot) and `cf.verified_bot_category` for known-good bots. Verified bots (like Googlebot, Bingbot) are whitelisted based on reverse DNS verification and IP ranges. Cloudflare's recently announced **Agent Registry** proposes a cryptographic verification system where agents can register and prove their identity beyond IP-based checks. For an AI agent harness, the path to becoming a verified bot involves registering with Cloudflare's Radar bot directory and implementing the Web Bot Auth protocol, which is the most legitimate and sustainable approach to WAF traversal.

---

## 3. Bypass Techniques: Research Findings

The following techniques have been identified through research across GitHub repositories, Reddit communities (r/webscraping, r/cybersecurity, r/Python), Stack Overflow, and security blogs. They are presented here for educational and engineering purposes, to inform the design of your agent harness. Each technique is rated by effectiveness, maintenance burden, and ethical considerations. The recommended approach for a production agent harness is to combine the legitimate access methods (Section 3.7–3.8) with graceful challenge handling (Section 3.3–3.4) rather than relying on evasion techniques.

### 3.1 TLS Fingerprint Impersonation (curl_cffi / curl-impersonate)

The **curl-impersonate** project provides patched versions of curl that mimic the TLS and HTTP/2 fingerprints of real browsers (Chrome 110+, Firefox 120+, Safari). The Python binding **curl_cffi** wraps this functionality, allowing agents to make requests that are indistinguishable from real browsers at the TLS level. This is the single most impactful technique because it addresses the first detection layer. Without TLS fingerprint impersonation, all other techniques are largely ineffective since the agent will be flagged at the handshake stage. The library supports impersonation targets like `chrome110`, `chrome120`, `safari15_5`, and `firefox120`. It integrates with async Python (asyncio) and supports proxy rotation, making it suitable for high-throughput agent workloads.

```bash
pip install curl_cffi
```

```python
from curl_cffi.requests import AsyncSession

async with AsyncSession(impersonate='chrome120') as s:
    r = await s.get('https://target-site.com')
```

**Effectiveness:** High for TLS-level detection. Does not solve JS challenges or Turnstile.  
**Maintenance:** Medium; Cloudflare periodically updates fingerprints, requiring library updates. The curl_cffi maintainers are responsive but there is always a lag between Cloudflare updates and library patches.

### 3.2 Stealth Browser Automation

When TLS impersonation alone is insufficient (e.g., the site requires JavaScript execution or Turnstile), a full browser automation approach is needed. Several tools have emerged to make automated browsers harder to detect. The key insight is that standard Selenium and Playwright installations are trivially detectable via the `navigator.webdriver` property, WebDriver-specific Chrome DevTools Protocol commands, and missing browser APIs.

| Tool | Language | Key Feature | Turnstile Support |
|------|----------|-------------|-------------------|
| undetected-chromedriver | Python | Patches ChromeDriver to remove detection flags | Partial |
| SeleniumBase (UC Mode) | Python | Built-in UC mode for undetected browsing | Yes |
| PyDoll | Python | CDP-based, no WebDriver binary, native CAPTCHA bypass | Yes (native) |
| Rebrowser | JS/TS | Patches for Puppeteer/Playwright anti-detection | Partial |
| puppeteer-extra-plugin-stealth | JS/TS | Evasion plugin for Puppeteer | Partial |
| Playwright Stealth | JS/TS | Evasion patches for Playwright | Partial |

**PyDoll** is particularly noteworthy for agent harness builders because it connects directly to the Chrome DevTools Protocol (CDP) over WebSocket, eliminating the WebDriver binary entirely. Since Cloudflare detects WebDriver connections, removing this dependency is a significant advantage. PyDoll also includes native bypass for Cloudflare Turnstile and reCAPTCHA v3, which means it can handle challenge pages without requiring an external CAPTCHA solving service. This makes it the most self-contained option for agents that need full browser capabilities.

**Effectiveness:** High for JS challenges and Turnstile (managed/non-interactive modes). Lower for interactive CAPTCHA.  
**Maintenance:** High; browser detection is an arms race and patches break frequently with browser updates. Running a full browser per agent is resource-intensive.

### 3.3 FlareSolverr (Challenge Solving Proxy)

**FlareSolverr** is a dedicated proxy server that sits between your agent and the target site. When a Cloudflare challenge is detected, FlareSolverr opens the URL in a headless Chromium instance with undetected-chromedriver, waits for the challenge to be solved, extracts the `cf_clearance` cookie, and returns it to the calling agent. The agent can then use this cookie for subsequent requests via a lightweight HTTP client (like curl_cffi), avoiding the overhead of running a browser for every request. FlareSolverr runs as a Docker container and exposes a simple REST API, making it easy to integrate into any agent harness regardless of programming language.

```bash
docker run -d -p 8191:8191 flaresolverr/flaresolverr
```

```json
POST http://localhost:8191/v1
{
  "cmd": "request.get",
  "url": "https://target.com",
  "maxTimeout": 60000
}
```

**Effectiveness:** Moderate to High for JS challenges. Often fails against Turnstile and interactive CAPTCHAs.  
**Maintenance:** Medium; the project has had periods of inactivity and may not keep up with Cloudflare updates. Best used as a fallback rather than a primary strategy.

### 3.4 CAPTCHA Solving Services

When Turnstile operates in interactive mode or when a site uses hCaptcha/reCAPTCHA, automated browser approaches may not suffice. CAPTCHA solving services provide an API where you submit the CAPTCHA parameters and receive a solution token. These services use a combination of AI models and human workers to solve challenges.

| Service | Turnstile Support | Avg. Solve Time | Pricing Model |
|---------|-------------------|-----------------|---------------|
| 2Captcha | Yes | 10–30s | Per solve ($2.99/1000) |
| CapSolver | Yes | 5–15s | Per solve ($0.8–2/1000) |
| CapMonster Cloud | Yes | 5–20s | Per solve ($1.6/1000) |
| SolveCaptcha | Yes | 8–25s | Per solve (varies) |

The integration pattern is: detect CAPTCHA on the page → extract the sitekey and page URL → send to the solving service → receive the token → inject it back into the page. For Turnstile specifically, the token is injected into a hidden input field and the callback function is triggered.

**Effectiveness:** High for interactive CAPTCHAs. Cost scales with usage. Adds latency (5–30 seconds per solve).

### 3.5 Proxy Rotation & Residential IPs

Since IP reputation is a major signal in Cloudflare's scoring, rotating through different IP addresses is essential for agents making many requests. Datacenter proxies are cheap but easily detected. Residential proxies are more expensive but much harder to flag because they originate from ISP-assigned IP ranges. Mobile proxies (4G/5G) offer the highest trust score but are the most expensive. The proxy rotation strategy should include:

- **Rotating IPs** after a configurable number of requests or time interval
- **Sticky sessions** that maintain the same IP for the duration of a `cf_clearance` cookie's validity
- **Geographic targeting** to match the agent's claimed location
- **Fallback chains** that switch proxy providers on failure

Key providers include Bright Data, Oxylabs, Smartproxy, and IPRoyal for residential, and cheaper datacenter providers for less protected targets.

### 3.6 Cookie Jar Management & Session Persistence

Once a Cloudflare challenge is solved (whether via browser automation, FlareSolverr, or manual intervention), the resulting `cf_clearance` cookie is valuable. A well-designed agent harness must persist these cookies across sessions and reuse them until they expire. This involves:

1. Serialising the cookie jar to disk or a database after each request
2. Checking cookie expiry before each request and proactively refreshing
3. Associating cookies with the specific IP address and User-Agent that generated them (Cloudflare validates cookie-to-IP-to-UA consistency)
4. Implementing a cookie refresh pipeline that solves challenges proactively before expiry
5. Isolating cookie jars per target domain to prevent cross-contamination

This technique alone can reduce challenge encounters by 80–90% once an initial session is established.

### 3.7 Cloudflare Agent Registry & Verified Bot Program

The most sustainable and legitimate approach is to register your agent with Cloudflare's emerging **Agent Registry**. Announced in 2025, the Agent Registry proposes a cryptographic verification system where agents can prove their identity using signed tokens rather than relying on IP-based whitelisting. This moves beyond the current Verified Bot program (which relies on reverse DNS and IP range verification) to a model where any agent can register, declare its purpose, and be granted access by origin servers that choose to allow it. The registry uses a proposed **Web Bot Auth** protocol where agents present a signed token in a standardised HTTP header. Origin servers can verify this token against the registry and make allow/deny decisions based on the agent's declared identity and purpose. For an agent harness, implementing this protocol is the recommended long-term strategy because it provides stable, legitimate access without the cat-and-mouse game of evasion techniques.

### 3.8 API-First Access & Authentication

The simplest bypass is not to bypass at all. If the target site offers a public API with authentication (API key, OAuth, JWT), use it. APIs are typically served from different infrastructure that does not go through the WAF's JavaScript challenge pipeline. Many sites that protect their web UI with Cloudflare leave their API endpoints either unprotected or protected only by rate limiting and authentication. If you control both the agent and the target (e.g., your own AI Voice Agent platform), design your architecture so that agents authenticate via API keys and communicate directly with your backend, bypassing the WAF entirely. Cloudflare Workers can also be used to create authenticated API routes that sit in front of your backend, providing WAF protection for unauthenticated traffic while allowing authenticated agents through.

---

## 4. Agent Harness Integration Architecture

This section defines the concrete architecture for integrating WAF traversal capabilities into your agent harness. The design follows a layered approach where each layer can be enabled or disabled independently, allowing you to tune the balance between stealth, performance, and cost for each target site.

### 4.1 Layer Architecture

The WAF integration module is structured as a stack of five layers, each responsible for a specific aspect of WAF traversal. Requests flow through the layers from top to bottom, and each layer can short-circuit the process if it successfully handles the request. This architecture ensures that the simplest and cheapest method is always tried first, escalating to more resource-intensive methods only when necessary.

| Layer | Name | Purpose | Cost |
|-------|------|---------|------|
| L0 | API-First | Use official API if available | Free |
| L1 | TLS Impersonation | Match browser TLS/HTTP2 fingerprint | Low |
| L2 | Session Reuse | Reuse `cf_clearance` cookies | Low |
| L3 | Challenge Solver | Automated browser solves JS/Turnstile | Medium |
| L4 | CAPTCHA Service | External solving for interactive CAPTCHA | High |

### 4.2 Core Module Interface

The WAF integration module exposes a unified interface that abstracts away the complexity of the layered approach. The agent harness calls a single request method, and the module handles all WAF-related logic internally. The interface is designed to be asynchronous and supports both single-request and batch-request patterns.

```python
class WAFIntegrationConfig:
    tls_impersonation: str = 'chrome120'         # curl_cffi target
    proxy_pool: ProxyPoolConfig = None           # proxy rotation settings
    cookie_store: CookieStoreConfig = None       # persistence backend
    challenge_solver: SolverConfig = None        # browser automation settings
    captcha_service: CAPTCHAServiceConfig = None # external solver
    rate_limit_rps: float = 2.0                  # max requests per second
    jitter_range_ms: tuple = (500, 3000)         # random delay range
    max_retries: int = 3                         # retry count per request
    challenge_timeout_s: int = 60                # max time for JS challenge


class WAFIntegration:
    async def request(self, url, method='GET', headers={},
                       body=None, max_retries=3) -> Response:
        """Single request with automatic WAF handling."""

    async def batch_request(self, urls, concurrency=5) -> List[Response]:
        """Batch requests with shared session and rate limiting."""

    async def refresh_session(self, domain: str) -> bool:
        """Proactively refresh cf_clearance before expiry."""

    def get_cookie(self, domain: str) -> Optional[str]:
        """Retrieve stored cookie for domain."""
```

### 4.3 Request Flow

Every request follows a deterministic flow through the layers. The flow is designed to minimise unnecessary resource usage while maximising the chance of successful WAF traversal. Below is the step-by-step decision tree that the WAF integration module follows for each request.

1. **Step 1:** Check if an official API endpoint exists for the target domain. If yes, route to L0 (API-First) and return the response directly.
2. **Step 2:** Check the cookie store for a valid, unexpired `cf_clearance` cookie for this domain. If found, attach it and proceed to L1 (TLS Impersonation).
3. **Step 3:** Make the request using `curl_cffi` with the configured impersonation target and proxy. Check the response status code.
4. **Step 4:** If response is 200, cache any new cookies and return the response. If response is 403 with Cloudflare challenge page, proceed to L3 (Challenge Solver).
5. **Step 5:** If response is 429 (rate limited), respect the `Retry-After` header, apply jitter, and retry after the specified delay. If no `Retry-After`, use exponential backoff starting at the configured jitter range.
6. **Step 6:** At L3, launch a browser automation instance (PyDoll or FlareSolverr) to solve the challenge. Extract the `cf_clearance` cookie and store it. Retry the original request with the new cookie.
7. **Step 7:** If L3 fails (e.g., interactive CAPTCHA detected), escalate to L4 (CAPTCHA Service). Send the CAPTCHA parameters to the configured service, inject the solution token, and retry.
8. **Step 8:** If all layers fail, log the failure with full context and return an error to the calling agent with a `WAFBlockError` exception containing the challenge type and response body.

### 4.4 Cookie Store Design

The cookie store is a critical component that must be thread-safe, persistent, and keyed by the combination of domain, IP address, and User-Agent string. Cloudflare validates that `cf_clearance` cookies are presented from the same IP and with the same User-Agent that originally solved the challenge. If any of these change, the cookie is rejected and a new challenge is triggered. The store must therefore maintain these associations and ensure that cookie lookups match on all three keys.

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | Target domain (e.g., `example.com`) |
| `cookie_name` | string | Always `cf_clearance` for Cloudflare |
| `cookie_value` | string | The `cf_clearance` token |
| `ip_address` | string | Proxy IP used when challenge was solved |
| `user_agent` | string | UA string used when challenge was solved |
| `expires_at` | datetime | Cookie expiry timestamp |
| `created_at` | datetime | When the challenge was solved |
| `challenge_type` | string | `js_challenge` \| `turnstile_managed` \| `turnstile_interactive` |

The recommended storage backends are: **Redis** for high-performance distributed setups, **SQLite** for single-node deployments, and an **in-memory LRU cache** for ephemeral sessions. Each backend must implement the same interface: `get(domain, ip, ua)`, `set(cookie_record)`, `delete(domain, ip, ua)`, and `cleanup_expired()`. The `cleanup_expired` method should run on a configurable interval (default: every 5 minutes) to remove expired cookies and prevent stale entries from causing challenge failures.

### 4.5 Proxy Pool Integration

The proxy pool manages a rotating set of proxy addresses with sticky session support. When a `cf_clearance` cookie is obtained through a specific proxy IP, subsequent requests to the same domain must use the same IP until the cookie expires. The pool must support:

1. **Random rotation** for initial requests
2. **Sticky assignment** when a cookie exists
3. **Health checking** to remove non-responsive proxies
4. **Geographic targeting** so that agents can appear to originate from specific countries
5. **Fallback chains** that automatically switch to a backup provider when the primary pool is exhausted or blocked

```python
class ProxyPoolConfig:
    providers: List[ProxyProvider]    # ordered by priority
    sticky_session_ttl: int = 1800   # match cf_clearance TTL
    health_check_interval: int = 300  # seconds between checks
    geo_target: Optional[str] = None  # ISO country code
    max_failures_before_rotate: int = 3
    proxy_type: str = 'residential'  # residential | datacenter | mobile
```

### 4.6 Rate Limiter & Jitter Engine

The rate limiter enforces a configurable maximum requests-per-second rate per domain, per IP, and globally. It also implements jitter to make request timing appear more human-like. The jitter engine adds a random delay drawn from a configurable distribution (uniform, Gaussian, or Poisson) between requests. The default configuration uses a uniform distribution between 500ms and 3000ms. Additionally, the rate limiter must respect Cloudflare's rate limit headers (429 status code and `Retry-After` header) and implement exponential backoff with a maximum backoff of 60 seconds. The limiter should also implement a cool-down period after consecutive rate limit responses, gradually reducing the request rate to avoid triggering progressively stricter limits.

---

## 5. Configuration Reference

This section provides the complete configuration schema for the WAF integration module. All settings are optional with sensible defaults. The configuration is designed to be loaded from a YAML or JSON file, allowing per-target overrides via a `targets` map.

```yaml
waf_integration:
  default:
    tls_impersonation: chrome120
    rate_limit_rps: 2.0
    jitter_range_ms: [500, 3000]
    max_retries: 3
    challenge_timeout_s: 60
    cookie_store:
      backend: redis
      redis_url: redis://localhost:6379/0
      cleanup_interval_s: 300
    proxy_pool:
      type: residential
      sticky_session_ttl: 1800
      geo_target: null
    challenge_solver:
      engine: pydoll          # pydoll | flaresolverr | seleniumbase
      headless: true
      flaresolverr_url: http://localhost:8191
    captcha_service:
      provider: null          # 2captcha | capsolver | null
      api_key: null
  targets:
    example.com:
      rate_limit_rps: 0.5
      jitter_range_ms: [2000, 8000]
      proxy_pool:
        geo_target: US
```

---

## 6. Hardening Your Own Endpoints

If your agent harness also exposes APIs (e.g., `/call`, `/transcribe`, `/tts`, `/agent`), you should protect them with Cloudflare WAF. This section describes the recommended WAF rule configuration for an AI voice agent or SaaS platform. The goal is to block malicious traffic while allowing your own authenticated agents through.

### 6.1 WAF Custom Rules

Create the following custom rules in your Cloudflare dashboard (Security > WAF > Custom Rules). These rules are ordered by priority, with the first matching rule taking effect.

| Priority | Rule Name | Expression | Action |
|----------|-----------|------------|--------|
| 1 | Allow Authenticated Agents | `http.request.uri.path in {"/api/v1/call" "/api/v1/tts"} AND http.request.headers["X-Agent-Token"] in {"<your-token>"}` | Allow |
| 2 | Block Known Bad ASNs | `ip.src.asn in {<list-of-abuse-ASNs>}` | Block |
| 3 | Rate Limit Agent Endpoints | `http.request.uri.path starts with "/api/" AND rate > 100 req/min` | Challenge |
| 4 | Block AI Scrapers | `cf.verified_bot_category in {"AI Crawler"} AND http.request.uri.path starts with "/api/"` | Block |
| 5 | Challenge Suspicious Bots | `cf.bot_management.score < 30` | Managed Challenge |

### 6.2 API Authentication Pattern

The recommended authentication pattern for your own agent endpoints is a **three-tier model**. Tier 1 is the Cloudflare WAF, which filters out the most obvious malicious traffic (bots, scrapers, known-abuse IPs). Tier 2 is the API gateway (e.g., Nginx or Kong), which validates API keys or JWT tokens and enforces rate limits at the application level. Tier 3 is your application backend, which performs fine-grained authorisation checks (e.g., is this agent allowed to access this specific resource?). This layered approach ensures that even if an attacker bypasses the WAF, they still need valid credentials and must respect application-level rate limits.

```
Internet → Cloudflare (WAF + Bot Mgmt) → Nginx/API Gateway (Auth + Rate Limit)
  → Backend (Authorisation + Input Validation) → LLM / Database
```

### 6.3 Bot Management Configuration

Enable Cloudflare Bot Management (the paid add-on) and configure the following settings:

- **Bot Fight Mode:** ON for automatic protection against known bots
- **AI Bot Block toggle:** ON to block AI crawlers in the verified bot directory's "AI Crawler" category
- **Super Bot Fight Mode:** Challenge requests with bot score < 30, block requests with bot score < 10
- **Session scoring:** Enabled so that Cloudflare builds a behavioural profile for each visitor over time, improving detection accuracy for sophisticated bots that pass initial checks

### 6.4 Allowlisting Your Own Agents

To ensure your own agents can reach your endpoints without being challenged, implement one of the following strategies:

- **Option A: X-Agent-Token header** — as described in the custom rules above. This is the simplest and most reliable method.
- **Option B: IP Access Rules** — add your agent's source IPs to a Cloudflare IP Access Rule with Allow action. This works if your agents run from known, static IP ranges.
- **Option C: Agent Registry** — implement the Cloudflare Agent Registry protocol (when available) to cryptographically verify your agent's identity. This is the most future-proof option.

For all options, ensure that your agents send a consistent `User-Agent` string that you can use in WAF rules for logging and debugging, even if you do not rely on it for authentication (since User-Agent is trivially spoofed).

---

## 7. Implementation Roadmap

This section provides a phased implementation plan for integrating the WAF module into your agent harness. Each phase builds on the previous one and can be deployed independently.

### 7.1 Phase 1: Foundation (Week 1–2)

- Implement the `WAFIntegration` core class with the `request`/`batch_request` interface
- Integrate `curl_cffi` with TLS impersonation (L1) and configurable proxy support
- Implement the in-memory cookie store with domain/IP/UA keying
- Add the rate limiter with jitter engine
- Write integration tests against a Cloudflare-protected test endpoint

### 7.2 Phase 2: Challenge Handling (Week 3–4)

- Integrate PyDoll as the primary challenge solver (L3)
- Add FlareSolverr as a fallback solver
- Implement the cookie persistence backend (Redis or SQLite)
- Add the proxy pool with sticky session support
- Implement the full request flow with all layer escalation logic

### 7.3 Phase 3: CAPTCHA & Scale (Week 5–6)

- Integrate a CAPTCHA solving service (L4) for interactive challenges
- Implement batch request mode with concurrent session management
- Add monitoring and metrics (challenge solve rate, cookie hit rate, retry count)
- Load test with 100+ concurrent agents against multiple target domains

### 7.4 Phase 4: Hardening & Registry (Week 7–8)

- Configure Cloudflare WAF rules for your own endpoints (Section 6)
- Implement the three-tier authentication model for your APIs
- Evaluate the Cloudflare Agent Registry for verified bot status
- Document the WAF integration module API for other teams
- Run red team exercises to validate both bypass and hardening effectiveness

---

## 8. Tools & Dependencies

| Tool | Purpose | Language | Status | GitHub |
|------|---------|----------|--------|--------|
| curl_cffi | TLS fingerprint impersonation | Python | Active | lexiforest/curl_cffi |
| PyDoll | CDP browser automation + CAPTCHA | Python | Active | autoscrape-labs/pydoll |
| FlareSolverr | Cloudflare challenge proxy | Any (REST) | Slow updates | FlareSolverr/FlareSolverr |
| undetected-chromedriver | Stealth Selenium | Python | Active | ultrafunkamsterdam/undetected-chromedriver |
| SeleniumBase | Full-featured test framework | Python | Active | seleniumbase/SeleniumBase |
| Rebrowser | Puppeteer/Playwright patches | JS/TS | Active | rebrowser/rebrowser-patches |
| 2Captcha | CAPTCHA solving service | Any (REST) | Active | 2captcha/2captcha-python |
| CapSolver | CAPTCHA solving service | Any (REST) | Active | capsolver/capsolver-python |

---

## 9. Risks & Ethical Considerations

Building WAF traversal capabilities into an agent harness carries significant responsibilities. This section outlines the key risks and ethical considerations that must be addressed before deploying such a system.

### 9.1 Legal Risk

Bypassing a website's security measures may violate the Computer Fraud and Abuse Act (CFAA) in the US, the Computer Misuse Act in the UK, or equivalent laws in other jurisdictions. Even if the intent is benign (e.g., legitimate research or authorised data collection), the act of circumventing access controls can be construed as unauthorised access. Always obtain explicit permission before accessing third-party sites, and prefer official APIs and data partnerships over web scraping. The techniques described in this document are intended for use on systems you own or have explicit authorisation to access.

### 9.2 Arms Race Risk

Cloudflare continuously improves its detection capabilities. Techniques that work today may stop working tomorrow. Investing heavily in evasion techniques creates a fragile system that requires constant maintenance. The most sustainable approach is to invest in the legitimate access paths (Agent Registry, API authentication, verified bot status) that provide stable, long-term access without the need for ongoing evasion work. Treat evasion techniques as a temporary bridge while you pursue legitimate access channels.

### 9.3 Resource Abuse Risk

An agent that bypasses WAF protections can consume server resources (CPU, GPU for LLM inference, database connections) without the target site's consent. This is particularly concerning for AI SaaS platforms where each API call may cost real money (LLM token costs, GPU time). Always implement rate limiting and respect the target site's capacity. If you control both the agent and the target, design your architecture to authenticate agents at the API gateway level so that unauthenticated traffic is blocked before it reaches expensive backend services.

### 9.4 Responsible Disclosure

If you discover a genuine vulnerability in Cloudflare's WAF (e.g., a bypass that affects all sites), report it through Cloudflare's bug bounty programme rather than exploiting it. Responsible disclosure helps improve the security ecosystem for everyone. The techniques described in this document are well-known and publicly discussed; they represent the current state of the art in agent-WAF interaction, not novel vulnerabilities.

---

## 10. References

- Cloudflare WAF Documentation: https://developers.cloudflare.com/waf/
- Cloudflare JA3/JA4 Fingerprinting: https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint
- Cloudflare Bot Management: https://developers.cloudflare.com/bots/get-started/bot-management
- Cloudflare Agent Registry Blog: https://blog.cloudflare.com/agent-registry
- Cloudflare Verified Bots Directory: https://radar.cloudflare.com/bots/directory
- curl_cffi Documentation: https://curl-cffi.readthedocs.io/
- PyDoll GitHub: https://github.com/autoscrape-labs/pydoll
- PyDoll CF WAF Bypasser Skills: https://github.com/Esonhugh/pydoll-cf-waf-bypasser-skills
- FlareSolverr GitHub: https://github.com/FlareSolverr/FlareSolverr
- Rebrowser Patches: https://github.com/rebrowser/rebrowser-patches
- GitLab Red Team — Bypassing Cloudflare Under Attack Mode: https://gitlab-com.gitlab.io/gl-security/security-tech-notes/red-team-tech-notes/cloudflare-notes
- Quarkslab — In WAF We Should Not Trust: https://blog.quarkslab.com/in-waf-we-should-not-trust.html
- Bright Data — Bypass Cloudflare Guide: https://brightdata.com/blog/web-data/bypass-cloudflare
- Scrapfly — Bypass Cloudflare Anti-Scraping: https://scrapfly.io/blog/posts/how-to-bypass-cloudflare-anti-scraping
- CapSolver — Cloudflare Blocking Your AI Agent: https://www.capsolver.com/blog/cloudflare/cloudflare-blocking-your-ai-agent-solution
- OpenAI ChatGPT Agent Allowlisting: https://help.openai.com/en/articles/11845367-chatgpt-agent-allowlisting

