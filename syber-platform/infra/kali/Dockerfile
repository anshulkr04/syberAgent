# Self-contained Kali image: Claude Code (DeepSeek V4) + Syber platform + the full
# active-scanning toolchain + the agent-browser browser-automation CLI. Claude Code
# runs as a NON-ROOT user with permission prompts disabled (the container is the
# isolation boundary), so the agent operates autonomously.
#
# Build context = the syber-platform directory (so the package + baked workspace are
# copied in; see docker-compose.kali.yml).
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-c"]

# --- Scanning toolchain + browser (chromium pulls correct deps) + python -----
# Install chromium via apt rather than hand-listing X/GTK libs: Kali (Debian sid)
# did the time_t 64-bit transition (libasound2 -> libasound2t64, etc.), so the
# chromium package is the reliable way to get a working browser + all its deps.
# CORE tools — must all resolve (build fails loudly if any is missing).
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap nikto gobuster ffuf masscan nuclei sslscan whatweb \
      dnsutils whois netcat-traditional iproute2 \
      python3 python3-venv python3-pip \
      curl git ca-certificates jq xz-utils sudo \
      chromium fonts-liberation \
      exploitdb feroxbuster wafw00f hydra redis-tools \
 && rm -rf /var/lib/apt/lists/*
# Deep-verification tooling (Phase 8): exploitdb=searchsploit (CVE correlation),
# feroxbuster (recursive content discovery), wafw00f (WAF id), hydra + nuclei
# default-logins (credential verification), redis-tools (datastore probe). testssl.sh
# and git-dumper are fetched below (not reliably packaged).

# ENUMERATION tools + wordlists — BEST-EFFORT (a missing/renamed pkg must NOT fail the
# build; the Python layer degrades gracefully via _have()/wordlist fallback). Installed
# one-per-line so one bad name doesn't drop the rest. seclists = real content + DNS
# wordlists (raft-medium ~30k) so we're not stuck on the 81-path builtin.
RUN apt-get update && \
    for pkg in subfinder dnsx amass massdns puredns seclists; do \
      apt-get install -y --no-install-recommends "$pkg" \
        || echo "WARN: optional package '$pkg' unavailable — Syber degrades gracefully"; \
    done; \
    rm -rf /var/lib/apt/lists/*
# Fresh validated DNS resolvers for puredns (trickest); static fallback if the fetch fails.
RUN curl -fsSL -o /opt/resolvers.txt \
      https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
    || printf '1.1.1.1\n8.8.8.8\n8.8.4.4\n9.9.9.9\n1.0.0.1\n' > /opt/resolvers.txt

# --- testssl.sh (TLS audit) + vulners.nse (nmap CVE correlation) -------------
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
 && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh \
 && curl -fsSL -o /usr/share/nmap/scripts/vulners.nse \
      https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse \
 && nmap --script-updatedb 2>/dev/null || true

# Point agent-browser at the system chromium (no per-user Chrome download needed).
ENV AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium

# --- Node 20 + Claude Code + agent-browser ----------------------------------
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y nodejs \
 && npm install -g @anthropic-ai/claude-code agent-browser \
 && rm -rf /var/lib/apt/lists/*

# --- Non-root user (Claude Code disables permission prompts only as non-root) -
RUN useradd -m -s /bin/bash -u 1000 syber \
 && echo "syber ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/syber

# --- Python venv with the Syber platform ------------------------------------
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
COPY --chown=syber:syber . /opt/syber-platform
RUN /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/venv/bin/pip install --no-cache-dir -e /opt/syber-platform \
 && /opt/venv/bin/pip install --no-cache-dir mcp neo4j "psycopg[binary]" confluent-kafka pyyaml \
 && /opt/venv/bin/pip install --no-cache-dir agentmail \
 && /opt/venv/bin/pip install --no-cache-dir git-dumper arjun \
 && ln -sf /opt/venv/bin/git-dumper /usr/local/bin/git-dumper \
 && ln -sf /opt/venv/bin/arjun /usr/local/bin/arjun \
 && chown -R syber:syber /opt/venv

# --- Baked project workspace (project-level .claude/ + .mcp.json) ------------
RUN cp -r /opt/syber-platform/infra/kali/workspace /home/syber/workspace \
 && chown -R syber:syber /home/syber/workspace

# --- Durable engagement state (fleet checkpoint, etc.) -----------------------
# Pre-create + chown the state dir so a named volume mounted here (compose) is
# owned by the non-root 'syber' user and the fleet checkpoint persists across runs.
RUN mkdir -p /opt/syber-platform/.investigation_state \
 && chown -R syber:syber /opt/syber-platform/.investigation_state

USER syber
WORKDIR /home/syber/workspace
ENV HOME=/home/syber

# Templates are NOT prefetched (saves ~hundreds of MB); nuclei downloads them on
# its first run. To prefetch on a fat-disk host, run `nuclei -update-templates`.

COPY --chown=syber:syber infra/kali/entrypoint.sh /usr/local/bin/syber-entrypoint
USER root
RUN chmod +x /usr/local/bin/syber-entrypoint
USER syber

ENTRYPOINT ["/usr/local/bin/syber-entrypoint"]
CMD ["claude", "--dangerously-skip-permissions"]
