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
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap nikto gobuster ffuf masscan nuclei sslscan whatweb \
      dnsutils whois netcat-traditional iproute2 \
      seclists wordlists \
      python3 python3-venv python3-pip \
      curl git ca-certificates jq xz-utils sudo \
      chromium fonts-liberation fonts-noto-color-emoji \
 && rm -rf /var/lib/apt/lists/*

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
 && chown -R syber:syber /opt/venv

# --- Baked project workspace (project-level .claude/ + .mcp.json) ------------
RUN cp -r /opt/syber-platform/infra/kali/workspace /home/syber/workspace \
 && chown -R syber:syber /home/syber/workspace

USER syber
WORKDIR /home/syber/workspace
ENV HOME=/home/syber

# Prefetch nuclei templates so the first vuln scan is fast (best-effort).
RUN nuclei -update-templates >/dev/null 2>&1 || true

COPY --chown=syber:syber infra/kali/entrypoint.sh /usr/local/bin/syber-entrypoint
USER root
RUN chmod +x /usr/local/bin/syber-entrypoint
USER syber

ENTRYPOINT ["/usr/local/bin/syber-entrypoint"]
CMD ["claude", "--dangerously-skip-permissions"]
