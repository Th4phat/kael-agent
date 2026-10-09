FROM kalilinux/kali-rolling:latest

LABEL description="AI Agent Penetration Testing Environment with Comprehensive Automated Tools"

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y kali-archive-keyring sudo && \
    apt-get update && \
    apt-get upgrade -y

RUN useradd -m -s /bin/bash pentester && \
    usermod -aG sudo pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    touch /home/pentester/.hushlogin

RUN mkdir -p /home/pentester/tools && \
    chown -R pentester:pentester /home/pentester/tools

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget curl git vim nano unzip tar \
    apt-transport-https ca-certificates gnupg lsb-release \
    build-essential software-properties-common \
    gcc libc6-dev pkg-config libpcap-dev libssl-dev \
    python3 python3-pip python3-dev python3-venv python3-setuptools \
    golang-go \
    net-tools dnsutils whois \
    jq parallel ripgrep grep \
    less man-db procps htop \
    iproute2 iputils-ping netcat-traditional \
    nmap ncat ndiff \
    sqlmap nuclei subfinder naabu ffuf \
    nodejs pipx \
    libcap2-bin \
    gdb \
    libnss3-tools \
    chromium fonts-liberation


RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

# Create the shared application environment before any feature-specific
# Python packages are installed. Keep it owned by the unprivileged runtime
# user so later layers never need to install packages as root.
RUN python3 -m venv /app/.venv && \
    chown -R pentester:pentester /app/.venv

RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh

RUN curl -fsSL https://bun.sh/install | bash && \
    mv /root/.bun/bin/bun /usr/local/bin/bun && \
    ln -s /usr/local/bin/bun /usr/local/bin/bunx

USER pentester
WORKDIR /tmp

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/cvemap/cmd/vulnx@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest && \
    go clean -cache -modcache

RUN nuclei -update-templates

RUN pipx install arjun && \
    pipx install dirsearch && \
    pipx inject dirsearch 'setuptools<81' && \
    pipx install wafw00f

ENV BUN_INSTALL=/home/pentester/.bun
RUN mkdir -p /home/pentester/.bun/bin

RUN bun install -g retire@5.3.0 && \
    bun install -g eslint@10.4.1 && \
    bun install -g js-beautify@1.15.4 && \
    bun install -g @ast-grep/cli@0.38.7 && \
    bun install -g tree-sitter-cli@0.26.8 && \
    bun install -g --ignore-scripts agent-browser@0.27.3 && \
    node /home/pentester/.bun/install/global/node_modules/agent-browser/scripts/postinstall.js

ENV AGENT_BROWSER_EXECUTABLE_PATH=/usr/bin/chromium
ENV AGENT_BROWSER_USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
ENV AGENT_BROWSER_ARGS="--disable-blink-features=AutomationControlled,--no-first-run,--no-default-browser-check,--lang=en-US"
ENV AGENT_BROWSER_SCREENSHOT_DIR=/workspace/.agent-browser-screenshots
RUN /home/pentester/.bun/bin/agent-browser doctor --offline --quick

RUN set -eux; \
    TS_PARSER_DIR="/home/pentester/.tree-sitter/parsers"; \
    mkdir -p "${TS_PARSER_DIR}"; \
    for repo in tree-sitter-java tree-sitter-javascript tree-sitter-python tree-sitter-go tree-sitter-bash tree-sitter-json tree-sitter-yaml tree-sitter-typescript; do \
        if [ "$repo" = "tree-sitter-yaml" ]; then \
            repo_url="https://github.com/tree-sitter-grammars/${repo}.git"; \
        else \
            repo_url="https://github.com/tree-sitter/${repo}.git"; \
        fi; \
        if [ ! -d "${TS_PARSER_DIR}/${repo}" ]; then \
            git clone --depth 1 "${repo_url}" "${TS_PARSER_DIR}/${repo}"; \
        fi; \
    done; \
    if [ -d "${TS_PARSER_DIR}/tree-sitter-typescript/typescript" ]; then \
        ln -sfn "${TS_PARSER_DIR}/tree-sitter-typescript/typescript" "${TS_PARSER_DIR}/tree-sitter-typescript-typescript"; \
    fi; \
    if [ -d "${TS_PARSER_DIR}/tree-sitter-typescript/tsx" ]; then \
        ln -sfn "${TS_PARSER_DIR}/tree-sitter-typescript/tsx" "${TS_PARSER_DIR}/tree-sitter-typescript-tsx"; \
    fi; \
    tree-sitter init-config >/dev/null 2>&1 || true; \
    TS_CONFIG="/home/pentester/.config/tree-sitter/config.json"; \
    mkdir -p "$(dirname "${TS_CONFIG}")"; \
    [ -f "${TS_CONFIG}" ] || printf '{}\n' > "${TS_CONFIG}"; \
    TMP_CFG="$(mktemp)"; \
    jq --arg p "${TS_PARSER_DIR}" '.["parser-directories"] = ((.["parser-directories"] // []) + [$p] | unique)' "${TS_CONFIG}" > "${TMP_CFG}"; \
    mv "${TMP_CFG}" "${TS_CONFIG}"

WORKDIR /home/pentester/tools
RUN git clone https://github.com/aravind0x7/JS-Snooper.git && \
    chmod +x JS-Snooper/js_snooper.sh && \
    git clone https://github.com/xchopath/jsniper.sh.git && \
    chmod +x jsniper.sh/jsniper.sh && \
    git clone https://github.com/ticarpi/jwt_tool.git && \
    chmod +x jwt_tool/jwt_tool.py

USER root

RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
RUN set -eux; \
    ARCH="$(uname -m)"; \
    case "$ARCH" in \
        x86_64) GITLEAKS_ARCH="x64" ;; \
        aarch64|arm64) GITLEAKS_ARCH="arm64" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac; \
    TAG="$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name)"; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/${TAG}/gitleaks_${TAG#v}_linux_${GITLEAKS_ARCH}.tar.gz" -o /tmp/gitleaks.tgz; \
    tar -xzf /tmp/gitleaks.tgz -C /tmp; \
    install -m 0755 /tmp/gitleaks /usr/local/bin/gitleaks; \
    rm -f /tmp/gitleaks /tmp/gitleaks.tgz

# wsrx (WebSocketReflectorX) — tunnels raw TCP over a WebSocket, for CTF
# challenges reachable only through a ws:// / wss:// gateway. Upstream ships a
# Linux CLI for x86_64 only (static musl); skip cleanly on other arches.
ARG WSRX_VERSION=0.6.1
RUN set -eux; \
    if [ "$(uname -m)" = "x86_64" ]; then \
        curl -fsSL "https://github.com/XDSEC/WebSocketReflectorX/releases/download/${WSRX_VERSION}/wsrx-cli-${WSRX_VERSION}-linux-musl-x86_64.tar.gz" -o /tmp/wsrx.tgz; \
        tar -xzf /tmp/wsrx.tgz -C /usr/local/bin wsrx; \
        chmod +x /usr/local/bin/wsrx; \
        rm -f /tmp/wsrx.tgz; \
        wsrx --version; \
    else \
        echo "wsrx: no upstream Linux CLI for $(uname -m); skipping"; \
    fi

RUN apt-get update && apt-get install -y zaproxy

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

RUN apt-get install -y wapiti mitmproxy

USER pentester

RUN pipx install semgrep && \
    pipx install bandit

RUN bun install -g jshint@2.13.6

USER root

# === REVERSE ENGINEERING TOOLCHAIN ===
# Install RE tools (radare2 will be built from source)
RUN apt-get update && apt-get install -y --no-install-recommends \
    bubblewrap \
    iptables \
    tcpdump \
    strace \
    ltrace \
    binwalk \
    foremost \
    upx-ucl \
    yara \
    python3-yara \
    ssdeep \
    libfuzzy-dev \
    exiftool \
    file \
    wine64 \
    mono-runtime \
    default-jdk-headless \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install radare2 from source
RUN git clone --depth 1 https://github.com/radareorg/radare2 /tmp/radare2 && \
    cd /tmp/radare2 && \
    ./sys/install.sh --install --without-pull && \
    cd / && \
    rm -rf /tmp/radare2

USER pentester
RUN /app/.venv/bin/pip install --no-cache-dir 'setuptools<81' wheel six cffi && \
    /app/.venv/bin/pip install --no-cache-dir --no-build-isolation \
    'r2pipe>=1.9.4,<2' \
    'scapy==2.7.0' \
    'pefile==2024.8.26' \
    'pyelftools==0.33' \
    'ssdeep>=3.4,<4' \
    'py-tlsh>=4.7.2,<5' \
    'yara-python==4.5.4'
USER root

# Create directories for RE artifacts and rules
RUN mkdir -p /opt/yara-rules/{malware_families,techniques,crypto,packers} \
    /opt/kael-re \
    && chown -R pentester:pentester /opt/kael-re

# Copy YARA rules bundle
COPY --chown=pentester:pentester kael/tools/re_sandbox/yara_rules/ /opt/yara-rules/

# Copy RE runner script
COPY --chmod=755 kael/tools/re_sandbox/re_runner.py /opt/kael-re/re_runner.py

RUN apt-get autoremove -y && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.bun/bin:/app/.venv/bin:$PATH"
ENV VIRTUAL_ENV="/app/.venv"

WORKDIR /app

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

RUN mkdir -p /workspace && chown -R pentester:pentester /workspace /app

USER pentester
RUN /app/.venv/bin/pip install --no-cache-dir \
        'requests==2.32.5' && \
    /app/.venv/bin/pip install --no-cache-dir -r /home/pentester/tools/jwt_tool/requirements.txt && \
    printf '%s\n' \
        '#!/bin/bash' \
        'exec /app/.venv/bin/python /home/pentester/tools/jwt_tool/jwt_tool.py "$@"' \
        > /home/pentester/.local/bin/jwt_tool && \
    chmod +x /home/pentester/.local/bin/jwt_tool

COPY --chown=pentester:pentester kael/tools/proxy/mitm_addon.py /opt/kael-python/mitm_addon.py
COPY --chown=pentester:pentester kael/tools/proxy/mitm_control.py /opt/kael-python/mitm_control.py
COPY --chown=pentester:pentester kael/tools/proxy/sitemap.py /opt/kael-python/sitemap.py
COPY --chown=pentester:pentester kael/tools/proxy/scope_store.py /opt/kael-python/scope_store.py
ENV PYTHONPATH=/opt/kael-python

RUN echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.bun/bin:/app/.venv/bin:$PATH"' >> /home/pentester/.bashrc && \
    echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.bun/bin:/app/.venv/bin:$PATH"' >> /home/pentester/.profile

USER root
COPY containers/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER pentester
WORKDIR /workspace

ENTRYPOINT ["docker-entrypoint.sh"]
