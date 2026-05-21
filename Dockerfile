# =============================================================================
# ARGUS Security — Dockerfile prod
# Image multi-stage : compile rien, télécharge les binaires Go et installe les
# dépendances Python via uv.
# =============================================================================

FROM python:3.12-slim AS base

# Dépendances système (libpcap pour naabu, unzip pour les archives, curl pour DL)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    libpcap-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# Étape 1 : Télécharger les binaires Go (ProjectDiscovery + ffuf)
# =============================================================================
WORKDIR /tools-tmp

# Versions alignées sur tools/install_tools.ps1
ARG SUBFINDER_VERSION=2.6.7
ARG HTTPX_VERSION=1.6.10
ARG NUCLEI_VERSION=3.3.7
ARG TLSX_VERSION=1.1.8
ARG NAABU_VERSION=2.3.3
ARG FFUF_VERSION=2.1.0
ARG DNSX_VERSION=1.2.2
ARG KATANA_VERSION=1.1.2

RUN set -eux; \
    # subfinder
    curl -sSL -o sf.zip "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" && unzip -q sf.zip && rm sf.zip; \
    # httpx
    curl -sSL -o hx.zip "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" && unzip -q hx.zip && rm hx.zip; \
    # nuclei
    curl -sSL -o nu.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" && unzip -q nu.zip && rm nu.zip; \
    # tlsx
    curl -sSL -o tx.zip "https://github.com/projectdiscovery/tlsx/releases/download/v${TLSX_VERSION}/tlsx_${TLSX_VERSION}_linux_amd64.zip" && unzip -q tx.zip && rm tx.zip; \
    # naabu (nécessite libpcap déjà installé)
    curl -sSL -o nb.zip "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_amd64.zip" && unzip -q nb.zip && rm nb.zip; \
    # ffuf
    curl -sSL -o ff.tgz "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" && tar -xzf ff.tgz && rm ff.tgz; \
    # dnsx
    curl -sSL -o dx.zip "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_amd64.zip" && unzip -q dx.zip && rm dx.zip; \
    # katana
    curl -sSL -o kt.zip "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_amd64.zip" && unzip -q kt.zip && rm kt.zip; \
    # Garde seulement les binaires
    mkdir -p /opt/argus-bin && \
    mv subfinder httpx nuclei tlsx naabu ffuf dnsx katana /opt/argus-bin/ && \
    chmod +x /opt/argus-bin/* && \
    /opt/argus-bin/subfinder -version && \
    /opt/argus-bin/httpx -version && \
    /opt/argus-bin/nuclei -version

# =============================================================================
# Étape 2 : Pré-charge les templates Nuclei (12k+ YAML, ~50MB)
# Évite un cold-start de 30s sur le premier scan
# =============================================================================
RUN /opt/argus-bin/nuclei -update-templates -silent || true

# =============================================================================
# Étape 3 : Installer uv (gestionnaire Python rapide d'Astral)
# =============================================================================
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    mv /root/.local/bin/uv /usr/local/bin/uv && \
    mv /root/.local/bin/uvx /usr/local/bin/uvx 2>/dev/null || true

# =============================================================================
# Étape 4 : Installer les dépendances Python
# =============================================================================
WORKDIR /app

# Copie d'abord SEULEMENT les fichiers de deps pour profiter du cache Docker
COPY pyproject.toml uv.lock /app/

# Installe les deps dans un venv système
RUN uv sync --frozen --no-dev

# =============================================================================
# Étape 5 : Copie de l'app
# =============================================================================

# Crée les dossiers persistants
RUN mkdir -p /app/data /app/logs /app/logs/emails /app/tools/bin

# Place les binaires Go aux endroits attendus par l'app
RUN cp /opt/argus-bin/* /app/tools/bin/

# Copie le code applicatif
COPY app/ /app/app/

# Variable d'env pour pointer vers les templates nuclei pré-chargés
ENV HOME=/root
ENV PYTHONUNBUFFERED=1
ENV DEBUG=0

# Port exposé
EXPOSE 8000

# Health check (utilisé par Coolify pour savoir si l'app est prête)
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8000/healthz || exit 1

# Lancement de l'app via uv
CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
