# Hugging Face Space (Docker SDK). The Space repo only needs this file and
# README.md: the app itself is cloned from GitHub at build time, so pushing to
# GitHub and clicking "Factory rebuild" on the Space deploys the latest version.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Hugging Face runs containers as user 1000
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user PATH=/home/user/.local/bin:$PATH
WORKDIR /home/user/app

ARG REPO=https://github.com/yashdeep370/ThreatLens.git
ARG BRANCH=main
# The commit feed changes whenever the branch gets a new commit, so Docker doesn't
# reuse a stale clone (the feed isn't subject to the GitHub API's rate limit).
ADD --chown=user https://github.com/yashdeep370/ThreatLens/commits/main.atom /tmp/version.atom
RUN git clone --depth 1 --branch ${BRANCH} ${REPO} . \
    && pip install --no-cache-dir --user -r requirements.txt

# Public deployment mode: per-visitor sessions + rate limits.
# API keys (GEMINI_API_KEY / GROQ_API_KEY) come from the Space's secrets.
ENV THREATLENS_MULTI_USER=1 PYTHONUNBUFFERED=1
EXPOSE 7860
CMD ["python", "-m", "uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "7860", "--proxy-headers", "--forwarded-allow-ips", "*"]
