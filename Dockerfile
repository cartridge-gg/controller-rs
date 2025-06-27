FROM ghcr.io/dojoengine/katana:v1.6.0-alpha.1

# Install build dependencies for Rust compilation including OpenSSL
RUN apt-get update && \
    apt-get install -y \
        build-essential \
        gcc \
        git \
        libssl-dev \
        pkg-config && \
    rm -rf /var/lib/apt/lists/*
