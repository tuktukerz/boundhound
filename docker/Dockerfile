# --- builder: compile the Go recon tools at pinned versions ---
FROM golang:1.23-bookworm AS gotools
ENV CGO_ENABLED=0
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6 \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.9

# --- final: slim runtime with nmap + bridge utils + the Go binaries ---
FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl iputils-ping dnsutils ca-certificates nmap \
 && rm -rf /var/lib/apt/lists/*
COPY --from=gotools /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=gotools /go/bin/httpx    /usr/local/bin/httpx
# Phase 1: recon tools only (subfinder/httpx/nmap). No enum/exploit tooling yet.
WORKDIR /work
CMD ["sleep", "infinity"]
