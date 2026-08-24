# --- builder: compile the Go recon + enum tools at pinned versions ---
FROM golang:1.23-bookworm AS gotools
ENV CGO_ENABLED=0
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6 \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.9 \
 && go install github.com/ffuf/ffuf/v2@v2.2.1 \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1

# --- final: slim runtime with nmap + bridge utils + the Go binaries ---
FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl iputils-ping dnsutils ca-certificates nmap \
 && rm -rf /var/lib/apt/lists/*
COPY --from=gotools /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=gotools /go/bin/httpx    /usr/local/bin/httpx
COPY --from=gotools /go/bin/ffuf     /usr/local/bin/ffuf
COPY --from=gotools /go/bin/nuclei   /usr/local/bin/nuclei
# Bundled small wordlist for ffuf content discovery (no built-in generator).
COPY wordlists/common.txt /usr/share/boundhound/wordlists/common.txt
# Phase 1: recon tools (subfinder/httpx/nmap). Phase 2: enum tools (ffuf/nuclei).
WORKDIR /work
CMD ["sleep", "infinity"]
