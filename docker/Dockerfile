FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl iputils-ping dnsutils ca-certificates \
 && rm -rf /var/lib/apt/lists/*
# Fase 0: HANYA alat uji jembatan. TIDAK ada tool pentest.
WORKDIR /work
CMD ["sleep", "infinity"]
