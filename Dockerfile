FROM ubuntu:24.04 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app
COPY CMakeLists.txt .
COPY src/ src/

RUN cmake -B build -S . -DCMAKE_BUILD_TYPE=Release\
    && cmake --build build

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3t64 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/build/cert_verifier /usr/local/bin/cert_verifier 
COPY certs/ /app/certs/

ENTRYPOINT ["cert_verifier"]
