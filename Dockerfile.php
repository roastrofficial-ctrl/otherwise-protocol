FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
ARG TARGETARCH
WORKDIR /protocol
COPY build/debian /tmp/debian-locks
COPY scripts/install-debian.sh /tmp/install-debian.sh
RUN DEBIAN_FRONTEND=noninteractive sh /tmp/install-debian.sh /tmp/debian-locks/${TARGETARCH}.lock
COPY reference/php reference/php
COPY conformance/vectors.json conformance/vectors.json
CMD ["sh", "reference/php/check.sh"]
