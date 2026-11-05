FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
ARG TARGETARCH
ARG SOURCE_DATE_EPOCH=1793836800
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /protocol
COPY build/debian /tmp/debian-locks
COPY scripts/install-debian.sh /tmp/install-debian.sh
RUN DEBIAN_FRONTEND=noninteractive sh /tmp/install-debian.sh /tmp/debian-locks/${TARGETARCH}.lock
COPY requirements.lock requirements-build.lock requirements-test.lock ./
RUN python -m pip install --only-binary=:all: --require-hashes --no-deps -r requirements.lock -r requirements-build.lock -r requirements-test.lock
COPY . .
RUN python -m pip install --no-deps --no-build-isolation . && python -m pip check
ENV PYTHONPATH=/protocol/reference/python
CMD ["python", "-m", "unittest", "discover", "-s", "tests", "-v"]
