# build container
FROM --platform=linux/amd64 golang:1.23-alpine AS build-env

# Build tools + typical deps to compile analyzers that spicyc generates
# + ca-certificates for HTTPS, + iptables, iptables-dev and libpcap-dev for glutton
RUN set -ex && apk add --no-cache \
    build-base \
    clang llvm \
    cmake \
    bison flex \
    zlib zlib-dev \
    iptables-dev libpcap-dev \
    git \
    bash curl ca-certificates

# Download the official Spicy (binary) Alpine tarball that matches your arch/version.
ARG SPICY_URL="https://github.com/zeek/spicy/releases/download/v1.14.0/spicy_linux_alpine_3_18.tar.gz"
ARG SPICY_SHA256=""

RUN set -eux; \
  test -n "$SPICY_URL"; \
  curl -fsSL "$SPICY_URL" -o /tmp/spicy.tar.gz; \
  if [ -n "$SPICY_SHA256" ]; then \
    echo "${SPICY_SHA256}  /tmp/spicy.tar.gz" | sha256sum -c -; \
  fi; \
  rm -rf /opt/spicy && mkdir -p /opt/spicy; \
  tar xf /tmp/spicy.tar.gz -C /opt/spicy --strip-components=3; \
  rm /tmp/spicy.tar.gz

ENV PATH="/opt/spicy/bin:$PATH"

# (Optional) Precompile headers to speed up C++ compilation of analyzers
RUN spicy-precompile-headers || true

# glutton build steps
RUN mkdir -p /opt/glutton
WORKDIR /opt/glutton

ADD go.mod go.sum ./

RUN go env && \
    GODEBUG=http2client=0 GOPROXY=${GOPROXY:-https://proxy.golang.org,direct} \
    go mod download -x

# RUN go mod download

ADD . .

RUN make build
RUN make spicy

# glutton run container with spicy parsers
FROM --platform=linux/amd64 alpine:3.21

RUN set -ex && apk add --no-cache zlib iptables iptables-dev libpcap-dev

RUN mkdir -p /opt/spicy

WORKDIR /opt/spicy

COPY --from=build-env /opt/spicy /opt/spicy

ENV PATH="/opt/spicy/bin:$PATH"

# (Optional) Precompile headers to speed up C++ compilation of analyzers
RUN spicy-precompile-headers || true

WORKDIR /opt/glutton

COPY --from=build-env /opt/glutton/protocols/spicy/parsers/*.h /opt/glutton/protocols/spicy/parsers/
COPY --from=build-env /opt/glutton/protocols/spicy/*.cc /opt/glutton/protocols/spicy/
COPY --from=build-env /opt/glutton/bin/server /opt/glutton/bin/server
COPY --from=build-env /opt/glutton/config /opt/glutton/config
COPY --from=build-env /opt/glutton/rules /opt/glutton/rules

CMD ["./bin/server", "-i", "eth0", "-l", "/var/log/glutton.log", "-d", "true"]
