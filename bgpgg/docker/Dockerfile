FROM busybox:musl

ARG TARGETPLATFORM
ARG VERSION

RUN test -n "$TARGETPLATFORM" || (echo "TARGETPLATFORM is required" && exit 1)
RUN test -n "$VERSION" || (echo "VERSION is required" && exit 1)

WORKDIR /tmp/tarballs

# Copy all architecture tarballs
COPY rogg-*.tar.gz ./

# Select and extract the correct tarball based on target platform
RUN case "$TARGETPLATFORM" in \
      "linux/amd64") ARCH="x86_64-linux" ;; \
      "linux/arm64") ARCH="aarch64-linux" ;; \
      "linux/arm/v7") ARCH="armv7-linux" ;; \
      "linux/386") ARCH="i686-linux" ;; \
      *) echo "Unsupported platform: $TARGETPLATFORM" && exit 1 ;; \
    esac && \
    TARBALL="rogg-${VERSION}-${ARCH}.tar.gz" && \
    echo "Extracting $TARBALL for $TARGETPLATFORM" && \
    tar -xzf "$TARBALL" -C /usr/bin --strip-components=1

WORKDIR /root

CMD ["bgpggd"]

EXPOSE 179
