FROM alpine:3.20 AS builder

RUN apk add git rust cargo
WORKDIR /app
RUN git clone https://github.com/thin-edge/thin-edge.io.git /app
RUN cargo build --release --bin tedge --features cryptoki

#---------------------------------------------
FROM ghcr.io/thin-edge/tedge-container-bundle:20250131.2034

# Match default tedge uid/gid used by Yocto images
ARG USERID=999
ARG GROUPID=992

USER root
RUN apk add --no-cache \
        sudo \
        p11-kit-server \
        gcompat \
        libgcc \
        shadow \
        # for debugging only
        gnutls-utils\ 
    && mkdir -p /etc/pkcs11/modules \
    && echo "module: /usr/lib/pkcs11/p11-kit-client.so" > /etc/pkcs11/modules/p11-kit-client.module

COPY --from=builder /app/target/release/tedge /usr/bin/tedge

# overwrite existing init script
COPY 50_configure.sh  /etc/cont-init.d/

ENV P11_KIT_SERVER_ADDRESS=unix:path=/p11-kit/pkcs11

ENV TEDGE_DEVICE_CRYPTOKI_ENABLE=true
ENV TEDGE_DEVICE_CRYPTOKI_MODULE_PATH=/usr/lib/pkcs11/p11-kit-client.so

# FIXME: Wrap pin in double quotes to prevent a parsing error
# which will be fixed by https://github.com/thin-edge/thin-edge.io/issues/3394
ENV TEDGE_DEVICE_CRYPTOKI_PIN="123456"
ENV TEDGE_MQTT_BRIDGE_BUILT_IN=true

# Control uid and gid to allow a non-root user
# access to sockets mounted into the container
RUN usermod -u "$USERID" tedge \
    && groupmod -g "$GROUPID" tedge \
    && chown -R tedge:tedge /data/tedge \
    && chown -R tedge:tedge /etc/tedge \
    && chown -R tedge:tedge /var/tedge

USER tedge
