FROM debian:12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        sudo \
        ca-certificates \
        openssl \
        libengine-pkcs11-openssl \
        gnutls-bin \
        opensc \
    && mkdir -p /etc/pkcs11/modules \
    && echo "module: /usr/lib/aarch64-linux-gnu/pkcs11/p11-kit-client.so" > /etc/pkcs11/modules/p11-kit-client.module

COPY ./target/aarch64-unknown-linux-gnu/release/client /usr/bin/test-client
COPY entrypoint.sh /usr/bin/entrypoint.sh

ENV P11_KIT_SERVER_ADDRESS=unix:path=/run/pkcs11
ENV PKCS11_MODULE=/usr/lib/aarch64-linux-gnu/pkcs11/p11-kit-client.so

CMD [ "/usr/bin/entrypoint.sh" ]
