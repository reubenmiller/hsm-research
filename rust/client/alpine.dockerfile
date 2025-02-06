FROM alpine:3.20 AS builder

RUN apk add rust cargo nfpm
WORKDIR /app
COPY . .
RUN cargo build --release


#---------------------------------------------
FROM alpine:3.20

RUN apk add --no-cache \
        sudo \
        openssl \
        p11-kit-server \
        gnutls \
        gnutls-utils \
        opensc \
        gcompat \
        libgcc \
    && mkdir -p /etc/pkcs11/modules \
    && echo "module: /usr/lib/pkcs11/p11-kit-client.so" > /etc/pkcs11/modules/p11-kit-client.module

COPY --from=builder /app/target/release/client /usr/bin/test-client
COPY entrypoint.sh /usr/bin/entrypoint.sh

ENV P11_KIT_SERVER_ADDRESS=unix:path=/run/pkcs11
ENV PKCS11_MODULE=/usr/lib/pkcs11/p11-kit-client.so

CMD [ "/usr/bin/entrypoint.sh" ]
