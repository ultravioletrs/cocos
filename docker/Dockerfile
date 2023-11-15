FROM golang:1.21-alpine AS builder
ARG SVC
ARG GOARCH
ARG GOARM
ARG VERSION
ARG COMMIT
ARG TIME

WORKDIR /go/src/github.com/ultravioletrs/cocos-ai
COPY . .
RUN apk update \
    && apk add make qemu-system-x86_64 \
    && make $SVC \
    && mv build/cocos-$SVC /exe

FROM scratch
# Certificates are needed so that mailing util can work.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/bin/qemu-system-x86_64 /usr/bin/qemu-system-x86_64
COPY --from=builder /exe /
ENTRYPOINT ["/exe"]
