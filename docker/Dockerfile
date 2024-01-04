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
    && apk add make \
    && make $SVC \
    && mv build/cocos-$SVC /exe

FROM alpine:latest
RUN apk add qemu-system-x86_64
COPY --from=builder /exe /
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENTRYPOINT ["/exe"]
