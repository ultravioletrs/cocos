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

ENTRYPOINT ["/exe"]
