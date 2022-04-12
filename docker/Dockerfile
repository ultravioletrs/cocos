FROM golang:1.18-alpine AS builder
ARG SVC
ARG GOARCH
ARG GOARM
ARG VERSION
ARG COMMIT
ARG TIME

WORKDIR /go/src/github.com/ultravioletrs/cocos
COPY . .
RUN apk update \
    && apk add make\
    && make $SVC \
    && mv build/cocos-$SVC /exe

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /exe /
ENTRYPOINT ["/exe"]
