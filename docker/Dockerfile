FROM golang:1.16-alpine AS builder

WORKDIR /go/src/github.com/mainflux/mfxkit
COPY . .
RUN CGO_ENABLED=0 GOARCH=amd64 \
  go build -mod=vendor -ldflags "-s -w" -o build/mainflux-mfxkit cmd/mfxkit/main.go \
  && mv build/mainflux-mfxkit /exe

FROM scratch
COPY --from=builder /exe /
ENTRYPOINT ["/exe"]
