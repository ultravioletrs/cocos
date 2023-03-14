FROM golang:1.16-alpine AS builder

WORKDIR /go/src/github.com/mainflux/agent
COPY . .
RUN CGO_ENABLED=0 GOARCH=amd64 \
  go build -mod=vendor -ldflags "-s -w" -o build/mainflux-agent cmd/agent/main.go \
  && mv build/mainflux-agent /exe

FROM scratch
COPY --from=builder /exe /
ENTRYPOINT ["/exe"]
