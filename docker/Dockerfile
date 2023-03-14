FROM golang:1.16-alpine AS builder

WORKDIR /go/src/github.com/mainflux/manager
COPY . .
RUN CGO_ENABLED=0 GOARCH=amd64 \
  go build -mod=vendor -ldflags "-s -w" -o build/mainflux-manager cmd/manager/main.go \
  && mv build/mainflux-manager /exe

FROM scratch
COPY --from=builder /exe /
ENTRYPOINT ["/exe"]
