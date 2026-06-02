FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY . .
RUN go build -mod=vendor -o /tpt-identity ./cmd/tpt-identity

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /tpt-identity /usr/local/bin/tpt-identity
ENTRYPOINT ["tpt-identity"]
CMD ["serve", "--config", "/etc/tpt-identity/config.yaml"]
