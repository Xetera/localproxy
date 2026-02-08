FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o localproxyd ./cmd/localproxyd

FROM alpine:latest

RUN apk --no-cache add ca-certificates netcat-openbsd

WORKDIR /root

COPY --from=builder /app/localproxyd /usr/local/bin/

COPY --from=builder /app/internal/dashboard/templates /root/internal/dashboard/templates

CMD sh -c "while true; do nc -l -p 9999; done & localproxyd --watch /"
