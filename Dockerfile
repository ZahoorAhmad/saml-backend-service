# Stage 1: Build
FROM golang:1.23-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o saml-backend ./cmd/server

# Stage 2: Runtime
FROM alpine:latest

WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/saml-backend .

EXPOSE 8080

CMD ["./saml-backend"]
