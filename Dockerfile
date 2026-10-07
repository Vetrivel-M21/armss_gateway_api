# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install git and build essentials if needed
RUN apk add --no-cache git ca-certificates tzdata

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and migrations
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY migrations/ ./migrations/

# Compile static binary for Linux
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /app/server ./cmd/server

# Final runtime image
FROM alpine:3.20

WORKDIR /app

# Install CA certificates for TLS/SMTP and tzdata for timezone support
RUN apk --no-cache add ca-certificates tzdata curl

# Copy binary and migrations from builder
COPY --from=builder /app/server /app/server
COPY --from=builder /app/migrations /app/migrations

# Create uploads directory and update directory
RUN mkdir -p /app/uploads /opt/armss

# Expose default port
EXPOSE 2092

# Run application
CMD ["/app/server"]
