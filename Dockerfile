FROM golang:1.22-alpine AS builder

# Set build arguments
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Install build dependencies
RUN apk add --no-cache git tzdata ca-certificates

# Create non-root user for the final image
RUN addgroup -g 10001 appuser && \
    adduser -u 10001 -G appuser -h /app -D appuser

# Set working directory
WORKDIR /src

# Copy go.mod and go.sum
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application with version information
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s \
    -X main.version=${VERSION} \
    -X main.commit=${COMMIT} \
    -X main.buildDate=${BUILD_DATE}" \
    -o /app/auth-proxy ./cmd/main.go

# Copy default policies
RUN mkdir -p /app/policies && \
    cp -r policies/* /app/policies/

# Final stage
FROM alpine:3.19

# Add CA certificates
RUN apk --no-cache add ca-certificates tzdata

# Copy the binary from the builder stage
COPY --from=builder /app/auth-proxy /app/auth-proxy

# Copy default policies
COPY --from=builder /app/policies /policies

# Copy non-root user from builder
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Set ownership
RUN chown -R appuser:appuser /policies && \
    chmod -R 755 /policies

# Set environment variables
ENV PORT=8080 \
    POLICY_DIR=/policies \
    LOG_FORMAT=json

# Switch to non-root user
USER appuser

# Create volume for policies
VOLUME ["/policies"]

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the binary
ENTRYPOINT ["/app/auth-proxy"]