# Stage 1: Build the Go binary
FROM golang:1.26-alpine AS builder
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the generated eBPF bytecode and Go source code
COPY . .

# Build a statically linked binary (ignoring C files)
RUN CGO_ENABLED=0 GOOS=linux go build -o ebpf-observer .

# Stage 2: Create the minimal runtime image
FROM alpine:latest
WORKDIR /root/

# Copy the compiled binary from the builder stage
COPY --from=builder /app/ebpf-observer .

# Expose the Prometheus metrics port
EXPOSE 8080

# Execute the agent
CMD ["./ebpf-observer"]
