# Start from the official Go 1.22 image for the build stage
FROM golang:1.22 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application
# Use -ldflags="-w -s" to reduce binary size
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -a -installsuffix cgo -o basic-auth-sidecar ./cmd/server

# Start from Google's distroless Go image
# Note: As of my last update, there wasn't a specific distroless image for Go 1.22,
# so we're using the latest available distroless Go image.
FROM gcr.io/distroless/static-debian12:nonroot

# Copy the pre-built binary file from the previous stage
COPY --from=builder /app/basic-auth-sidecar /basic-auth-sidecar

# Expose port 8080
EXPOSE 8080

# Command to run the executable
CMD ["/basic-auth-sidecar"]