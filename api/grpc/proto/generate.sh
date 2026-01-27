#!/bin/bash
# Generate Go code from protobuf definitions

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

echo "Generating protobuf code from $SCRIPT_DIR..."

# Check if protoc is installed
if ! command -v protoc &> /dev/null; then
    echo "Error: protoc is not installed. Please install it first."
    echo "  macOS: brew install protobuf"
    echo "  Linux: apt-get install protobuf-compiler"
    exit 1
fi

# Check if protoc-gen-go-grpc is installed
if ! command -v protoc-gen-go-grpc &> /dev/null; then
    echo "Installing protoc-gen-go-grpc..."
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
fi

# Check if protoc-gen-go is installed
if ! command -v protoc-gen-go &> /dev/null; then
    echo "Installing protoc-gen-go..."
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
fi

# Create pb directory if it doesn't exist
mkdir -p "$SCRIPT_DIR/pb"

# Generate Go code
echo "Generating Go code..."
protoc \
    --go_out="$SCRIPT_DIR/pb" \
    --go-grpc_out="$SCRIPT_DIR/pb" \
    --go_opt=paths=source_relative \
    --go-grpc_opt=paths=source_relative \
    -I="$SCRIPT_DIR" \
    "$SCRIPT_DIR"/*.proto

echo "Generation complete!"
echo "Generated files in: $SCRIPT_DIR/pb/"

# List generated files
echo ""
echo "Generated files:"
ls -la "$SCRIPT_DIR/pb/"
