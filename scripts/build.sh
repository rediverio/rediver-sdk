#!/bin/bash
# Build script for sdk

set -e

echo "Building sdk..."

# Build all packages
go build ./...

# Build CLI
go build -o bin/agent ./cmd/agent

echo "Build completed successfully!"
echo "Binary: bin/agent"
