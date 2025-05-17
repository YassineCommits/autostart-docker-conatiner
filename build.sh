#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Define directories (optional)
PROJECT_ROOT=$(dirname "$(realpath "$0")") # Get dir where script is located
BPF_DIR="${PROJECT_ROOT}/bpf"
GO_DIR="${PROJECT_ROOT}/go"

# --- Build BPF ---
echo "INFO: Building BPF code in ${BPF_DIR}..."
cd "${BPF_DIR}"
make clean
make
echo "INFO: BPF code built successfully."

# --- Build Go ---
echo "INFO: Building Go code in ${GO_DIR}..."
cd "${GO_DIR}"
# Ensure bpf2go runs (embeds BPF object)
echo "INFO: Running go generate..."
go generate
# Build the final executable
echo "INFO: Running go build..."
go build -ldflags="-s -w" -o watcher .
echo "INFO: Go code built successfully. Executable: ${GO_DIR}/watcher"

# --- Done ---
cd "${PROJECT_ROOT}"
echo "INFO: Build complete!"
echo ""
# --- How to Run ---
echo "INFO: To run the watcher:"
echo "INFO:   1. Set environment variables:"
echo "INFO:      export NOMAD_ADDR=\"http://<your-nomad>:4646\""
echo "INFO:      export NOMAD_TOKEN=\"<your-token>\""
echo "INFO:   2. Run with sudo -E (preserving environment) and specify interface/port:"
echo "INFO:      sudo -E ${GO_DIR}/watcher -iface <interface> -port <port>"
echo "INFO:      Example: sudo -E ${GO_DIR}/watcher -iface lo -port 4432"