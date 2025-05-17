#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
BINARY_NAME="watcher" # Expected name of the Go binary after build
SOURCE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )" # Get script's directory
BUILD_SCRIPT="./build.sh"
GO_SOURCE_DIR="${SOURCE_DIR}/go"
INSTALL_PATH="/usr/local/bin/${BINARY_NAME}"
SERVICE_NAME="nomad-bpf-watcher.service"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"
DEFAULT_PORT="8080" # Default port if not provided by --port
DEFAULT_INTERFACE="eth0" # Default interface if not provided by --iface
DEFAULT_NOMAD_ADDR="http://127.0.0.1:4646" # Default Nomad address

# --- Argument Parsing ---
PORT="${DEFAULT_PORT}"
INTERFACE="${DEFAULT_INTERFACE}"
NOMAD_ADDR="${DEFAULT_NOMAD_ADDR}"
NOMAD_TOKEN="" # No default for token

# Function to display usage
usage() {
  echo "Usage: $0 [--port <port>] [--iface <interface>] [--nomad-addr <url>] [--nomad-token <token>]"
  echo "  --port         TCP port for the Go watcher program (default: ${DEFAULT_PORT})"
  echo "  --iface        Network interface for BPF program (default: ${DEFAULT_INTERFACE})"
  echo "  --nomad-addr   URL of the Nomad API (default: ${DEFAULT_NOMAD_ADDR})"
  echo "  --nomad-token  Nomad ACL token (required if ACLs are enabled)"
  exit 1
}


while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    --port)
      PORT="$2"
      shift; shift
      ;;
    --interface|--iface)
      INTERFACE="$2"
      shift; shift
      ;;
    --nomad-addr)
      NOMAD_ADDR="$2"
      shift; shift
      ;;
    --nomad-token)
      NOMAD_TOKEN="$2"
      shift; shift
      ;;
    --help|-h)
      usage
      ;;
    *)    # unknown option
      echo "Unknown option: $1"
      usage
      ;;
  esac
done

echo "--- Configuration ---"
echo "Go Watcher Port: ${PORT}"
echo "BPF Interface: ${INTERFACE}"
echo "Nomad Address: ${NOMAD_ADDR}"
echo "Nomad Token: ${NOMAD_TOKEN:+Set (value hidden)}" # Indicate if token is set without printing it
echo "Binary Name: ${BINARY_NAME}"
echo "Install Path: ${INSTALL_PATH}"
echo "Service Name: ${SERVICE_NAME}"
echo "---------------------"
echo

# --- Check for Root Privileges ---
if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root (or using sudo)"
   exit 1
fi

# --- Build Step ---
echo "--> Running build script (${BUILD_SCRIPT})..."
if [[ ! -f "${SOURCE_DIR}/${BUILD_SCRIPT}" ]]; then
    echo "Error: Build script '${BUILD_SCRIPT}' not found in ${SOURCE_DIR}."
    exit 1
fi
cd "${SOURCE_DIR}"
bash "${BUILD_SCRIPT}"
echo "--> Build complete."
echo

# Check if binary exists after build
COMPILED_BINARY_PATH="${GO_SOURCE_DIR}/${BINARY_NAME}"
if [[ ! -f "${COMPILED_BINARY_PATH}" ]]; then
    echo "Error: Compiled binary '${BINARY_NAME}' not found in ${GO_SOURCE_DIR} after build."
    echo "Please check the build script and Go source."
    exit 1
fi

# --- Installation Step ---
echo "--> Stopping existing service (if running) before replacing binary..."
systemctl stop "${SERVICE_NAME}" || true # Stop the service first, ignore error if not running

echo "--> Installing binary '${BINARY_NAME}' to ${INSTALL_PATH}..."
mkdir -p "$(dirname "${INSTALL_PATH}")"
cp "${COMPILED_BINARY_PATH}" "${INSTALL_PATH}" # Now copy the file
chmod +x "${INSTALL_PATH}"
echo "--> Binary installed."
echo

# --- Systemd Service File Creation ---
echo "--> Creating systemd service file at ${SERVICE_FILE}..."

# Create the service file content using a heredoc
# Environment variables are now set directly line-by-line
cat << EOF > "${SERVICE_FILE}"
[Unit]
Description=Nomad BPF Watcher Service
After=network.target

[Service]
# Consider creating a dedicated user/group for security
# User=nomadwatcher
# Group=nomadwatcher

# Pass Nomad address and token as environment variables
# Use printf %q to safely quote the values
Environment="NOMAD_ADDR=$(printf '%q' "${NOMAD_ADDR}")"
$( [[ -n "${NOMAD_TOKEN}" ]] && printf 'Environment="NOMAD_TOKEN=%q"\n' "${NOMAD_TOKEN}" )

# Execute the watcher binary with port and interface flags
ExecStart=${INSTALL_PATH} -port ${PORT} -iface ${INTERFACE}

Restart=on-failure
RestartSec=5s

# Ensure Go program logs (stdout/stderr) go to journald
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "--> Service file created."
echo

# --- Systemd Configuration ---
echo "--> Configuring systemd..."
systemctl daemon-reload
echo "--> Enabling service to start on boot."
systemctl enable "${SERVICE_NAME}"
echo "--> Starting service..."
systemctl start "${SERVICE_NAME}"
echo "--> Service started."
echo

# --- Final Status ---
echo "--- Installation Complete ---"
echo "Nomad BPF Watcher has been installed and started as a systemd service."
echo "Nomad Address set to: ${NOMAD_ADDR}"
if [[ -n "${NOMAD_TOKEN}" ]]; then
  echo "Nomad Token has been set for the service."
else
  echo "Nomad Token was not provided; service will run without it."
fi
echo
echo "You can check the status using: systemctl status ${SERVICE_NAME}"
echo "Logs (including Go program stdout/stderr) can be viewed using: journalctl -u ${SERVICE_NAME}"
echo "To follow logs in real-time: journalctl -f -u ${SERVICE_NAME}"
echo "---------------------------"
echo "NOTE: If Go program logs are still missing, please verify the logging implementation within your Go application."

exit 0
