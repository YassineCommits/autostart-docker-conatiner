#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status

echo "--- Starting Package Build for nomad-bpf-watcher ---"

# Flag to ensure apt-get update is run only once
APT_UPDATED=""

# Helper function to check for a dependency and install packages if not found
ensure_command_or_install_package() {
    local dep_name_to_check="$1" # This is what we're checking for (e.g., "make", "libelf.pc", "fpm-gem")
    shift
    local pkgs_to_install=("$@") # Remaining arguments are packages
    local dep_display_name="$dep_name_to_check"

    local is_installed=false

    # Determine how to check if the dependency is satisfied
    if [ "$dep_name_to_check" = "libelf.pc" ]; then
        # For libelf.pc, we check if pkg-config can find libelf
        if command -v pkg-config &> /dev/null && pkg-config --exists libelf &> /dev/null; then
            is_installed=true
        fi
    elif [ "$dep_name_to_check" = "fpm-gem" ]; then
        # For fpm-gem, we check for the 'fpm' command
        if command -v fpm &> /dev/null; then
            is_installed=true
        fi
    else
        # Default: check if it's a command in PATH
        if command -v "$dep_name_to_check" &> /dev/null; then
            is_installed=true
        fi
    fi

    if $is_installed; then
        echo "INFO: Dependency '$dep_display_name' is already satisfied."
        return 0
    fi

    # If not installed, proceed with installation attempt
    echo "INFO: Dependency '$dep_display_name' not found. Attempting to install required package(s): ${pkgs_to_install[*]}..."
    if [ -z "$APT_UPDATED" ]; then
        echo "INFO: Running apt-get update..."
        sudo apt-get update -y
        APT_UPDATED=true
    fi
    # Attempt to install system packages
    # For fpm-gem, pkgs_to_install might be empty if we intend to only use gem,
    # or it might contain prerequisites like ruby-dev, build-essential.
    if [ ${#pkgs_to_install[@]} -gt 0 ]; then
        sudo apt-get install -y "${pkgs_to_install[@]}"
    fi


    # Post-installation verification
    local installed_successfully=false
    if [ "$dep_name_to_check" = "libelf.pc" ]; then
        # Verify using pkg-config again after installation attempt
        if command -v pkg-config &> /dev/null && pkg-config --exists libelf &> /dev/null; then
            installed_successfully=true
        fi
    elif [ "$dep_name_to_check" = "fpm-gem" ]; then
        # Check if fpm command is available (might have been installed by system pkgs if specified, or needs gem)
        if command -v fpm &> /dev/null; then
            installed_successfully=true
        else
            echo "INFO: FPM command still not found. Attempting to install FPM via RubyGems..."
            # Ensure gem command is available
            if ! command -v gem &> /dev/null; then
                 echo "ERROR: 'gem' command not found. Cannot install FPM via RubyGems. Please install Ruby and RubyGems."
                 # pkgs_to_install for fpm-gem should have included ruby-full or similar
                 # If it didn't, this is an issue.
            else
                sudo gem install fpm --no-document # --no-document speeds it up
                if command -v fpm &> /dev/null; then
                    installed_successfully=true
                    echo "INFO: Successfully installed FPM via RubyGems."
                fi
            fi
        fi
    else
        # Default: check command again after apt-get install
        if command -v "$dep_name_to_check" &> /dev/null; then
            installed_successfully=true
        fi
    fi

    if $installed_successfully; then
        echo "INFO: Successfully installed/verified '$dep_display_name'."
    else
        echo "ERROR: Failed to install/verify '$dep_display_name'. Please install it manually and try again."
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# 0. Install Dependencies
# -----------------------------------------------------------------------------
echo "--> Checking and installing dependencies..."

# Core build tools
ensure_command_or_install_package "make" "make"
ensure_command_or_install_package "curl" "curl"

# Go (for building the watcher)
ensure_command_or_install_package "go" "golang-go"

# BPF related tools (Clang, LLVM, libelf, bpftool)
ensure_command_or_install_package "clang" "clang"
ensure_command_or_install_package "llvm-strip" "llvm"
ensure_command_or_install_package "pkg-config" "pkg-config" # Must be installed before checking libelf.pc
ensure_command_or_install_package "libelf.pc" "libelf-dev"   # Now uses pkg-config to check for 'libelf'

# bpftool installation attempt
if ! command -v bpftool &> /dev/null; then
    echo "INFO: bpftool not found, attempting to install via 'bpftool' package or 'linux-tools-generic'..."
    if [ -z "$APT_UPDATED" ]; then sudo apt-get update -y; APT_UPDATED=true; fi
    if sudo apt-get install -y bpftool; then
        echo "INFO: Successfully installed bpftool."
    elif sudo apt-get install -y "linux-tools-generic" "linux-tools-$(uname -r)"; then
        echo "INFO: Successfully installed bpftool via linux-tools."
    else
        echo "WARNING: Could not install bpftool automatically. The build might use a fallback for vmlinux.h."
    fi
else
    echo "INFO: Command 'bpftool' is already installed."
fi

# Ruby and FPM dependencies
ensure_command_or_install_package "ruby" "ruby-full"
ensure_command_or_install_package "gcc" "build-essential"

# FPM (Ruby Gem)
ensure_command_or_install_package "fpm-gem" # System packages for fpm itself are rare, gem is primary

# dpkg-dev for dpkg --print-architecture
ensure_command_or_install_package "dpkg-architecture" "dpkg-dev"


echo "--> Dependency check complete."
echo

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
WATCHER_BINARY_SRC="./go/watcher"
STAGING_DIR="./staging"

# -----------------------------------------------------------------------------
# 1. Build the application binary
# -----------------------------------------------------------------------------
echo "--> Building the watcher binary (via ./build.sh)..."
./build.sh
if [ ! -f "$WATCHER_BINARY_SRC" ]; then
    echo "ERROR: Watcher binary '$WATCHER_BINARY_SRC' not found after running ./build.sh."
    exit 1
fi
echo "--> Watcher binary build complete. Expected at: $WATCHER_BINARY_SRC"
echo

# -----------------------------------------------------------------------------
# 2. Create the necessary directory structure in staging
# -----------------------------------------------------------------------------
echo "--> Creating/ensuring staging directory structure in: $STAGING_DIR"
mkdir -p "$STAGING_DIR/usr/bin"
mkdir -p "$STAGING_DIR/etc/default"
mkdir -p "$STAGING_DIR/lib/systemd/system"
echo "--> Staging directory structure created/ensured."
echo

# -----------------------------------------------------------------------------
# 3. Create/Copy files into the staging directory
# -----------------------------------------------------------------------------
echo "--> Copying watcher binary to staging..."
cp "$WATCHER_BINARY_SRC" "$STAGING_DIR/usr/bin/watcher"
echo "--> Watcher binary copied."
echo

echo "--> Creating default config file in staging: $STAGING_DIR/etc/default/nomad-bpf-watcher"
cat << 'EOF' > "$STAGING_DIR/etc/default/nomad-bpf-watcher"
# Configuration for nomad-bpf-watcher service
# Edit these values as needed
IFACE="eth0"
PORT="4432"
NOMAD_ADDR="http://127.0.0.1:4646"
NOMAD_TOKEN=""
# WATCHER_OPTS=""
EOF
echo "--> Default config file created in staging."
echo

echo "--> Creating systemd service file in staging: $STAGING_DIR/lib/systemd/system/nomad-bpf-watcher.service"
cat << 'EOF' > "$STAGING_DIR/lib/systemd/system/nomad-bpf-watcher.service"
[Unit]
Description=Nomad BPF Watcher Service
After=network-online.target
# Wants=nomad.service
# After=nomad.service

[Service]
EnvironmentFile=-/etc/default/nomad-bpf-watcher
# User=nomadwatcher
# Group=nomadwatcher
ExecStart=/usr/bin/watcher -iface ${IFACE} -port ${PORT} ${WATCHER_OPTS}
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
# AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_BPF

[Install]
WantedBy=multi-user.target
EOF
echo "--> Systemd service file created in staging."
echo
echo "--> All necessary files are now in staging."
echo

# -----------------------------------------------------------------------------
# 4. Run the fpm command to build the Debian package
# -----------------------------------------------------------------------------
echo "--> Building the Debian package with fpm..."
fpm -s dir \
    -t deb \
    -n nomad-bpf-watcher \
    -v 0.1 \
    --iteration 1 \
    -a "$(dpkg --print-architecture)" \
    -m "Yassine Tbessi <yassine@guepard.run>" \
    --description "Nomad BPF Watcher Service for dynamic traffic control" \
    --url "https://guepard.run" \
    --vendor "Guepard" \
    --license "Apache-2.0" \
    --depends systemd \
    --depends libc6 \
    --config-files /etc/default/nomad-bpf-watcher \
    --deb-systemd "$STAGING_DIR/lib/systemd/system/nomad-bpf-watcher.service" \
    --exclude "lib/systemd/system/nomad-bpf-watcher.service" \
    -C "$STAGING_DIR" \
    usr etc lib

echo
echo "--- Package Build Complete ---"
ARCH=$(dpkg --print-architecture)
echo "Package created: nomad-bpf-watcher_0.1-1_${ARCH}.deb (or similar in the current directory)"

