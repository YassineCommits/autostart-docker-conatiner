# Autostart docker container with Nomad BPF Watcher

This project uses eBPF (Extended Berkeley Packet Filter) to monitor network traffic for specific patterns (like TLS SNI on a given port) and interacts with a HashiCorp Nomad cluster based on the observed traffic.

The primary components are:
* An eBPF program (`bpf/nomad_watcher.bpf.c`) that attaches to a network interface and filters packets.
* A Go user-space application (`go/main.go`) that loads the eBPF program, reads events from it (via ring buffer or perf buffer), processes these events (e.g., extracts SNI), and communicates with the Nomad API.

## Prerequisites

Before building and running this project, ensure you have the following installed:

* **Go:** Version 1.18 or later (check with `go version`).
* **Clang & LLVM:** Required for compiling eBPF C code (check with `clang --version`).
* **libbpf Headers:** Development headers for libbpf (e.g., `libbpf-dev` or `libbpf-devel` package).
* **bpftool:** For generating `vmlinux.h` (often part of the kernel tools package, e.g., `linux-tools-common`, `linux-tools-$(uname -r)`).
* **Make:** For the BPF build process (check with `make --version`).
* **Linux Kernel:** Version 5.2 or later is generally recommended for the required eBPF features (TC BPF, ring buffer, BTF). BTF (BPF Type Format) support is needed for CO-RE features (`/sys/kernel/btf/vmlinux` should exist).
* **Nomad:** A running Nomad cluster accessible from where the watcher will run.

## Building

The project includes a build script that compiles both the eBPF C code and the Go application.

1.  **Clone the repository (if you haven't already):**
    ```bash
    git clone <your-repo-url>
    cd nomad-bpf-watcher
    ```
2.  **Run the build script:**
    ```bash
    ./build.sh
    ```
This script will:
* Clean and build the eBPF object file (`bpf/nomad_watcher.bpf.o`) using `make`.
* Generate necessary Go files from the BPF object file using `go generate` (likely using `bpf2go`).
* Build the Go executable (`go/watcher`).

## Installation (Systemd Service)

An installation script is provided to set up the watcher as a systemd service, allowing it to run reliably in the background.

1.  **Ensure the project is built:** Run `./build.sh` first.
2.  **Run the installation script with `sudo`:** You need to provide the network interface, the port for the Go application to listen on (distinct from the port being monitored by BPF, unless they serve the same purpose in your design), the Nomad API address, and optionally a Nomad token.

    ```bash
    sudo ./install.sh \
        --port <go_watcher_port> \
        --iface <network_interface> \
        --nomad-addr <nomad_api_url> \
        [--nomad-token <your_nomad_token>]
    ```

    **Example:**
    ```bash
    sudo ./install.sh \
        --port 5432 \
        --iface ens5 \
        --nomad-addr [http://10.0.4.10:4646](http://10.0.4.10:4646) \
        --nomad-token "0f6gfd0-dcfa-277b-fa82-481cfg2b91b8b1"
    ```

    The script will:
    * Copy the `watcher` binary to `/usr/local/bin/`.
    * Create a systemd service file (`/etc/systemd/system/nomad-bpf-watcher.service`) configured with the provided arguments and environment variables.
    * Reload systemd, enable the service to start on boot, and start the service immediately.

3.  **Check Service Status:**
    ```bash
    sudo systemctl status nomad-bpf-watcher.service
    ```

4.  **View Logs:**
    Logs from the Go application (stdout/stderr) are directed to the systemd journal.
    ```bash
    sudo journalctl -u nomad-bpf-watcher.service
    ```
    To follow logs in real-time:
    ```bash
    sudo journalctl -f -u nomad-bpf-watcher.service
    ```

## Manual Running (for Development/Debugging)

You can also run the watcher directly without installing it as a service. This is useful for development and debugging.

1.  **Ensure the project is built:** Run `./build.sh`.
2.  **Set Environment Variables:** The Go application likely reads Nomad connection details from environment variables.
    ```bash
    export NOMAD_ADDR="http://<your-nomad-addr>:4646"
    export NOMAD_TOKEN="<your-nomad-token>" # If needed
    ```
3.  **Run with `sudo -E`:** You need root privileges for eBPF operations, and `-E` preserves the environment variables you just set. Pass the required flags.
    ```bash
    sudo -E ./go/watcher -iface <interface> -port <bpf_monitored_port>
    ```
    **Example:**
    ```bash
    sudo -E ./go/watcher -iface ens5 -port 5432
    ```
    *(Note: Ensure the `-port` flag here corresponds to the port your BPF program is designed to monitor, which might be different from the `--port` used in the `install.sh` if that script's port argument is for a different purpose, like an internal API for the Go app itself).*

## Functionality Overview

1.  **Initialization:** The Go application starts, parses flags, and reads environment variables.
2.  **BPF Loading:** It loads the compiled eBPF program (`nomad_watcher.bpf.o`) into the kernel.
3.  **Map Configuration:** It updates eBPF maps with runtime configuration (e.g., the specific destination port to monitor).
4.  **Attaching:** It attaches the eBPF program to the specified network interface (`--iface`) using a suitable hook (e.g., TC clsact ingress/egress).
5.  **Event Monitoring:** It listens for events sent from the eBPF program via a ring buffer or perf buffer. These events likely contain packet metadata or payload prefixes for connections matching the BPF filter rules.
6.  **Event Processing:** When an event is received, the Go application processes it (e.g., attempts to parse TLS SNI from the payload).
7.  **Nomad Interaction:** Based on the processed event (e.g., a specific SNI is detected), the application interacts with the Nomad API (`NOMAD_ADDR`) using the provided token (`NOMAD_TOKEN`) to perform actions like checking job status, scaling jobs, etc.

## Troubleshooting

* **Permissions:** Most errors during startup relate to insufficient permissions. Ensure you run the installation script or the manual command with `sudo`. Check kernel logs (`dmesg`) for BPF verifier errors.
* **Dependencies:** Ensure all prerequisites are installed correctly. Missing headers (`vmlinux.h`, `libbpf`) are common issues.
* **Interface Name:** Double-check the network interface name (`ip addr`).
* **Nomad Connection:** Verify `NOMAD_ADDR` is correct and reachable. If ACLs are enabled, ensure `NOMAD_TOKEN` is valid and has the necessary permissions.
* **Logs:** Use `sudo journalctl -u nomad-bpf-watcher.service` for the systemd service. For manual runs, check the terminal output. Add more logging to the Go application if needed.
