#!/bin/bash

# Simple Node Exporter Installation Script
# Installs Node Exporter binary and creates service user
# Version: 6.0

set -euo pipefail

# Default values
VERSION=""
PORT="9100"
FORCE="false"
SILENT="false"

# Configuration
INSTALL_DIR="/usr/local/bin"
SERVICE_USER="node_exporter"
ARCH="linux-amd64"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    
    if [[ "$SILENT" == "true" && "$level" != "ERROR" ]]; then
        return
    fi
    
    case "$level" in
        "INFO")  echo -e "${GREEN}[INFO]${NC} $message" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC} $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
    esac
}

# Error exit function
error_exit() {
    log "ERROR" "$1"
    exit 1
}

# Detect architecture
detect_arch() {
    local machine_arch=$(uname -m)
    case "$machine_arch" in
        x86_64)   ARCH="linux-amd64" ;;
        aarch64)  ARCH="linux-arm64" ;;
        armv7l)   ARCH="linux-armv7" ;;
        *)        error_exit "Unsupported architecture: $machine_arch" ;;
    esac
    log "INFO" "Detected architecture: $ARCH"
}

# Check requirements
check_requirements() {
    log "INFO" "Checking system requirements..."
    
    # Check for required commands
    if ! command -v wget >/dev/null && ! command -v curl >/dev/null; then
        error_exit "Neither wget nor curl found"
    fi
    
    # Check disk space (need at least 50MB)
    local available=$(df /tmp | awk 'NR==2 {print $4}')
    if [[ $available -lt 51200 ]]; then
        error_exit "Insufficient disk space in /tmp"
    fi
    
    log "INFO" "System requirements check passed"
}

# Download Node Exporter
download_node_exporter() {
    log "INFO" "Downloading Node Exporter v$VERSION..."
    
    local download_file="node_exporter-${VERSION}.${ARCH}.tar.gz"
    local download_url="https://github.com/prometheus/node_exporter/releases/download/v${VERSION}/${download_file}"
    
    cd /tmp
    
    if command -v wget >/dev/null; then
        if [[ "$SILENT" == "true" ]]; then
            wget -q "$download_url" -O "$download_file"
        else
            wget "$download_url" -O "$download_file"
        fi
    else
        if [[ "$SILENT" == "true" ]]; then
            curl -sL "$download_url" -o "$download_file"
        else
            curl -L "$download_url" -o "$download_file"
        fi
    fi
    
    if [[ ! -f "$download_file" || ! -s "$download_file" ]]; then
        error_exit "Download failed: $download_file"
    fi
    
    log "INFO" "Download completed"
}

# Install binary
install_binary() {
    log "INFO" "Installing Node Exporter binary..."
    
    local archive="node_exporter-${VERSION}.${ARCH}.tar.gz"
    local extract_dir="node_exporter-${VERSION}.${ARCH}"
    
    cd /tmp
    
    # Extract
    tar -xzf "$archive"
    
    if [[ ! -f "$extract_dir/node_exporter" ]]; then
        error_exit "node_exporter binary not found in archive"
    fi
    
    # Install
    sudo cp "$extract_dir/node_exporter" "$INSTALL_DIR/"
    sudo chmod +x "$INSTALL_DIR/node_exporter"
    sudo chown root:root "$INSTALL_DIR/node_exporter"
    
    # Verify
    if ! "$INSTALL_DIR/node_exporter" --version >/dev/null 2>&1; then
        error_exit "Binary installation verification failed"
    fi
    
    log "INFO" "Binary installed successfully"
}

# Create service user
create_user() {
    log "INFO" "Creating service user..."
    
    if id "$SERVICE_USER" >/dev/null 2>&1; then
        log "INFO" "User $SERVICE_USER already exists"
    else
        sudo useradd --no-create-home --shell /usr/sbin/nologin --system --user-group "$SERVICE_USER"
        log "INFO" "Created user: $SERVICE_USER"
    fi
}

# Cleanup
cleanup() {
    log "INFO" "Cleaning up..."
    cd /tmp
    rm -f node_exporter-*.tar.gz
    rm -rf node_exporter-*/
}

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version)
                VERSION="$2"
                shift 2
                ;;
            --port)
                PORT="$2"
                shift 2
                ;;
            --force)
                FORCE="true"
                shift
                ;;
            --silent)
                SILENT="true"
                shift
                ;;
            *)
                error_exit "Unknown option: $1"
                ;;
        esac
    done
    
    # Validate version
    if [[ -z "$VERSION" ]]; then
        error_exit "Version is required. Use --version X.X.X"
    fi
    
    if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        error_exit "Invalid version format: $VERSION"
    fi
}

# Main installation
main() {
    parse_args "$@"
    
    log "INFO" "Starting Node Exporter installation..."
    log "INFO" "Version: $VERSION"
    log "INFO" "Port: $PORT"
    
    detect_arch
    check_requirements
    download_node_exporter
    install_binary
    create_user
    cleanup
    
    log "INFO" "Installation completed successfully!"
    log "INFO" "Binary: $INSTALL_DIR/node_exporter"
    log "INFO" "User: $SERVICE_USER"
    log "INFO" "Configure service with your configuration management tool"
}

# Run main function
main "$@"