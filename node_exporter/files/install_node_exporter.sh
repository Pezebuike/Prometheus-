#!/bin/bash

# Ansible-Ready Prometheus Node Exporter Installation Script
# Designed for deployment with Ansible roles
# Version is passed as required parameter
# Author: Auto-generated script
# Version: 4.0

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
readonly SCRIPT_NAME="$(basename "$0")"
readonly ARCH="linux-amd64"
readonly INSTALL_DIR="/usr/local/bin"
readonly SERVICE_USER="node_exporter"
readonly SERVICE_FILE="/etc/systemd/system/node_exporter.service"
readonly DEFAULT_PORT="9100"
readonly LOG_FILE="/tmp/node_exporter_install.log"

# Required parameters
VERSION=""
COMMAND="install"

# Default options
FORCE_INSTALL=false
SILENT_MODE=false
REMOVE_USER_ON_UNINSTALL=false

# Colors for output (disabled in silent mode)
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if [[ "$SILENT_MODE" == "true" ]] && [[ "$level" != "ERROR" ]]; then
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
        return
    fi
    
    case "$level" in
        "INFO")  echo -e "${GREEN}[INFO]${NC} $message" | tee -a "$LOG_FILE" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC} $message" | tee -a "$LOG_FILE" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" | tee -a "$LOG_FILE" ;;
        "DEBUG") echo -e "${BLUE}[DEBUG]${NC} $message" | tee -a "$LOG_FILE" ;;
    esac
}

# Error handler
error_exit() {
    log "ERROR" "$1"
    cleanup_on_failure
    exit 1
}

# Cleanup function for failed installations
cleanup_on_failure() {
    log "DEBUG" "Cleaning up after failed installation..."
    rm -f node_exporter-*.tar.gz 2>/dev/null || true
    rm -rf node_exporter-*/ 2>/dev/null || true
}

# Validate version format
validate_version() {
    if [[ -z "$VERSION" ]]; then
        error_exit "Version is required. Use --version X.X.X"
    fi
    
    if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        error_exit "Invalid version format: '$VERSION'. Expected format: X.X.X (e.g., 1.8.2)"
    fi
    
    log "INFO" "Using Node Exporter version: $VERSION"
}

# Check system requirements
check_requirements() {
    log "INFO" "Checking system requirements..."
    
    # Check if systemd is available
    if ! command -v systemctl &> /dev/null; then
        error_exit "systemctl not found. This script requires systemd."
    fi
    
    # Check if wget or curl is available
    if ! command -v wget &> /dev/null && ! command -v curl &> /dev/null; then
        error_exit "Neither wget nor curl found. Please install one of them."
    fi
    
    # Check architecture and set ARCH accordingly
    local machine_arch=$(uname -m)
    case "$machine_arch" in
        x86_64) 
            ARCH="linux-amd64"
            ;;
        aarch64|arm64) 
            ARCH="linux-arm64"
            log "INFO" "Detected ARM64 architecture, using $ARCH"
            ;;
        armv7l|armv6l)
            ARCH="linux-armv7"
            log "INFO" "Detected ARM v7/v6 architecture, using $ARCH"
            ;;
        *) 
            error_exit "Unsupported architecture: $machine_arch" 
            ;;
    esac
    
    # Check available disk space (need at least 50MB)
    local available_space=$(df /tmp | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 51200 ]]; then
        error_exit "Insufficient disk space. Need at least 50MB in /tmp"
    fi
    
    # Check if running with sufficient privileges
    if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
        error_exit "This script requires sudo privileges"
    fi
    
    log "INFO" "System requirements check passed (arch: $ARCH)"
}

# Check if Node Exporter is already installed
check_existing_installation() {
    if [[ -f "$INSTALL_DIR/node_exporter" ]]; then
        local current_version
        current_version=$("$INSTALL_DIR/node_exporter" --version 2>&1 | grep -o 'version [0-9.]*' | cut -d' ' -f2 || echo "unknown")
        log "INFO" "Node Exporter is currently installed (version: $current_version)"
        
        if [[ "$FORCE_INSTALL" == "false" ]]; then
            if [[ "$current_version" == "$VERSION" ]]; then
                log "INFO" "Target version $VERSION is already installed. Use --force to reinstall."
                exit 0
            else
                log "INFO" "Upgrading from version $current_version to $VERSION"
            fi
        else
            log "INFO" "Force install requested. Proceeding with installation of version $VERSION"
        fi
    else
        log "INFO" "Node Exporter not currently installed. Proceeding with fresh installation."
    fi
}

# Download Node Exporter
download_node_exporter() {
    log "INFO" "Downloading Node Exporter v$VERSION for $ARCH..."
    
    local download_file="node_exporter-${VERSION}.${ARCH}.tar.gz"
    local download_url="https://github.com/prometheus/node_exporter/releases/download/v${VERSION}/${download_file}"
    
    # Download with appropriate tool
    if command -v wget &> /dev/null; then
        if [[ "$SILENT_MODE" == "true" ]]; then
            if ! wget -q "$download_url" -O "$download_file"; then
                error_exit "Failed to download from $download_url"
            fi
        else
            if ! wget --progress=bar:force:noscroll "$download_url" -O "$download_file"; then
                error_exit "Failed to download from $download_url"
            fi
        fi
    else
        if [[ "$SILENT_MODE" == "true" ]]; then
            if ! curl -sL "$download_url" -o "$download_file"; then
                error_exit "Failed to download from $download_url"
            fi
        else
            if ! curl -L --progress-bar "$download_url" -o "$download_file"; then
                error_exit "Failed to download from $download_url"
            fi
        fi
    fi
    
    # Verify download
    if [[ ! -f "$download_file" ]] || [[ ! -s "$download_file" ]]; then
        error_exit "Download failed or file is empty: $download_file"
    fi
    
    # Basic file type verification
    if ! file "$download_file" | grep -q "gzip compressed"; then
        error_exit "Downloaded file is not a valid gzip archive"
    fi
    
    log "INFO" "Download completed successfully"
}

# Extract and install binary
install_binary() {
    log "INFO" "Extracting and installing binary..."
    
    local archive="node_exporter-${VERSION}.${ARCH}.tar.gz"
    local extract_dir="node_exporter-${VERSION}.${ARCH}"
    
    # Extract archive
    if ! tar -xzf "$archive"; then
        error_exit "Failed to extract archive: $archive"
    fi
    
    # Verify extraction
    if [[ ! -f "$extract_dir/node_exporter" ]]; then
        error_exit "node_exporter binary not found in extracted files"
    fi
    
    # Stop service if running
    if systemctl is-active --quiet node_exporter 2>/dev/null; then
        log "INFO" "Stopping existing node_exporter service..."
        sudo systemctl stop node_exporter
    fi
    
    # Backup existing binary if it exists
    if [[ -f "$INSTALL_DIR/node_exporter" ]]; then
        sudo cp "$INSTALL_DIR/node_exporter" "$INSTALL_DIR/node_exporter.backup.$(date +%s)"
        log "INFO" "Backed up existing binary"
    fi
    
    # Install binary
    sudo cp "$extract_dir/node_exporter" "$INSTALL_DIR/"
    sudo chmod +x "$INSTALL_DIR/node_exporter"
    sudo chown root:root "$INSTALL_DIR/node_exporter"
    
    # Verify installation
    if ! "$INSTALL_DIR/node_exporter" --version &>/dev/null; then
        error_exit "Binary installation verification failed"
    fi
    
    # Verify version matches what we expect
    local installed_version
    installed_version=$("$INSTALL_DIR/node_exporter" --version 2>&1 | grep -o 'version [0-9.]*' | cut -d' ' -f2)
    if [[ "$installed_version" != "$VERSION" ]]; then
        error_exit "Version mismatch. Expected: $VERSION, Got: $installed_version"
    fi
    
    log "INFO" "Binary installed successfully (version: $installed_version)"
}

# Create system user
create_user() {
    log "INFO" "Managing system user..."
    
    if id "$SERVICE_USER" &>/dev/null; then
        log "INFO" "User $SERVICE_USER already exists"
    else
        sudo useradd --no-create-home --shell /usr/sbin/nologin --system --user-group "$SERVICE_USER"
        log "INFO" "Created system user: $SERVICE_USER"
    fi
}

# Create systemd service
create_service() {
    log "INFO" "Creating systemd service..."
    
    # Backup existing service file if it exists
    if [[ -f "$SERVICE_FILE" ]]; then
        sudo cp "$SERVICE_FILE" "${SERVICE_FILE}.backup.$(date +%s)"
        log "INFO" "Backed up existing service file"
    fi
    
    sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=Prometheus Node Exporter
Documentation=https://prometheus.io/docs/guides/node-exporter/
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
User=$SERVICE_USER
Group=$SERVICE_USER
Type=simple
Restart=on-failure
RestartSec=5s
ExecStart=$INSTALL_DIR/node_exporter \\
    --web.listen-address=:$DEFAULT_PORT \\
    --path.procfs=/proc \\
    --path.sysfs=/sys \\
    --collector.filesystem.mount-points-exclude='^/(sys|proc|dev|host|etc|rootfs/var/lib/docker/containers|rootfs/var/lib/docker/overlay2|rootfs/run/docker/netns|rootfs/var/lib/docker/aufs)($$|/)'
ExecReload=/bin/kill -HUP \$MAINPID
TimeoutStopSec=20s
SendSIGKILL=no
KillMode=mixed
SyslogIdentifier=node_exporter

# Security measures
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictRealtime=true
RestrictSUIDSGID=true
RemoveIPC=true
RestrictNamespaces=true

[Install]
WantedBy=multi-user.target
EOF
    
    log "INFO" "Service file created with security hardening"
}

# Configure and start service
configure_service() {
    log "INFO" "Configuring and starting service..."
    
    sudo systemctl daemon-reload
    sudo systemctl enable node_exporter
    
    if ! sudo systemctl start node_exporter; then
        # Get service status for debugging
        local status_output
        status_output=$(sudo systemctl status node_exporter --no-pager 2>&1 || true)
        log "ERROR" "Service status: $status_output"
        error_exit "Failed to start node_exporter service"
    fi
    
    # Wait for service to be ready
    local timeout=30
    local count=0
    while ! systemctl is-active --quiet node_exporter && [[ $count -lt $timeout ]]; do
        sleep 1
        ((count++))
    done
    
    if [[ $count -ge $timeout ]]; then
        local status_output
        status_output=$(sudo systemctl status node_exporter --no-pager 2>&1 || true)
        log "ERROR" "Service status after timeout: $status_output"
        error_exit "Service failed to start within $timeout seconds"
    fi
    
    log "INFO" "Service started successfully"
}

# Health check
health_check() {
    log "INFO" "Performing health check..."
    
    # Check service status
    if ! systemctl is-active --quiet node_exporter; then
        error_exit "Service is not running"
    fi
    
    # Check if port is listening
    if ! ss -tlnp | grep -q ":$DEFAULT_PORT "; then
        error_exit "Service is not listening on port $DEFAULT_PORT"
    fi
    
    # Test metrics endpoint
    local test_cmd=""
    if command -v curl &> /dev/null; then
        test_cmd="curl -s --max-time 10"
    elif command -v wget &> /dev/null; then
        test_cmd="wget -qO- --timeout=10"
    fi
    
    if [[ -n "$test_cmd" ]]; then
        if ! $test_cmd "http://localhost:$DEFAULT_PORT/metrics" | grep -q "node_exporter_build_info"; then
            error_exit "Metrics endpoint is not responding correctly"
        fi
    fi
    
    log "INFO" "Health check passed - Node Exporter v$VERSION is running correctly"
}

# Cleanup temporary files
cleanup() {
    log "DEBUG" "Cleaning up temporary files..."
    rm -f node_exporter-*.tar.gz 2>/dev/null || true
    rm -rf node_exporter-*/ 2>/dev/null || true
}

# Installation function
install() {
    validate_version
    
    log "INFO" "Starting Node Exporter installation (version $VERSION)..."
    
    check_requirements
    check_existing_installation
    download_node_exporter
    install_binary
    create_user
    create_service
    configure_service
    health_check
    cleanup
    
    log "INFO" "Installation completed successfully!"
    log "INFO" "Node Exporter v$VERSION is now running on port $DEFAULT_PORT"
    
    if [[ "$SILENT_MODE" == "false" ]]; then
        show_status
    fi
}

# Uninstall function
uninstall() {
    log "INFO" "Uninstalling Node Exporter..."
    
    # Stop and disable service
    if systemctl is-enabled --quiet node_exporter 2>/dev/null; then
        sudo systemctl stop node_exporter 2>/dev/null || true
        sudo systemctl disable node_exporter 2>/dev/null || true
        log "INFO" "Service stopped and disabled"
    fi
    
    # Remove service file
    if [[ -f "$SERVICE_FILE" ]]; then
        sudo rm -f "$SERVICE_FILE"
        sudo systemctl daemon-reload
        log "INFO" "Service file removed"
    fi
    
    # Remove binary
    if [[ -f "$INSTALL_DIR/node_exporter" ]]; then
        sudo rm -f "$INSTALL_DIR/node_exporter"
        log "INFO" "Binary removed"
    fi
    
    # Remove user if requested
    if [[ "$REMOVE_USER_ON_UNINSTALL" == "true" ]]; then
        if id "$SERVICE_USER" &>/dev/null; then
            sudo userdel "$SERVICE_USER" 2>/dev/null || true
            log "INFO" "Removed user $SERVICE_USER"
        fi
    fi
    
    log "INFO" "Node Exporter uninstalled successfully"
}

# Status function
show_status() {
    echo
    echo "=== Node Exporter Status ==="
    echo "Service Status: $(systemctl is-active node_exporter 2>/dev/null || echo 'inactive')"
    echo "Service Enabled: $(systemctl is-enabled node_exporter 2>/dev/null || echo 'disabled')"
    echo "Port Status: $(ss -tlnp | grep ":$DEFAULT_PORT " &>/dev/null && echo 'listening' || echo 'not listening')"
    echo "Metrics URL: http://localhost:$DEFAULT_PORT/metrics"
    if [[ -f "$INSTALL_DIR/node_exporter" ]]; then
        echo "Version: $("$INSTALL_DIR/node_exporter" --version 2>/dev/null | head -n1 || echo 'unknown')"
    else
        echo "Version: not installed"
    fi
    echo
    echo "Management Commands:"
    echo "  Status:  sudo systemctl status node_exporter"
    echo "  Stop:    sudo systemctl stop node_exporter"
    echo "  Start:   sudo systemctl start node_exporter"
    echo "  Restart: sudo systemctl restart node_exporter"
    echo "  Logs:    sudo journalctl -u node_exporter -f"
    echo "  Test:    curl http://localhost:$DEFAULT_PORT/metrics"
}

# Usage function
usage() {
    cat << EOF
Usage: $SCRIPT_NAME --version X.X.X [OPTIONS] [COMMAND]

REQUIRED:
    --version VERSION   Node Exporter version to install (e.g., 1.8.2)

COMMANDS:
    install     Install Node Exporter (default)
    uninstall   Remove Node Exporter
    status      Show current status
    health      Perform health check
    help        Show this help

OPTIONS:
    --force             Force installation even if same version exists
    --silent            Silent mode - minimal output (suitable for automation)
    --remove-user       Remove service user during uninstall
    --port PORT         Custom port (default: $DEFAULT_PORT)

EXAMPLES:
    $SCRIPT_NAME --version 1.8.2                    # Install version 1.8.2
    $SCRIPT_NAME --version 1.8.2 --force --silent  # Force reinstall in silent mode
    $SCRIPT_NAME uninstall --remove-user            # Uninstall and remove user
    $SCRIPT_NAME status                              # Check status

ANSIBLE ROLE USAGE:
    - name: Install Node Exporter
      script: >
        $SCRIPT_NAME 
        --version {{ node_exporter_version }}
        --silent --force
      become: yes

LOGS:
    Installation logs are saved to: $LOG_FILE
EOF
}

# Parse command line arguments
parse_args() {
    if [[ $# -eq 0 ]]; then
        log "ERROR" "Version is required. Use --version X.X.X"
        usage
        exit 1
    fi
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version)
                if [[ -z "${2:-}" ]]; then
                    error_exit "Version value is required after --version"
                fi
                VERSION="$2"
                shift 2
                ;;
            --force)
                FORCE_INSTALL=true
                shift
                ;;
            --silent)
                SILENT_MODE=true
                shift
                ;;
            --remove-user)
                REMOVE_USER_ON_UNINSTALL=true
                shift
                ;;
            --port)
                if [[ -z "${2:-}" ]]; then
                    error_exit "Port value is required after --port"
                fi
                DEFAULT_PORT="$2"
                shift 2
                ;;
            install|uninstall|status|health|help|-h|--help)
                COMMAND="$1"
                shift
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Main function
main() {
    # Parse arguments
    parse_args "$@"
    
    # Initialize log file
    : > "$LOG_FILE"
    
    case "$COMMAND" in
        "install")
            install
            ;;
        "uninstall")
            uninstall
            ;;
        "status")
            show_status
            ;;
        "health")
            health_check
            log "INFO" "Health check completed successfully"
            ;;
        "help"|"-h"|"--help")
            usage
            ;;
        *)
            log "ERROR" "Unknown command: $COMMAND"
            usage
            exit 1
            ;;
    esac
}

# Trap for cleanup on script exit
trap cleanup EXIT

# Run main function with all arguments
main "$@"