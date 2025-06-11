#!/bin/bash

# This script sets up SSH keys and configuration for secure access to EC2 instances
# Usage: ./setup_ssh.sh [hostname_or_ip]

set -e  # Exit on any error

# # Variables
# SSH_DIR="$HOME/.ssh"
# SSH_CONFIG_FILE="$SSH_DIR/config"
# SSH_PRIVATE_KEY="$SSH_DIR/id_rsa"
# SSH_PUBLIC_KEY="$SSH_DIR/id_rsa.pub"
# SSH_AUTHORIZED_KEYS="$SSH_DIR/authorized_keys"

# # Function to print status messages
# print_status() {
#     echo "[INFO] $1"
# }

# print_status "Setting up SSH configuration for EC2 access..."

# # Create the .ssh directory if it doesn't exist
# if [ ! -d "$SSH_DIR" ]; then
#     print_status "Creating SSH directory..."
#     mkdir -p "$SSH_DIR"
# fi

# # Set correct permissions for SSH directory
# chmod 700 "$SSH_DIR"

# # Generate SSH key pair if it doesn't exist
# if [ ! -f "$SSH_PRIVATE_KEY" ]; then
#     print_status "Generating new SSH key pair..."
#     ssh-keygen -t rsa -b 4096 -f "$SSH_PRIVATE_KEY" -N "" -C "$(whoami)@$(hostname)-$(date +%Y%m%d)"
#     print_status "SSH key pair generated successfully"
# else
#     print_status "SSH key pair already exists"
# fi

# # Set correct permissions for SSH keys
# if [ -f "$SSH_PRIVATE_KEY" ]; then
#     chmod 600 "$SSH_PRIVATE_KEY"
# fi

# if [ -f "$SSH_PUBLIC_KEY" ]; then
#     chmod 644 "$SSH_PUBLIC_KEY"
# fi

# # Create authorized_keys file if it doesn't exist
# if [ ! -f "$SSH_AUTHORIZED_KEYS" ]; then
#     print_status "Creating authorized_keys file..."
#     touch "$SSH_AUTHORIZED_KEYS"
# fi

# # Add public key to authorized_keys if not already present
# if [ -f "$SSH_PUBLIC_KEY" ] && ! grep -Fq "$(cat "$SSH_PUBLIC_KEY")" "$SSH_AUTHORIZED_KEYS" 2>/dev/null; then
#     print_status "Adding public key to authorized_keys..."
#     cat "$SSH_PUBLIC_KEY" >> "$SSH_AUTHORIZED_KEYS"
# fi

# # Set correct permissions for authorized_keys
# chmod 600 "$SSH_AUTHORIZED_KEYS"

# # Create SSH config file if it doesn't exist
# if [ ! -f "$SSH_CONFIG_FILE" ]; then
#     print_status "Creating SSH config file..."
#     touch "$SSH_CONFIG_FILE"
# fi

# # Set correct permissions for SSH config
# chmod 600 "$SSH_CONFIG_FILE"

# # Add EC2 configuration to SSH config if not already present
# EC2_CONFIG="Host ec2-*
#     User ec2-user
#     IdentityFile ~/.ssh/id_rsa
#     StrictHostKeyChecking no
#     UserKnownHostsFile /dev/null
#     LogLevel ERROR
#     IdentitiesOnly yes"

# if ! grep -q "Host ec2-\*" "$SSH_CONFIG_FILE" 2>/dev/null; then
#     print_status "Adding EC2 configuration to SSH config..."
#     echo "" >> "$SSH_CONFIG_FILE"  # Add blank line
#     echo "# EC2 Instance Configuration" >> "$SSH_CONFIG_FILE"
#     echo "$EC2_CONFIG" >> "$SSH_CONFIG_FILE"
#     print_status "EC2 SSH configuration added"
# else
#     print_status "EC2 SSH configuration already exists"
# fi

# # If hostname/IP provided as argument, add specific host entry
# if [ $# -gt 0 ]; then
#     HOSTNAME="$1"
#     SPECIFIC_CONFIG="Host $HOSTNAME
#     User ec2-user
#     IdentityFile ~/.ssh/id_rsa
#     StrictHostKeyChecking no
#     UserKnownHostsFile /dev/null
#     LogLevel ERROR"
    
#     if ! grep -q "Host $HOSTNAME" "$SSH_CONFIG_FILE" 2>/dev/null; then
#         print_status "Adding specific host configuration for $HOSTNAME..."
#         echo "" >> "$SSH_CONFIG_FILE"
#         echo "# Specific EC2 Host: $HOSTNAME" >> "$SSH_CONFIG_FILE"
#         echo "$SPECIFIC_CONFIG" >> "$SSH_CONFIG_FILE"
#         print_status "Host-specific configuration added for $HOSTNAME"
#     else
#         print_status "Configuration for $HOSTNAME already exists"
#     fi
# fi

# print_status "SSH setup completed successfully!"
# print_status "Your public key is located at: $SSH_PUBLIC_KEY"

# # Display the public key for easy copying
# if [ -f "$SSH_PUBLIC_KEY" ]; then
#     echo ""
#     echo "=== Your Public Key (copy this to your EC2 instance) ==="
#     cat "$SSH_PUBLIC_KEY"
#     echo "======================================================="
#     echo ""
#     print_status "To use this key with your EC2 instance:"
#     print_status "1. Copy the public key above"
#     print_status "2. Add it to ~/.ssh/authorized_keys on your EC2 instance"
#     print_status "3. Or add it through the EC2 console when launching the instance"
    
#     if [ $# -gt 0 ]; then
#         echo ""
#         print_status "You can now connect using: ssh $1"
#     fi
# fi




# This script sets up SSH keys and configuration for secure access to an EC2 instance.
#!/bin/bash
cat >> ~/.ssh/confug << EOF
Host *
    user ec2-user
    IdentityFile ~/.ssh/id_rsa
    Hostname %h
EOF
# Create the .ssh directory if it doesn't exist
# mkdir -p ~/.ssh
# # Create the SSH configuration file if it doesn't exist
# if [ ! -f ~/.ssh/confug ]; then
#     touch ~/.ssh/confug
# fi  
# chmod 600 ~/.ssh/confug
# # Ensure the SSH directory and files have the correct permissions
# chmod 700 ~/.ssh
# chmod 600 ~/.ssh/id_rsa
# chmod 644 ~/.ssh/id_rsa.pub
# # Create the SSH key pair if it doesn't exist
# if [ ! -f ~/.ssh/id_rsa ]; then
#     ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
# fi
# # Add the public key to the authorized keys
# if [ ! -f ~/.ssh/authorized_keys ]; then
#     touch ~/.ssh/authorized_keys
# fi
# if ! grep -q "$(cat ~/.ssh/id_rsa.pub)" ~/.ssh/authorized_keys; then
#     cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
# fi
# # Ensure the authorized keys file has the correct permissions
# chmod 600 ~/.ssh/authorized_keys
# # Add the SSH configuration to the SSH config file
# if [ ! -f ~/.ssh/config ]; then
#     touch ~/.ssh/config
# fi
# if ! grep -q "Host *" ~/.ssh/config; then
#     echo "Host *
#     User ec2-user
#     IdentityFile ~/.ssh/id_rsa
#     Hostname %h" >> ~/.ssh/config
# fi
