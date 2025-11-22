#!/bin/bash

#
# This script builds and runs the Cobalt Strike Docker container.
#

# --- Configuration ---
# Name for the Docker image and container
DOCKER_IMAGE_NAME="cobaltstrike"
DOCKER_CONTAINER_NAME="cobaltstrike_server"
CONFIG_FILE=".env"

# --- Script Logic ---

# 1. Load or prompt for configuration
if [ -f "$CONFIG_FILE" ]; then
    echo "==> Found existing configuration file. Loading settings..."
    source "$CONFIG_FILE"
else
    echo "==> No configuration file found. Prompting for new settings..."
    # Prompt for License Key
    read -p "==> Enter Cobalt Strike License Key: " COBALTSTRIKE_LICENSE
    if [ -z "$COBALTSTRIKE_LICENSE" ]; then
        echo "Error: A license key is required."
        exit 1
    fi

    # Prompt for Team Server Password
    read -s -p "==> Enter Team Server Password: " TEAMSERVER_PASSWORD
    echo

    # Save to config file
    echo "==> Saving settings to $CONFIG_FILE for future runs..."
    (
        echo "COBALTSTRIKE_LICENSE="$COBALTSTRIKE_LICENSE""
        echo "TEAMSERVER_PASSWORD="$TEAMSERVER_PASSWORD""
    ) > "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
fi

# Validate that variables are set
if [ -z "$COBALTSTRIKE_LICENSE" ] || [ -z "$TEAMSERVER_PASSWORD" ]; then
    echo "Error: License key and password must be set."
    echo "Please check your $CONFIG_FILE or remove it to re-configure."
    exit 1
fi

# 2. Build the Docker image.
#    This will use the improved multi-stage Dockerfile.
echo "==> Building the Docker image ($DOCKER_IMAGE_NAME)..."
docker build --build-arg COBALTSTRIKE_LICENSE="$COBALTSTRIKE_LICENSE" -t "$DOCKER_IMAGE_NAME":latest .

# Check if the build was successful
if [ $? -ne 0 ]; then
    echo "Error: Docker image build failed."
    exit 1
fi

# 3. Detect the operating system and get the host's primary IP address.
OS="$(uname)"
if [[ "$OS" == "Linux" ]]; then
    IPADDRESS=$(hostname -I | awk '{print $1}')
elif [[ "$OS" == "Darwin" ]]; then # macOS
    IPADDRESS=$(ifconfig en0 | grep "inet " | awk '{print $2}')
else
    echo "Unsupported OS: $OS"
    exit 1
fi

if [ -z "$IPADDRESS" ]; then
    echo "Error: Could not determine the host IP address."
    exit 1
fi
echo "==> Detected Host IP: $IPADDRESS"

# 4. Set the Malleable C2 profile.
PROFILE_NAME=${1:-malleable.profile}
if [ ! -f "$PROFILE_NAME" ]; then
    echo "Error: Malleable C2 profile not found at: $(pwd)/$PROFILE_NAME"
    exit 1
fi
echo "==> Using Malleable C2 Profile: $PROFILE_NAME"

# 5. Run the Docker container.
echo "==> Starting Cobalt Strike Docker container ($DOCKER_CONTAINER_NAME)..."
docker rm -f "$DOCKER_CONTAINER_NAME" >/dev/null 2>&1 || true
docker run --name "$DOCKER_CONTAINER_NAME" \
  --mount type=bind,source="$(pwd)",target=/opt/cobaltstrike/mount \
  -p 50050:50050 \
  -p 80:80 \
  -p 443:443 \
  -p 53:53/udp \
  --rm \
  "$DOCKER_IMAGE_NAME":latest \
  "$IPADDRESS" \
  "$TEAMSERVER_PASSWORD" \
  "/opt/cobaltstrike/mount/$PROFILE_NAME"
