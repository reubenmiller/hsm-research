#!/bin/sh
set -e

PKCS11_URI="${PKCS11_URI:-"pkcs11:model=PKCS%2315%20emulated"}"

usage() {
    cat <<EOT >&2
Start MacOS demo on how to run the p11-kit server and access it from a container

$0 [--group <ID>] [--debug] [--uri <PKCS11_URI>]

FLAGS
  --group, -g <ID>      Group ID to use inside the container. By default the given container image will be used
                        to detect the appropriate value
  --device-id <ID>      Device id / common name. Used if the device certificate does not already exist
  --debug               Enable shell debugging (verbose output)
  --uri <PKCS_URI>      PKCS#11 URI to be used scope the host's PKCS#11 module
  --IMAGE <image>       Container image to use. Defaults to auto detected based on the host's OS

EXAMPLES

  $0 --uri "pkcs11:model=PKCS%2315%20emulated"
  # Start the demo and only serve tokens matching the given URI

EOT
}

DEVICE_ID="${DEVICE_ID:-tedge_hsm_test001}"

while [ $# -gt 0 ]; do
    case "$1" in
        -g|--group)
            CONTAINER_GROUP_ID="$2"
            shift
            ;;
        --uri)
            PKCS11_URI="$2"
            shift
            ;;
        --device-id)
            DEVICE_ID="$2"
            shift
            ;;
        --debug)
            set -x
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
    shift
done

check_dependency() {
    if ! command -V "$1" >/dev/null 2>&1; then
        echo "Error. Could not find $1. Please install it and try again" >&2
        exit 1
    fi    
}

check_dependency p11-kit
check_dependency docker

if ! docker ps >/dev/null 2>&1; then
    echo "Error. docker ps failed. Are you sure docker is running?" >&2
    exit 1
fi

if ! docker compose --help >/dev/null 2>&1; then
    echo "Error. docker compose failed. Please install it and try again" >&2
    exit 1
fi

prepare() {
    echo "Preparing setup" >&2

    # setup p11-kit server
    if command -V brew >/dev/null 2>&1; then
        mkdir -p "$(brew --prefix)/etc/pkcs11/modules"
        if [ ! -f "$(brew --prefix)/etc/pkcs11/modules/yk-pkcs11.module" ]; then
            echo "Adding the yk-pkcs11.module to $(brew --prefix)/etc/pkcs11/modules/" >&2
            cat <<EOT > "$(brew --prefix)/etc/pkcs11/modules/yk-pkcs11.module"
module: $(brew --prefix)/lib/libykcs11.dylib
priority: 1
EOT
        fi
    fi
}

# Run setup checks
prepare

echo "Stopping any previous p11-kit process" >&2
pkill "p11-kit" || echo "p11-kit was not previously running" >&2

# Set which container image to use
IMAGE=${IMAGE:-}
if [ -z "$IMAGE" ]; then
    HOST_ARCH=$(uname -m)
    case "$HOST_ARCH" in
        arm64|aarch64)
            IMAGE=ghcr.io/reubenmiller/experiment-tedge-container-bundle-arm64:latest
            ;;
        x86_64|amd64)
            IMAGE=ghcr.io/reubenmiller/experiment-tedge-container-bundle-amd64:latest
            ;;
        *)
            echo "Unsupported host CPU architecture" >&2
            exit 1
            ;;
    esac
fi

# docker pull "$IMAGE"
if [ -z "$CONTAINER_GROUP_ID" ]; then
    echo "Detecting group id used the container" >&2
    CONTAINER_GROUP_ID=$(docker run --rm -it "$IMAGE" sh -c 'id -g' | tr -d '\r')
fi
echo "Using GroupID for socket ownership: $CONTAINER_GROUP_ID" >&2

if ! grep -q 'IMAGE=.*' .env >/dev/null 2>&1; then
    echo "Setting container image in .env. IMAGE=$IMAGE"
    echo "IMAGE=$IMAGE" >> .env
fi

SOCKET_PATH="/tmp/pkcs11"
mkdir -p "$(dirname "$SOCKET_PATH")"

# Start p11-kit server in the background
SHELL_COMMANDS=$(p11-kit server --sh -n "$SOCKET_PATH" "$PKCS11_URI")
eval "$SHELL_COMMANDS"

echo "Changing p11-kit socket group ownership to match the container (requires sudo permission)" >&2
sudo chown ":${CONTAINER_GROUP_ID}" "$SOCKET_PATH"
sudo chmod g+rw "$SOCKET_PATH"

# Forward socket to colima vm
if command -V colima >/dev/null 2>&1; then
    echo "Forwarding p11-kit socket to colima (to enable mounting as docker volume)" >&2
    colima ssh -- sudo rm -rf "$SOCKET_PATH"
    colima ssh -- sudo mkdir -p "$(dirname "$SOCKET_PATH")"
    ssh \
        -fN \
        -i "/Users/$(whoami)/.colima/_lima/_config/user" \
        -R "${SOCKET_PATH}:${SOCKET_PATH}" \
        127.0.0.1 -p "$(colima ssh-config | grep Port | awk '{print $2}')"

    colima ssh -- sudo chown ":${CONTAINER_GROUP_ID}" "$SOCKET_PATH"
    colima ssh -- sudo chmod 660 "$SOCKET_PATH"
fi

docker compose up
