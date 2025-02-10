#!/command/with-contenv sh
# shellcheck shell=sh
set -e
echo "Current User: $(whoami)"

MAX_CONNECT_ATTEMPTS=${MAX_CONNECT_ATTEMPTS:-5}
MAX_RANDOM_WAIT=${MAX_RANDOM_WAIT:-15}

DATA_DIR=${DATA_DIR:-/data/tedge}
# Use PERSIST_TEDGE_TOML=1 to enable creating a symlink for the /etc/tedge/tedge.toml
# to /data/tedge/tedge.toml, to allow persisting tedge.toml info across upgrades
PERSIST_TEDGE_TOML=${PERSIST_TEDGE_TOML:-1}

#
# device certificate loaders
#
load_from_env() {
    #
    # Load certificate (base64 encoded) from env variables
    #
    if [ -z "${CERTPRIVATE:-}" ] && [ -z "${CERTPUBLIC:-}" ]; then
        return 1
    fi
    echo "Loading device certificate from environment variables" >&2

    if [ -n "${CERTPRIVATE:-}" ]; then
        echo "Writing thin-edge.io private key from env 'CERTPRIVATE' (decoding from base64) to file" >&2
        CERT_FILE_KEY="$(tedge config get device.key_path)"
        printf '%s' "$CERTPRIVATE" | tr -d '"' | base64 -d > "$CERT_FILE_KEY"
        chmod 600 "$CERT_FILE_KEY"
    fi

    if [ -n "${CERTPUBLIC:-}" ]; then
        echo "Writing thin-edge.io private key from env 'CERTPUBLIC' (decoding from base64) to file" >&2
        CERT_FILE_PUB="$(tedge config get device.cert_path)"
        printf '%s' "$CERTPUBLIC" | tr -d '"' | base64 -d > "$CERT_FILE_PUB"
        chmod 644 "$CERT_FILE_PUB"
    fi
}

load_from_secrets() {
    #
    # Load certificates from docker secrets, see https://docs.docker.com/reference/cli/docker/secret/create/
    # Note: Due to permissions problems, copy the secrets from the /run read-only path to /etc/tedge/device-certs/
    #
    if [ ! -f /run/secrets/certificate_private_key ] || [ ! -f /run/secrets/certificate_public_key ]; then
        return 1
    fi

    echo "Loading device certificate from docker secrets" >&2

    CERT_FILE_KEY="$(tedge config get device.key_path)"
    cat /run/secrets/certificate_private_key > "$CERT_FILE_KEY"
    chmod 600 "$CERT_FILE_KEY"

    CERT_FILE_PUB="$(tedge config get device.cert_path)"
    cat /run/secrets/certificate_public_key > "$CERT_FILE_PUB"
    chmod 644 "$CERT_FILE_PUB"
}

load_from_file() {
    CERT_FILE_KEY="$(tedge config get device.key_path)"
    CERT_FILE_PUB="$(tedge config get device.cert_path)"

    if [ ! -f "$CERT_FILE_KEY" ] || [ ! -f "$CERT_FILE_PUB" ]; then
        return 1
    fi

    # Don't actually do anything, but confirm the presence of device certificates
    echo "Loading device certifcates from file (no-op)"
}

create_tedge_config_symlink() {
    # Store the tedge.toml under the data dir, and
    # use a symlink from /etc/tedge/tedge.toml to point to the data dir.
    # This enables users to retain customized tedge.toml files across container
    # updates
    DATA_DIR_TEDGE_TOML="$DATA_DIR/tedge.toml"
    ETC_TEDGE_TOML="/etc/tedge/tedge.toml"

    if [ ! -d "$DATA_DIR" ]; then
        echo "Warning: Data dir does not exist, so skipping creation of symlink under $DATA_DIR" >&2
        return 0
    fi

    if [ -L "$ETC_TEDGE_TOML" ]; then
        echo "tedge.toml symlink already exists. path=$ETC_TEDGE_TOML" >&2
        return 0
    fi

    # move any existing tedge.toml to data dir (if it does not already exist)
    if [ ! -f "$DATA_DIR_TEDGE_TOML" ]; then
        if [ -f "$ETC_TEDGE_TOML" ]; then
            echo "Moving existing tedge.toml file from $ETC_TEDGE_TOML to $DATA_DIR_TEDGE_TOML" >&2
            cp "$ETC_TEDGE_TOML" "$DATA_DIR_TEDGE_TOML"
            rm -f "$ETC_TEDGE_TOML"
        else
            echo "Creating empty file"
            touch "$DATA_DIR_TEDGE_TOML"
        fi
    fi

    echo "Creating symlink from $DATA_DIR_TEDGE_TOML to /etc/tedge/tedge.toml" >&2
    ln -sf "$DATA_DIR_TEDGE_TOML" "$ETC_TEDGE_TOML" || echo "Warning: Failed to create tedge.toml symlink" >&2
    echo "Successfully created tedge.toml symlink" >&2
}

############
# Main
############

if [ "$PERSIST_TEDGE_TOML" = 1 ]; then
    create_tedge_config_symlink
fi

# Create the agent state folder
AGENT_STATE=$(tedge config get agent.state.path)
mkdir -p "$AGENT_STATE"

#
# Try loading the device certificates from several locations, taking the first successful function
# Don't fail as users are allowed to start up a container without a device certificate (e.g. when only running the tedge-agent)
#
load_from_env || load_from_secrets || load_from_file ||:


# Support variable set by go-c8y-cli
if [ -n "$C8Y_DOMAIN" ] && [ -z "${TEDGE_C8Y_URL:-}" ]; then
    echo "Setting c8y.url from C8Y_DOMAIN env variable. $C8Y_DOMAIN" >&2
    tedge config set c8y.url "$C8Y_DOMAIN"
fi

random_sleep() {
    VALUE=$(awk "BEGIN { srand(); print int(rand()*32768 % $MAX_RANDOM_WAIT) }")
    echo "Sleeping ${VALUE}s" >&2
    sleep "$VALUE" 
}

#
# Connect the mappers (if they are configured and not already connected)
#
MAPPERS="c8y az aws"
for MAPPER in $MAPPERS; do
    if tedge config get "${MAPPER}.url" 2>/dev/null; then

        # Try a few 
        attempt=1
        while :; do
            if tedge reconnect "$MAPPER"; then
                echo "Successfully connected to $MAPPER" >&2
                break
            fi
            if [ "$attempt" -ge "$MAX_CONNECT_ATTEMPTS" ]; then
                echo "Couldn't connect to $MAPPER but continuing anyway" >&2
                break
            fi
            attempt=$((attempt + 1))
            random_sleep
        done
    fi
done

# Check which bridges are present
echo "--- mosquitto-conf directory ---" >&2
ls -l /etc/tedge/mosquitto-conf/
