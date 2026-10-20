#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Local administrative install for one Linux host, from binaries already built
# in this checkout (scripts/build-linux-release.sh). No download, TUF or package.
#
#   sudo scripts/install-linux-local.sh install        # first install (interactive vault creation)
#   sudo scripts/install-linux-local.sh register-agent # after enrolling the agent in pm-tui
#   sudo scripts/install-linux-local.sh upgrade        # replace binaries, keep all state
#   sudo scripts/install-linux-local.sh status
#
# Layout follows docs/design/distribution.md (G8) and isolation.md (G1):
# root-owned release under /opt, dedicated `passwordmanager` service account,
# custody state in /var/lib/passwordmanager, sockets in /run/passwordmanager.
set -euo pipefail

SERVICE_USER=passwordmanager
AGENT_USER=${PM_AGENT_USER:-pm-agent}
OPT=/opt/passwordmanager
ETC=/etc/passwordmanager
STATE=/var/lib/passwordmanager
RUN=/run/passwordmanager
AGENT_HOME=/var/lib/$AGENT_USER
UNIT=/etc/systemd/system/passwordmanager.service
BINARIES=(pm pm-custody pm-web-auth pm-ssh-client pm-passkey-bridge)

die() { echo "error: $*" >&2; exit 1; }
say() { echo "==> $*"; }

[[ $(id -u) == 0 ]] || die "run with sudo"
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
human=${PM_HUMAN_USER:-${SUDO_USER:-}}
[[ -n "$human" && "$human" != root ]] || die "set PM_HUMAN_USER or run through sudo from the owner account"
human_home=$(getent passwd "$human" | cut -d: -f6)
human_uid=$(id -u "$human")
human_keys="$human_home/.config/passwordmanager"

as() { local user=$1; shift; runuser -u "$user" -- "$@"; }
custody() { "$OPT/current/bin/pm-custody" "$@"; }

install_release() {
    local release_id src dest
    release_id=$(git -C "$root" rev-parse --short=12 HEAD)
    git -C "$root" diff --quiet HEAD -- crates Cargo.toml Cargo.lock || release_id="$release_id-dirty"
    src="$root/target/release"
    for b in "${BINARIES[@]}"; do [[ -x "$src/$b" ]] || die "missing $src/$b; run scripts/build-linux-release.sh first"; done
    dest="$OPT/releases/$release_id"
    install -d -o root -g root -m 0755 "$OPT" "$OPT/releases"
    rm -rf "$dest.new"
    install -d -o root -g root -m 0755 "$dest.new" "$dest.new/bin"
    for b in "${BINARIES[@]}"; do install -o root -g root -m 0755 "$src/$b" "$dest.new/bin/$b"; done
    rm -rf "$dest"; mv "$dest.new" "$dest"
    ln -sfn "releases/$release_id" "$OPT/current.new" && mv -T "$OPT/current.new" "$OPT/current"
    ln -sfn "$OPT/current/bin/pm" /usr/local/bin/pm
    say "release $release_id installed in $dest"
}

install_wrappers() {
    install -d -o root -g root -m 0755 "$ETC"
    cat > /usr/local/bin/pm-tui <<EOF
#!/bin/sh
# Human TUI with the installed profile, the owner's protected key and the custody socket.
exec $OPT/current/bin/pm tui --profile $ETC/human.profile --private "\$HOME/.config/passwordmanager/human.key" \\
    --socket $RUN/human.sock --idle-seconds 300 --reveal-seconds 15 --copy-seconds 30
EOF
    cat > /usr/local/bin/pm-agent <<EOF
#!/bin/sh
# Delegated CLI/MCP for the registered agent account ($AGENT_USER).
# Examples: pm-agent capabilities --json | pm-agent credentials list --json | pm-agent mcp
export PM_PROFILE=$ETC/agent.profile PM_PRIVATE=$AGENT_HOME/.config/passwordmanager/agent.key PM_SOCKET=$RUN/agent.sock
exec $OPT/current/bin/pm "\$@"
EOF
    chmod 0755 /usr/local/bin/pm-tui /usr/local/bin/pm-agent
}

install_unit() {
    cat > "$UNIT" <<EOF
[Unit]
Description=Password manager custody service
After=local-fs.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$OPT/current/bin/pm-custody serve-vault --bootstrap $STATE/bootstrap --agent-socket $RUN/agent.sock --human-socket $RUN/human.sock --vault $STATE/vault.sqlite3 --device \${PM_DEVICE}
EnvironmentFile=$ETC/device.env
RuntimeDirectory=passwordmanager
RuntimeDirectoryMode=0755
UMask=0077
LimitCORE=0
LimitMEMLOCK=64M
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$STATE
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

wait_sockets() {
    for _ in $(seq 1 50); do
        [[ -S $RUN/agent.sock && -S $RUN/human.sock ]] && return 0
        sleep 0.2
    done
    systemctl --no-pager status passwordmanager || true
    die "custody sockets did not appear"
}

enrollment_line() {
    local subject request spki
    subject=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
    request=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
    spki=$(od -An -tx1 -v "$AGENT_HOME/.config/passwordmanager/agent.pub" | tr -d ' \n')
    echo "$subject|$request|$spki|$AGENT_USER|$(hostname)"
}

cmd_install() {
    [[ ! -e $STATE/vault.sqlite3 ]] || die "$STATE/vault.sqlite3 already exists; use upgrade"
    id -u "$SERVICE_USER" >/dev/null 2>&1 ||
        useradd --system --home-dir "$STATE" --no-create-home --shell /usr/bin/nologin "$SERVICE_USER"
    id -u "$AGENT_USER" >/dev/null 2>&1 ||
        useradd --system --home-dir "$AGENT_HOME" --create-home --shell /bin/bash "$AGENT_USER"
    local service_uid agent_uid
    service_uid=$(id -u "$SERVICE_USER"); agent_uid=$(id -u "$AGENT_USER")
    install_release
    install_wrappers
    install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0700 "$STATE"
    install -d -o "$AGENT_USER" -g "$AGENT_USER" -m 0750 "$AGENT_HOME"
    install -d -o "$AGENT_USER" -g "$AGENT_USER" -m 0700 "$AGENT_HOME/.config" "$AGENT_HOME/.config/passwordmanager"
    as "$human" install -d -m 0700 "$human_home/.config" "$human_keys"

    say "generating custody, owner and agent keys"
    [[ -e $STATE/server.key ]] || as "$SERVICE_USER" "$OPT/current/bin/pm-custody" keygen --private "$STATE/server.key" --public "$STATE/server.pub"
    [[ -e $human_keys/human.key ]] || as "$human" "$OPT/current/bin/pm-custody" keygen --private "$human_keys/human.key" --public "$human_keys/human.pub"
    [[ -e $AGENT_HOME/.config/passwordmanager/agent.key ]] || as "$AGENT_USER" "$OPT/current/bin/pm-custody" keygen \
        --private "$AGENT_HOME/.config/passwordmanager/agent.key" --public "$AGENT_HOME/.config/passwordmanager/agent.pub"

    say "provisioning bootstrap and profiles"
    if [[ ! -e $STATE/bootstrap ]]; then
        local tmp; tmp=$(mktemp -d); chmod 0755 "$tmp"
        install -m 0444 "$AGENT_HOME/.config/passwordmanager/agent.pub" "$tmp/agent.pub"
        install -m 0444 "$human_keys/human.pub" "$tmp/human.pub"
        as "$SERVICE_USER" "$OPT/current/bin/pm-custody" provision-bootstrap --path "$STATE/bootstrap" \
            --server-private "$STATE/server.key" --server-public "$STATE/server.pub" \
            --agent-public "$tmp/agent.pub" --agent-uid "$agent_uid" \
            --human-public "$tmp/human.pub" --human-uid "$human_uid"
        rm -rf "$tmp"
    fi
    local tmp; tmp=$(mktemp -d); install -m 0444 "$STATE/server.pub" "$tmp/server.pub"
    for role in human agent; do
        rm -f "$ETC/$role.profile"
        custody provision-profile --path "$ETC/$role.profile" --server-public "$tmp/server.pub" --server-uid "$service_uid" --role "$role"
    done
    rm -rf "$tmp"
    [[ -e $ETC/device.env ]] || echo "PM_DEVICE=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')" > "$ETC/device.env"
    chmod 0644 "$ETC/device.env"

    say "creating the vault: choose the master password and store the recovery code OFF this machine"
    ( cd "$STATE" && as "$SERVICE_USER" "$OPT/current/bin/pm" vault create "$STATE/vault.sqlite3" )

    install_unit
    systemctl enable --now passwordmanager
    wait_sockets
    say "custody service running"
    cat <<EOF

Next steps (as $human):
  1. pm-tui                      # unlock with the master password
  2. press 'a' (delegated access), then 'n', and paste this enrollment line:

     $(enrollment_line)

  3. create/import credentials, select one in the access screen and press 'e' to enable it for agents
  4. quit the TUI and run:  sudo $root/scripts/install-linux-local.sh register-agent
EOF
}

cmd_register_agent() {
    # shellcheck disable=SC1091
    . "$ETC/device.env"
    systemctl stop passwordmanager
    as "$SERVICE_USER" "$OPT/current/bin/pm-custody" migrate-agent-registry \
        --bootstrap "$STATE/bootstrap" --vault "$STATE/vault.sqlite3" --device "$PM_DEVICE" ||
        { systemctl start passwordmanager; die "registry migration refused: enroll the agent in pm-tui first"; }
    systemctl start passwordmanager
    wait_sockets
    say "agent $AGENT_USER registered; try: sudo -u $AGENT_USER pm-agent credentials list"
}

cmd_upgrade() {
    [[ -e $STATE/vault.sqlite3 ]] || die "nothing installed; use install"
    install_release
    install_wrappers
    install_unit
    systemctl restart passwordmanager
    wait_sockets
    say "upgraded and restarted"
}

cmd_status() {
    readlink "$OPT/current" || true
    systemctl --no-pager status passwordmanager || true
    ls -l "$RUN" "$STATE" 2>/dev/null || true
}

case "${1:-}" in
    install) cmd_install ;;
    register-agent) cmd_register_agent ;;
    upgrade) cmd_upgrade ;;
    status) cmd_status ;;
    *) die "usage: $0 install|register-agent|upgrade|status" ;;
esac
