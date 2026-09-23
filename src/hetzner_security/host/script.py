"""The host evidence bundle script: a fixed allowlist of read-only commands.

The CLI never connects to hosts. The owner reviews this script and runs it on each server,
for example ``ssh web-1 'sudo sh -s' < host-bundle.sh > web-1.bundle``, then passes the output
with ``--host-bundle``. The script prints configuration only: Docker inspection uses an explicit
template (no environment variables), Redis passwords print as ``<set>``/``<empty>``, and ACL hashes
are redacted.
"""

from __future__ import annotations

BUNDLE_VERSION = 1

BUNDLE_SCRIPT = r"""#!/bin/sh
# hetzner-audit host evidence bundle v1. Read-only: it prints configuration and changes nothing.
# Run as root so ufw, ss -p, sshd -T, and docker inspect can read state:
#   ssh HOST 'sudo HETZNER_AUDIT_SERVER=<hcloud server name> sh -s' < host-bundle.sh > HOST.bundle
set -u
LC_ALL=C
export LC_ALL
have() { command -v "$1" >/dev/null 2>&1; }
section() { printf '\n===HETZNER-AUDIT %s===\n' "$1"; }
limit() { if have timeout; then timeout 10 "$@"; else "$@"; fi; }

printf 'hetzner-audit-host-bundle 1\n'
section meta
printf 'server=%s\n' "${HETZNER_AUDIT_SERVER:-$(hostname)}"
printf 'collected_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf 'kernel=%s\n' "$(uname -r)"
[ -r /etc/os-release ] && grep -E '^(ID|VERSION_ID)=' /etc/os-release

section ufw
if have ufw; then limit ufw status verbose 2>&1; else echo 'not installed'; fi

section nftables
if have nft; then limit nft list ruleset 2>&1; else echo 'not installed'; fi

section iptables
if have iptables; then limit iptables -S INPUT 2>&1; else echo 'not installed'; fi

section ip6tables
if have ip6tables; then limit ip6tables -S INPUT 2>&1; else echo 'not installed'; fi

section docker_user
if have iptables; then limit iptables -S DOCKER-USER 2>&1; else echo 'not installed'; fi

section listeners
if have ss; then limit ss -H -ltunp 2>&1; else echo 'not installed'; fi

section agents
# Tunnel and mesh agents (names only): a service published through an outbound tunnel needs no inbound port.
ps -eo comm= 2>/dev/null | grep -E '^(cloudflared|ngrok|tailscaled|netbird|zerotier-one|frpc)$' | sort -u

section sshd
if have sshd; then
  limit sshd -T 2>/dev/null | grep -iE '^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|pubkeyauthentication|permitemptypasswords|maxauthtries|x11forwarding|allowtcpforwarding|authenticationmethods) '
else
  echo 'not installed'
fi

section docker
if have docker; then
  ids=$(limit docker ps -q 2>&1)
  if ! printf '%s\n' "$ids" | grep -Eq '^[0-9a-f]{12}$'; then
    # Keep the error: an unreachable daemon is not the same as "no containers".
    [ -n "$ids" ] && printf 'error: %s\n' "$ids" | head -n 3
  else
    # Explicit template: names, isolation settings, mounts, and published ports. No environment.
    limit docker inspect --format '{"name":{{json .Name}},"image":{{json .Config.Image}},"user":{{json .Config.User}},"privileged":{{json .HostConfig.Privileged}},"pid_mode":{{json .HostConfig.PidMode}},"network_mode":{{json .HostConfig.NetworkMode}},"cap_add":{{json .HostConfig.CapAdd}},"security_opt":{{json .HostConfig.SecurityOpt}},"ports":{{json .NetworkSettings.Ports}},"mounts":{{json .Mounts}}}' $ids 2>&1
  fi
else
  echo 'not installed'
fi

section pg_hba
found=0
for file in /etc/postgresql/*/main/pg_hba.conf /var/lib/pgsql/data/pg_hba.conf /var/lib/postgresql/data/pg_hba.conf ${HETZNER_AUDIT_PG_HBA:-}; do
  if [ -r "$file" ]; then
    found=1
    printf '# file %s\n' "$file"
    grep -vE '^[[:space:]]*(#|$)' "$file"
  fi
done
[ "$found" = 0 ] && echo 'not found'

section redis
if have redis-cli; then
  limit redis-cli CONFIG GET bind 2>&1
  limit redis-cli CONFIG GET protected-mode 2>&1
  limit redis-cli CONFIG GET requirepass 2>&1 | awk 'NR == 1 { print; next } NR == 2 { print ($0 == "" ? "<empty>" : "<set>"); next } { print }'
  limit redis-cli ACL LIST 2>&1 | sed -E 's/#[0-9a-fA-F]+/#<redacted>/g; s/>[^ ]+/><redacted>/g'
else
  echo 'not installed'
fi

section end
"""
