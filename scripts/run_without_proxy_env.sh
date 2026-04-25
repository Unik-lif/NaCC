#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 1
fi

# Bear only needs local process interception. Proxy variables are cleared for
# this subprocess because inheriting them can break compile database capture.
exec env \
  -u HTTP_PROXY \
  -u HTTPS_PROXY \
  -u ALL_PROXY \
  -u NO_PROXY \
  -u FTP_PROXY \
  -u SOCKS_PROXY \
  -u http_proxy \
  -u https_proxy \
  -u all_proxy \
  -u no_proxy \
  -u ftp_proxy \
  -u socks_proxy \
  -u GIT_PROXY_COMMAND \
  "$@"
