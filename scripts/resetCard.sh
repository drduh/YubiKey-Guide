#!/usr/bin/env bash
# https://github.com/drduh/YubiKey-Guide/blob/main/scripts/resetCard.sh

#set -x  # uncomment to debug
set -o errexit
set -o errtrace
set -o nounset
set -o pipefail

# https://developers.yubico.com/ykneo-openpgp/ResetApplet.html
readonly CARD_CMD=$(cat <<EOF
/hex
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 e6 00 00
scd apdu 00 44 00 00
/bye
EOF
)

GPG_AGENT=""

getAgent() {
  GPG_AGENT=$(command -v gpg-connect-agent) || {
    printf "gpg-connect-agent not found" >&2
    exit 1
  }

  [[ -x "$GPG_AGENT" ]] || {
    printf "%s is not executable" "$GPG_AGENT" >&2
    exit 1
  }

  readonly GPG_AGENT
  "$GPG_AGENT" /bye > /dev/null 2>&1 || {
    printf "gpg-connect-agent not available" >&2
    exit 1
  }
}

confirm() {
  printf "Reset command will be sent to gpg-agent ..."
  read -r -p " continue? [y/N] " reply
  case "$reply" in
    [Yy]) ;;
    *) exit 0 ;;
  esac
}

runCommands() {
  local output
  local error

  if ! output=$(printf "%s\n" "$CARD_CMD" |
      "$GPG_AGENT" 2>&1); then
    printf "gpg-connect-agent failed" >&2
    exit 1
  fi

  if error=$(grep "^ERR " <<<"$output" | head -n1); then
    printf "%s" "$error" >&2
    exit 1
  fi

  printf "%s" "$output"
}

main() {
  getAgent
  confirm
  runCommands
  printf "Done"
}

main "$@"
