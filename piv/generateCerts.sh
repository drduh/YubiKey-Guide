#!/usr/bin/env bash
# https://github.com/drduh/YubiKey-Guide/blob/main/piv/generateCerts.sh

#set -x  # uncomment to debug
set -o errexit
set -o errtrace
set -o nounset
set -o pipefail

umask 077

export LC_ALL="C"
export NAME_SERVER="" # required for alt names config
export OPENSSL_CNF="yk.cnf"

timestamp() { # Format current date and time.
  date +"%A %b %d %H:%M:%S"
}

log() { # Print formatted and timestamped events.
  local color="${1}"
  shift
  tput setaf "${color}"
  printf '(%s) %s\n' "$(timestamp)" "$*"
  tput sgr0
}

fail()  { log 1 "$@"; exit 1; }

get_temp_dir() { # Create a dated temporary directory.
  mktemp -d "${TMPDIR:-/tmp}/$(date +%Y.%m.%d)-XXXXXXXX" ||
    fail "could not create temp dir"
}

init_openssl_bin() { # Check for valid OpenSSL binary.
  export OPENSSL="/opt/homebrew/bin/openssl" # macOS
  #export OPENSSL="/usr/bin/openssl"          # Linux
  [[ -x "${OPENSSL}" ]] || fail "openssl not available"
}

init_work_dir() { # Create and work in temporary directory.
  export YK_CA_WORKDIR="$(get_temp_dir)"
  cp "$OPENSSL_CNF" "$YK_CA_WORKDIR"
  cd "$YK_CA_WORKDIR"
}

gen_cert_serial() { # Generate a random hex serial number.
  $OPENSSL rand -hex 16
}

init_piv_ca() { # Initialize certificate authority materials.
  mkdir -p certs
  touch index
  printf '%s' "$(gen_cert_serial)" > serial
}

get_date_flavor() { # Get date command type.
  if [[ -z "${DATE_FLAVOR:-}" ]]; then
    if date -v0H >/dev/null 2>&1; then
      DATE_FLAVOR=bsd
    else
      DATE_FLAVOR=gnu
    fi
  fi
  printf '%s' "$DATE_FLAVOR"
}

midnight_utc_offset() {
  local amount="${1:-0}" unit="${2:-d}"
  if [[ "$(get_date_flavor)" == bsd ]]; then
    local signed="$amount"
    [[ "$amount" == -* ]] || signed="+$amount"
    date -u -v"${signed}${unit}" -v0H -v0M -v0S \
      '+%Y%m%d%H%M%SZ'  # macOS/BSD
  else
    local unit_word=days
    [[ "$unit" == y ]] && unit_word=years
    date -u -d "today ${amount} ${unit_word} 00:00:00" \
      '+%Y%m%d%H%M%SZ'  # Linux/GNU
  fi
}

get_midnight_utc_today() { # Midnight UTC today
  midnight_utc_offset 0 d
}

get_midnight_utc_years() { # Midnight UTC, N years from today (default: 2)
  midnight_utc_offset "${1:-2}" y
}

get_midnight_utc_days() { # Midnight UTC, n days from today (default: 100)
  midnight_utc_offset "${1:-100}" d
}

get_cert_name() { # Format certificate common name.
  printf '/CN=yk.%s.%s' \
    "${1}" \
    "$(tr -dc 'a-z0-9' < /dev/urandom | head -c 16)"
}

preflight() {
  init_openssl_bin
  init_work_dir
  init_piv_ca
}

gen_private_key() { # Generate private key (select type).
  #$OPENSSL genrsa -out "${1}.key"
  #$OPENSSL genpkey -algorithm ed25519 -out "${1}.key"
  $OPENSSL ecparam -genkey -name secp384r1 -out "${1}.key"
}

gen_signing_req() { # Generate CSR.
  local certName="$(get_cert_name "${1}")"
  $OPENSSL req \
    -new \
    -config "$OPENSSL_CNF" \
    -subj "$certName" \
    -key "${1}.key" \
    -out "${1}.csr"
}

self_sign_cert() { # Self-sign root certificate.
  $OPENSSL ca \
    -batch \
    -config "$OPENSSL_CNF" \
    -extensions config_root \
    -startdate "$(get_midnight_utc_today)" \
    -enddate "$(get_midnight_utc_years "${2}")" \
    -selfsign \
    -keyfile "${1}.key" \
    -in  "${1}.csr" \
    -out "${1}.pem"
}

sign_with_ca() { # Sign with certificate authority.
  $OPENSSL ca \
    -batch \
    -config "$OPENSSL_CNF" \
    -extensions config_intermediate \
    -startdate "$(get_midnight_utc_today)" \
    -enddate "$(get_midnight_utc_years "${2}")" \
    -cert root.pem \
    -keyfile root.key \
    -in  "${1}.csr" \
    -out "${1}.pem"
}

sign_with_ia() { # Sign with intermediate authority on smartcard.
  $OPENSSL ca \
    -batch \
    -config "$OPENSSL_CNF" \
    -extensions config_server \
    -startdate "$(get_midnight_utc_today)" \
    -enddate "$(get_midnight_utc_days "${2}")" \
    -cert intermediate.pem \
    -keyfile 'pkcs11:id=%02;object=SIGN%20key;type=private' \
    -in  "${1}.csr" \
    -out "${1}.pem"
}

get_cert_detail() { # Print certificate details.
  printf '%0.s=' {1..80}
  printf '\n'
  $OPENSSL x509 \
    -noout \
    -issuer \
    -subject \
    -dates \
    -serial \
    -fingerprint \
    -sha256 \
    -in "${1}.pem" |
    while IFS='=' read -r key value; do
      key=${key/sha256 Fingerprint/SHA-256}
      printf '| %-10s %s\n' "$key:" "$value"
    done
  printf '%0.s=' {1..80}
  printf '\n'
  $OPENSSL x509 \
    -noout \
    -pubkey \
    -in "${1}.pem" |
    $OPENSSL pkey \
      -pubin \
      -noout \
      -text
  printf '%0.s=' {1..80}
  printf '\n'
}

gen_cred_root() { # Create root credentials.
  local credName="${1:-root}" credDuration="${2:-20}"
  gen_private_key "$credName"
  gen_signing_req "$credName"
  self_sign_cert  "$credName" "$credDuration"
  get_cert_detail "$credName"
}

gen_cred_intermediate() { # Create intermediate credentials.
  local credName="${1:-intermediate}" credDuration="${2:-2}"
  gen_private_key "$credName"
  gen_signing_req "$credName"
  sign_with_ca    "$credName" "$credDuration"
  get_cert_detail "$credName"
}

gen_cred_server() { # Create server credentials.
  local credName="${1:-server}" credDuration="${2:-99}"
  gen_private_key "$credName"
  gen_signing_req "$credName"
  sign_with_ia    "$credName" "$credDuration"
  get_cert_detail "$credName"
}

card_prep() { # Prepare smartcard for use.
  ykman piv info
  ykman piv reset
  sleep 1
}

card_load() { # Load credentials on smartcard.
  # https://docs.yubico.com/yesdk/users-manual/application-piv/pin-puk-mgmt-key.html
  local credName="${1:-intermediate}"
  local mgmtKey="010203040506070801020304050607080102030405060708"
  ykman piv keys         import -m "$mgmtKey" 9c "$credName.key"
  ykman piv certificates import -m "$mgmtKey" 9c "$credName.pem"
}

# 0. Set temp dir, cert common name and serial
preflight

# 1. Generate root credential, valid for number of years
gen_cred_root "root" "20"

# 2. Generate intermediate credential, valid for number of years
gen_cred_intermediate "intermediate" "2"

# 3. Reset card before use
card_prep

# 4. Import intermediate materials to card
card_load "intermediate"

# 5. Generate server credential, valid for number of days
gen_cred_server "server" "99"

printf "Materials in: %s\t\n" "$YK_CA_WORKDIR"
