#!/usr/bin/env bash
# https://github.com/drduh/YubiKey-Guide/blob/main/piv/generateRoot.sh

#set -x  # uncomment to debug
set -o errtrace
set -o nounset
set -o pipefail

umask 077
export LC_ALL="C"

get_temp_dir() {
  mktemp -d "${TMPDIR:-/tmp}/$(date +%Y.%m.%d)-XXXXXXXX"
}

get_cert_serial() {
  $OPENSSL rand -hex 16
}

get_cert_start() {
  date -u -v0H -v0M -v0S '+%Y%m%d%H%M%SZ'
}

get_cert_end() {
  printf '20500101000000Z'
}

get_cert_name() {
  printf '/CN=yk.%s' "$(tr -dc 'a-z0-9' < /dev/urandom | head -c 16)"
}

init_cert_name() {
  export CANAME="$(get_cert_name)"
}

init_openssl_bin() {
  export OPENSSL="/opt/homebrew/bin/openssl"
}

init_work_dir() {
  local YK_CA_WORKDIR="$(get_temp_dir)"
  cp "root.cnf" "$YK_CA_WORKDIR"
  cd "$YK_CA_WORKDIR"
}

init_piv_ca() {
  mkdir -p yk_piv_ca/certs
  touch yk_piv_ca/index
  printf '%s' "$(get_cert_serial)" > yk_piv_ca/serial
}

preflight() {
  init_openssl_bin
  init_cert_name
  init_work_dir
  init_piv_ca
}

gen_private_key() {
  #$OPENSSL genrsa -out root.key
  #$OPENSSL genpkey -algorithm ed25519 -out root.key
  $OPENSSL ecparam -genkey -name secp384r1 -out root.key
}

gen_signing_req() {
  $OPENSSL req -new \
    -config root.cnf \
    -subj "$CANAME" \
    -key root.key \
    -out root.csr
}

self_sign_cert() {
  $OPENSSL ca -selfsign -batch \
    -config root.cnf \
    -extensions "v3_ca" \
    -startdate "$(get_cert_start)" \
    -enddate "$(get_cert_end)" \
    -keyfile root.key \
    -in root.csr \
    -out root.pem
}

get_cert_detail() {
  $OPENSSL x509 -text -noout -in root.pem
}

prep_card() {
  ykman piv info
  ykman piv reset
}

load_card() {
  ykman piv keys import 9c root.key
  ykman piv certificates import 9c root.pem
}

# 0. Set temp dir, cert common name and serial
preflight

# 1. Generate private key
gen_private_key

# 2. Generate cert signing request
gen_signing_req

# 3. Self-sign certificate request
self_sign_cert

# 4. Print signed certificate details
get_cert_detail

# 5. Check status and reset card
#prep_card

# 6. Import key and certificate to card
#load_card
