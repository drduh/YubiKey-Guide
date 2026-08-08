#!/usr/bin/env bash
# https://github.com/drduh/YubiKey-Guide/blob/main/scripts/generateKeys.sh
# Generates GnuPG keys and corresponding passphrases.

#set -x  # uncomment to debug
set -o errtrace
set -o nounset
set -o pipefail

umask 077
export LC_ALL="C"

gpgExec="$(command -v gpg || command -v gpg2)"

log() { # Print formatted events.
  local color="$1"
  shift
  tput setaf "$color"
  printf '%s\n' "$*"
  tput sgr0
}

fail() { log 1 "$@"; exit 1; }
print_cred() { log 2 "$@"; }
print_id() { log 3 "$@"; }

get_id_label() { # Returns Identity name/label.
  printf "yk.$(tr -dc 'a-z0-9' < /dev/urandom | head -c 16)"
}

get_key_type_sign() { # Returns signature subkey type.
  #printf "default"
  printf "rsa4096"
}

get_key_type_enc() { # Returns encryption subkey type.
  #printf "default"
  printf "rsa4096"
}

get_key_type_auth() { # Returns authentication subkey type.
  #printf "default"
  #printf "rsa4096"
  printf "ed25519"
}

get_key_expiration() { # Returns key expiration date (2 years).
  date "-v+2y" "+%F"
}

preflight() { # Fail if GnuPG is not available.
  [[ -n "$gpgExec" ]] || fail "GnuPG binary not available"
}

get_temp_dir() { # Returns temporary working dir path.
  mktemp -d "${TMPDIR:-/tmp}/$(date +%Y.%m.%d)-XXXXXXXX"
}

set_temp_dir() { # Exports and switches to temporary dir.
  export GNUPGHOME="$(get_temp_dir)"
  cd "$GNUPGHOME" || exit 1
  printf "set temp dir (path='%s')\n" "$(pwd)"
}

set_attrs() { # Sets identity and key attributes.
  export IDENTITY="$(get_id_label)"
  export KEY_TYPE_SIGN="$(get_key_type_sign)"
  export KEY_TYPE_ENC="$(get_key_type_enc)"
  export KEY_TYPE_AUTH="$(get_key_type_auth)"
  export KEY_EXPIRATION="$(get_key_expiration)"
  printf "set attributes (label='%s', sign='%s', enc='%s', auth='%s', expire='%s')\n" \
    "$IDENTITY" "$KEY_TYPE_SIGN" "$KEY_TYPE_ENC" "$KEY_TYPE_AUTH" "$KEY_EXPIRATION"
}

get_pass() { # Returns random passphrase.
  tr -dc "A-Z3-9" < /dev/urandom |
    tr -d "IOUS5" |
    head -c ${PASS_LENGTH:-24} |
    fold -w ${PASS_GROUPSIZE:-4} |
    paste -sd ${PASS_DELIMITER:--} -
}

set_pass() { # Exports Certify and LUKS passphrases.
  export CERTIFY_PASS="$(get_pass)"
  export ENCRYPT_PASS="$(get_pass)"
  printf "set passphrases (certify='%s', encrypt='%s')\n" \
    "$CERTIFY_PASS" "$ENCRYPT_PASS"
}

gen_key_certify() { # Generates Certify key with no expiration.
  printf '%s' "$CERTIFY_PASS" |
    $gpgExec --batch --passphrase-fd 0 \
      --quick-generate-key "$IDENTITY" "$KEY_TYPE_SIGN" \
      "cert" "never"
}

set_fingerprint() { # Sets Key ID and Fingerprint environment vars.
  local key_list=$($gpgExec --list-secret-keys --with-colons)
  export KEY_FP=$(printf '%s' "$key_list" | awk -F: '/^fpr:/ { print $10; exit }')
  export KEY_ID="${KEY_FP: -16}"
  if [[ -z "$KEY_FP" || -z "$KEY_ID" ]]; then
    fail "could not set key fingerprint"
  fi
  printf "got identity (fp='%s', id='%s')\n" "$KEY_FP" "$KEY_ID"
}

gen_key_subs() { # Generates Subkeys with specified expiration.
  printf '%s' "$CERTIFY_PASS" |
    $gpgExec --batch --passphrase-fd 0 --pinentry-mode loopback \
      --quick-add-key "$KEY_FP" "$KEY_TYPE_SIGN" \
      "sign" "$KEY_EXPIRATION"
  printf '%s' "$CERTIFY_PASS" |
    $gpgExec --batch --passphrase-fd 0 --pinentry-mode loopback \
      --quick-add-key "$KEY_FP" "$KEY_TYPE_ENC" \
      "encrypt" "$KEY_EXPIRATION"
  printf '%s' "$CERTIFY_PASS" |
    $gpgExec --batch --passphrase-fd 0 --pinentry-mode loopback \
      --quick-add-key "$KEY_FP" "$KEY_TYPE_AUTH" \
      "auth" "$KEY_EXPIRATION"
}

save_secrets() { # Exports secret keys to local files.
  local OUTPUT_CERTIFY="$GNUPGHOME/secret-$KEY_ID-Certify.key"
  local OUTPUT_SUBKEYS="$GNUPGHOME/secret-$KEY_ID-Subkeys.key"
  printf '%s' "$CERTIFY_PASS" |
    $gpgExec --output "$OUTPUT_CERTIFY" \
      --batch --pinentry-mode loopback --passphrase-fd 0 \
      --armor --export-secret-keys "$KEY_ID"
  printf '%s' "$CERTIFY_PASS" |
    $gpgExec --output "$OUTPUT_SUBKEYS" \
      --batch --pinentry-mode loopback --passphrase-fd 0 \
      --armor --export-secret-subkeys "$KEY_ID"
}

save_pubkey() { # Exports public key to local file.
  export OUTPUT_PUBKEY="$GNUPGHOME/public-$KEY_ID-$(date +%F).asc"
  $gpgExec --output "$OUTPUT_PUBKEY" \
    --armor --export "$KEY_ID"
}

print_results() { # Prints id and credentials information.
  printf "\nidentity/key label:     "
  print_id "$IDENTITY"
  printf "key id/fingerprint:     "
  print_id "$KEY_ID"
  print_id "$KEY_FP"
  printf "subkeys expiration:     "
  print_id "$KEY_EXPIRATION"

  printf "\nsecrets and pubkey:     "
  print_id "$GNUPGHOME"
  print_id "$OUTPUT_PUBKEY"

  printf "\ncertify passphrase:     "
  print_cred "$CERTIFY_PASS"
  printf "encrypt passphrase:     "
  print_cred "$ENCRYPT_PASS"

  exit 0
}

# 0. Sanity check
preflight

# 1. Set temporary working directory for GnuPG ops.
set_temp_dir

# 2. Set identity and key attributes.
set_attrs

# 3. Set passphrases for identity and storage encryption.
set_pass

# 4. Generate the Certify key.
gen_key_certify

# 5. Set resulting identity fingerprint.
set_fingerprint

# 6. Generate the Subkeys.
gen_key_subs

# 7. Export Certify and Subkeys to local storage.
save_secrets

# 8. Export public key to local storage.
save_pubkey

# 9. Print results and exit.
print_results
