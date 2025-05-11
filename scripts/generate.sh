#!/usr/bin/env bash
# https://github.com/drduh/YubiKey-Guide/blob/master/scripts/generate.sh
# Generates GnuPG keys and corresponding passphrases to secure them.

#set -x  # uncomment to debug
set -o errtrace
set -o nounset
set -o pipefail

umask 077

export LC_ALL="C"

print_cred () {
  # Print a credential string in red.
  tput setaf 1 ; printf "%s\n" "${1}" ; tput sgr0
}

get_id_label () {
    # Returns Identity name/label.
    printf "YubiKey User <yubikey@example.domain>"
}

get_key_type () {
    # Returns key type and size.
    printf "rsa2048"
}

get_key_expiration () {
    # Returns key expiration date.
    printf "2027-05-01"
}

get_temp_dir () {
    # Returns temporary working directory path.
    mktemp -d -t $(date +%Y.%m.%d)-XXXX
}

set_temp_dir () {
    # Exports and switches to temporary dir.
    export GNUPGHOME="$(get_temp_dir)"
    cd "$GNUPGHOME"
    printf "set temp dir (path='%s')\n" "$(pwd)"
}

set_attrs () {
    # Sets identity and key attributes.
    export IDENTITY="$(get_id_label)"
    export KEY_TYPE="$(get_key_type)"
    export KEY_EXPIRATION="$(get_key_expiration)"
    printf "set attributes (label='%s', type='%s', expire='%s')\n" \
        "$IDENTITY" "$KEY_TYPE" "$KEY_EXPIRATION"
}

get_pass () {
    # Returns random passphrase.
    tr -dc "A-Z2-9" < /dev/urandom | \
        tr -d "IOUS5" | \
        fold  -w  ${PASS_GROUPSIZE:-4} | \
        paste -sd ${PASS_DELIMITER:--} - | \
        head  -c  ${PASS_LENGTH:-29}
}

set_pass () {
    # Exports Certify and LUKS passphrases.
    export CERTIFY_PASS="$(get_pass)"
    export ENCRYPT_PASS="$(get_pass)"
    printf "set passphrases (certify='%s', encrypt='%s')\n" \
        "$CERTIFY_PASS" "$ENCRYPT_PASS"
}

gen_key_certify () {
    # Generates Certify key with no expiration.
    echo "$CERTIFY_PASS" | \
        gpg --batch --passphrase-fd 0 \
            --quick-generate-key "$IDENTITY" \
            "$KEY_TYPE" "cert" "never"
}

set_id_fp () {
    # Sets Key ID and Fingerprint environment vars.
    export KEY_ID=$(gpg -k --with-colons "$IDENTITY" | \
        awk -F: '/^pub:/ { print $5; exit }')
    export KEY_FP=$(gpg -k --with-colons "$IDENTITY" | \
        awk -F: '/^fpr:/ { print $10; exit }')
    printf "got identity (fp='%s', id='%s')\n" \
        "$KEY_FP" "$KEY_ID"
}

gen_key_subs () {
    # Generates Subkeys with specified expiration.
    for SUBKEY in sign encrypt auth ; do \
        echo "$CERTIFY_PASS" | \
            gpg --batch --passphrase-fd 0 \
                --pinentry-mode=loopback \
                --quick-add-key "$KEY_FP" \
                "$KEY_TYPE" "$SUBKEY" "$KEY_EXPIRATION"
    done
}

list_keys () {
    # Prints available secret keys.
    gpg --list-secret-keys
}

save_secrets () {
    # Exports secret keys to local files.
    echo "$CERTIFY_PASS" | \
        gpg --output $GNUPGHOME/$KEY_ID-Certify.key \
            --batch --pinentry-mode=loopback --passphrase-fd 0 \
            --armor --export-secret-keys $KEY_ID

    echo "$CERTIFY_PASS" | \
        gpg --output $GNUPGHOME/$KEY_ID-Subkeys.key \
            --batch --pinentry-mode=loopback --passphrase-fd 0 \
            --armor --export-secret-subkeys $KEY_ID
}

save_pubkey () {
    # Exports public key to local file.
    gpg --output $GNUPGHOME/$KEY_ID-$(date +%F).asc \
        --armor --export $KEY_ID
}

finish () {
    # Prints final message with credentials.
    printf "certify passphrase: "
    print_cred $CERTIFY_PASS

    printf "encrypt passphrase: "
    print_cred $ENCRYPT_PASS
}

set_temp_dir

set_attrs

set_pass

gen_key_certify

set_id_fp

gen_key_subs

list_keys

save_secrets

save_pubkey

finish
