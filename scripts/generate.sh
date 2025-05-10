#!/usr/bin/env bash

#set -x  # uncomment to debug
set -o errtrace
set -o nounset
set -o pipefail

umask 077

export LC_ALL="C"

export GNUPGHOME=$(mktemp -d -t $(date +%Y.%m.%d)-XXXX)

cd "${GNUPGHOME}" ; printf "saving to %s\n" "$(pwd)"

export IDENTITY="YubiKey User <yubikey@example.domain>"

export KEY_TYPE="rsa4096"

export KEY_EXPIRATION="2027-05-01"

get_pass () {
    # Returns random passphrase.
    tr -dc "A-Z2-9" < /dev/urandom | \
        tr -d "IOUS5" | \
        fold  -w  ${PASS_GROUPSIZE:-4} | \
        paste -sd ${PASS_DELIMITER:--} - | \
        head  -c  ${PASS_LENGTH:-29}
}

export CERTIFY_PASS="$(get_pass)"

gen_key_certify () {
    # Generates Certify key with no expiration.
    echo "$CERTIFY_PASS" | \
        gpg --batch --passphrase-fd 0 \
            --quick-generate-key "$IDENTITY" \
            "$KEY_TYPE" "cert" "never"
}

set_key_id_fp () {
    # Sets Key ID and Fingerprint environment vars.
    export KEYID=$(gpg -k --with-colons "$IDENTITY" | \
        awk -F: '/^pub:/ { print $5; exit }')
    export KEYFP=$(gpg -k --with-colons "$IDENTITY" | \
        awk -F: '/^fpr:/ { print $10; exit }')
}

gen_key_certify

set_key_id_fp

printf "\nKey ID: %40s\nKey FP: %40s\n\n" "$KEYID" "$KEYFP"

gen_key_subs () {
    # Generates Subkeys with specified expiration.
    for SUBKEY in sign encrypt auth ; do \
        echo "$CERTIFY_PASS" | \
            gpg --batch --passphrase-fd 0 \
                --pinentry-mode=loopback \
                --quick-add-key "$KEYFP" \
                "$KEY_TYPE" "$SUBKEY" "$KEY_EXPIRATION"
    done
}

gen_key_subs

gpg -K

echo "$CERTIFY_PASS" | \
    gpg --output $GNUPGHOME/$KEYID-Certify.key \
        --batch --pinentry-mode=loopback --passphrase-fd 0 \
        --armor --export-secret-keys $KEYID

echo "$CERTIFY_PASS" | \
    gpg --output $GNUPGHOME/$KEYID-Subkeys.key \
        --batch --pinentry-mode=loopback --passphrase-fd 0 \
        --armor --export-secret-subkeys $KEYID

gpg --output $GNUPGHOME/$KEYID-$(date +%F).asc \
    --armor --export $KEYID

export LUKS_PASS="$(get_pass)"

printf "CERTIFY PASS: \n$CERTIFY_PASS\n\n"

printf "LUKS PASS:\n$LUKS_PASS\n\n"
