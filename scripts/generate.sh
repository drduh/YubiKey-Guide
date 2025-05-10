#!/usr/bin/env bash
# https://github.com/drduh/YubiKey-Guide/blob/master/scripts/generate.sh
# Generates GnuPG keys and corresponding passphrases to secure them.

#set -x  # uncomment to debug
set -o errtrace
set -o nounset
set -o pipefail

umask 077

export LC_ALL="C"

get_temp_dir () {
    # Returns temporary working directory path.
    mktemp -d -t $(date +%Y.%m.%d)-XXXX
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

get_pass () {
    # Returns random passphrase.
    tr -dc "A-Z2-9" < /dev/urandom | \
        tr -d "IOUS5" | \
        fold  -w  ${PASS_GROUPSIZE:-4} | \
        paste -sd ${PASS_DELIMITER:--} - | \
        head  -c  ${PASS_LENGTH:-29}
}

export GNUPGHOME="$(get_temp_dir)"
cd "$GNUPGHOME"
printf "set temp dir (path='%s')\n" "$(pwd)"

export IDENTITY="$(get_id_label)"
export KEY_TYPE="$(get_key_type)"
export KEY_EXPIRATION="$(get_key_expiration)"
printf "set id (label='%s', type='%s', expire='%s')\n" \
    "$IDENTITY" "$KEY_TYPE" "$KEY_EXPIRATION"

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

list_keys () {
    # Prints available secret keys.
    gpg --list-secret-keys
}

save_secrets () {
    # Exports secret keys to local files.
    echo "$CERTIFY_PASS" | \
        gpg --output $GNUPGHOME/$KEYID-Certify.key \
            --batch --pinentry-mode=loopback --passphrase-fd 0 \
            --armor --export-secret-keys $KEYID

    echo "$CERTIFY_PASS" | \
        gpg --output $GNUPGHOME/$KEYID-Subkeys.key \
            --batch --pinentry-mode=loopback --passphrase-fd 0 \
            --armor --export-secret-subkeys $KEYID
}

save_pubkey () {
    # Exports public key to local file.
    gpg --output $GNUPGHOME/$KEYID-$(date +%F).asc \
        --armor --export $KEYID
}

list_keys

save_secrets

save_pubkey

printf "CERTIFY PASS: \n$CERTIFY_PASS\n\n"

export LUKS_PASS="$(get_pass)"

printf "LUKS PASS:\n$LUKS_PASS\n\n"
