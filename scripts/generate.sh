#!/usr/bin/env bash

#set -x  # uncomment to debug
set -o errtrace
set -o nounset
set -o pipefail

umask 077

export LC_ALL="C"

export GNUPGHOME=$(mktemp -d -t $(date +%Y.%m.%d)-XXXX)

cd "${GNUPGHOME}" ; pwd

export IDENTITY="YubiKey User <yubikey@example.domain>"

export KEY_TYPE="rsa4096"

export KEY_EXPIRATION="2027-05-01"

export CERTIFY_PASS=$(LC_ALL=C tr -dc "A-Z2-9" < /dev/urandom | \
    tr -d "IOUS5" | \
    fold  -w  ${PASS_GROUPSIZE:-4} | \
    paste -sd ${PASS_DELIMITER:--} - | \
    head  -c  ${PASS_LENGTH:-29})

echo "$CERTIFY_PASS" | \
    gpg --batch --passphrase-fd 0 \
        --quick-generate-key "$IDENTITY" "$KEY_TYPE" cert never

export KEYID=$(gpg -k --with-colons "$IDENTITY" | \
    awk -F: '/^pub:/ { print $5; exit }')

export KEYFP=$(gpg -k --with-colons "$IDENTITY" | \
    awk -F: '/^fpr:/ { print $10; exit }')

printf "\nKey ID: %40s\nKey FP: %40s\n\n" "$KEYID" "$KEYFP"

for SUBKEY in sign encrypt auth ; do \
    echo "$CERTIFY_PASS" | \
        gpg --batch --pinentry-mode=loopback --passphrase-fd 0 \
            --quick-add-key "$KEYFP" "$KEY_TYPE" "$SUBKEY" "$KEY_EXPIRATION"
done

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

export LUKS_PASS=$(LC_ALL=C tr -dc "A-Z2-9" < /dev/urandom | \
    tr -d "IOUS5" | \
    fold  -w  ${PASS_GROUPSIZE:-4} | \
    paste -sd ${PASS_DELIMITER:--} - | \
    head  -c  ${PASS_LENGTH:-29})

printf "CERTIFY PASS: \n$CERTIFY_PASS\n\n"

printf "LUKS PASS:\n$LUKS_PASS\n\n"
