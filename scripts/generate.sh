#!/usr/bin/env bash
# https://github.com/drduh/YubiKey-Guide/blob/master/scripts/generate.sh
# Generates GnuPG keys and corresponding passphrases to secure them.

#set -x  # uncomment to debug
set -o errtrace
set -o nounset
set -o pipefail

umask 077

export LC_ALL="C"

fail() {
    # Print an error string in red and exit.
    tput setaf 1 ; printf "%s\n" "${1}" ; tput sgr0
    exit 1
}

print_cred () {
    # Print a credential string in red.
    tput setaf 1 ; printf "%s\n" "${1}" ; tput sgr0
}

print_id () {
    # Print an identity string in yellow.
    tput setaf 3 ; printf "%s\n" "${1}" ; tput sgr0
}

get_id_label () {
    # Returns Identity name/label.
    printf "YubiKey User <yubikey@example.domain>"
}

get_key_type_sign () {
    # Returns key type for signature subkey.
    #printf "default"
    printf "rsa4096"
}

get_key_type_enc () {
    # Returns key type for encryption subkey.
    #printf "default"
    printf "rsa4096"
}

get_key_type_auth () {
    # Returns key type for authentication subkey.
    #printf "default"
    #printf "rsa4096"
    printf "ed25519"
}

get_key_expiration () {
    # Returns key expiration date.
    printf "2027-07-01"
}

get_temp_dir () {
    # Returns temporary working directory path.
    mktemp -d -t "$(date +%Y.%m.%d)-XXXX"
}

set_temp_dir () {
    # Exports and switches to temporary dir.
    export GNUPGHOME="$(get_temp_dir)"
    cd "$GNUPGHOME" || exit 1
    printf "set temp dir (path='%s')\n" "$(pwd)"
}

set_attrs () {
    # Sets identity and key attributes.
    export IDENTITY="$(get_id_label)"
    export KEY_TYPE_SIGN="$(get_key_type_sign)"
    export KEY_TYPE_ENC="$(get_key_type_enc)"
    export KEY_TYPE_AUTH="$(get_key_type_auth)"
    export KEY_EXPIRATION="$(get_key_expiration)"
    printf "set attributes (label='%s', sign='%s', enc='%s', auth='%s', expire='%s')\n" \
        "$IDENTITY" "$KEY_TYPE_SIGN" "$KEY_TYPE_ENC" "$KEY_TYPE_AUTH" "$KEY_EXPIRATION"
}

get_pass () {
    # Returns random passphrase.
    tr -dc "A-Z2-9" < /dev/urandom | \
        tr -d "IOUS5" | \
        fold  -w  "${PASS_GROUPSIZE:-4}" | \
        paste -sd "${PASS_DELIMITER:--}" - | \
        head  -c  "${PASS_LENGTH:-29}"
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
            --quick-generate-key "$IDENTITY" "$KEY_TYPE_SIGN" "cert" "never"
}

set_fingerprint () {
    # Sets Key ID and Fingerprint environment vars.
    key_list=$(gpg --list-secret-keys --with-colons)
    export KEY_ID=$(printf "$key_list" | awk -F: '/^sec/ { print  $5; exit }')
    export KEY_FP=$(printf "$key_list" | awk -F: '/^fpr/ { print $10; exit }')
    if [[ -z "$KEY_FP" || -z "$KEY_ID" ]]; then
        fail "could not set key fingerprint"
    fi
    printf "got identity (fp='%s', id='%s')\n" "$KEY_FP" "$KEY_ID"
}

gen_key_subs () {
    # Generates Subkeys with specified expiration.
    echo "$CERTIFY_PASS" | \
        gpg --batch --passphrase-fd 0 --pinentry-mode=loopback \
            --quick-add-key "$KEY_FP" "$KEY_TYPE_SIGN" sign "$KEY_EXPIRATION"
    echo "$CERTIFY_PASS" | \
        gpg --batch --passphrase-fd 0 --pinentry-mode=loopback \
            --quick-add-key "$KEY_FP" "$KEY_TYPE_ENC" encrypt "$KEY_EXPIRATION"
    echo "$CERTIFY_PASS" | \
        gpg --batch --passphrase-fd 0  --pinentry-mode=loopback \
            --quick-add-key "$KEY_FP" "$KEY_TYPE_AUTH" auth "$KEY_EXPIRATION"
}

save_secrets () {
    # Exports secret keys to local files.
    export OUTPUT_CERTIFY="$GNUPGHOME/$KEY_ID-Certify.key"
    export OUTPUT_SUBKEYS="$GNUPGHOME/$KEY_ID-Subkeys.key"
    echo "$CERTIFY_PASS" | \
        gpg --output "$OUTPUT_CERTIFY" \
            --batch --pinentry-mode=loopback --passphrase-fd 0 \
            --armor --export-secret-keys "$KEY_ID"
    echo "$CERTIFY_PASS" | \
        gpg --output "$OUTPUT_SUBKEYS" \
            --batch --pinentry-mode=loopback --passphrase-fd 0 \
            --armor --export-secret-subkeys "$KEY_ID"
}

save_pubkey () {
    # Exports public key to local file.
    export OUTPUT_PUBKEY="$GNUPGHOME/$KEY_ID-Public.asc"
    gpg --output "$OUTPUT_PUBKEY" \
        --armor --export "$KEY_ID"
}

finish () {
    # Prints final message with id and credentials.
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

# 1. Set temporary working directory for GnuPG ops.
set_temp_dir

# 2. Set identity and key attributes, such as label and type.
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
finish
