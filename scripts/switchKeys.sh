#!/bin/sh
# https://github.com/drduh/YubiKey-Guide/blob/main/scripts/switchKeys.sh
#
# To duplicate YubiKey for GPG credentials:
# 1. Generate keys/subkeys
# 2. Insert first YubiKey
# 3. Run 'keytocard' to transfer keys to first YubiKey
# 4. Quit without saving!
#
# This will leave the keys on the YubiKey but NOT change the
# GPG keyring to point to the first YubiKey with only a stub
#
# 5. Insert second YubiKey
# 6. Run 'keytocard' to transfer keys to second YubiKey
# 7. QUIT and SAVE to point GPG stubs to second YubiKey
#
# Running any decrypt, auth or sign will now ask to insert second YubiKey
# To switch to the first YubiKey at any time run this script to force GPG
# to point key stubs to the currently inserted YubiKey
read -p "Insert YubiKey to use ... " ignore
echo "Switching GPG to backup YubiKey ..."
gpg-connect-agent "scd serialno" "learn --force" /bye
