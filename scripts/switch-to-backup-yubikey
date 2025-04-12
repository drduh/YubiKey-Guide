#!/bin/sh
#
# To make a duplicate Yubikey for GPG keys
# 1. Insert Yubikey1
# 2. Create keys/subkeys
# 3. Run keytocard to transfer keys to Yubikey1
# 4. QUIT WITHOUT SAVING!!!!! 
#
# This will leave the keys on the Yubikey but NOT change the 
# GPG keyring to point to the Yubikey1 with a stub
# 
# 5. Insert Yubikey2
# 6. Run keytocard to transfer keys to Yubikey2
# 7. QUIT and SAVE to make GPG point it's stubs to Yubikey2
#
# Running any decrypt, auth or sign will now ask you to insert Yubikey2
# To switch to Yubikey1 at any time run this script to force GPG 
# to repoint the key stubs to the inserted Yubikey

read -p "Insert the Yubikey you want to use ....  "   ignore
echo "Switching GPG to backup Yubikey ..."

gpg-connect-agent "scd serialno" "learn --force" /bye
