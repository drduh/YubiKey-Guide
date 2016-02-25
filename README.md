This is a guide to using YubiKey as a SmartCard for storing GPG keys.

An authentication key can also be created for SSH using gpg-agent.

Keys stored on a smartcard like YubiKey seem more difficult to steal than ones stored on disk, and are convenient for everyday use.

Instructions written on Debian GNU/Linux 8 (jessie) using YubiKey 4 in OTP+CCID mode.

Debian live install images are available from [here](https://www.debian.org/CD/live/) and are suitable for writing to USB keys.

If you have a comment or suggestion, please open an issue on GitHub.

- [Purchase YubiKey](#purchase-yubikey)
- [Install required software](#install-required-software)
- [Creating keys](#creating-keys)
  - [Create temporary working directory for GPG](#create-temporary-working-directory-for-gpg)
  - [Create configuration](#create-configuration)
  - [Create master key](#create-master-key)
  - [Create revocation certificate](#create-revocation-certificate)
  - [Back up master key](#back-up-master-key)
  - [Create subkeys](#create-subkeys)
    - [Signing key](#signing-key)
    - [Encryption key](#encryption-key)
    - [Authentication key](#authentication-key)
  - [Check your work](#check-your-work)
  - [Export subkeys](#export-subkeys)
  - [Back up everything](#back-up-everything)
  - [Configure YubiKey](#configure-yubikey)
  - [Configure smartcard](#configure-smartcard)
    - [Change PINs](#change-pins)
    - [Set optional card information](#set-optional-card-information)
  - [Transfer keys](#transfer-keys)
    - [Signature key](#signature-key)
    - [Encryption key](#encryption-key-1)
    - [Authentication key](#authentication-key-1)
  - [Check your work](#check-your-work-1)
  - [Export public key](#export-public-key)
- [Using keys](#using-keys)
  - [Insert YubiKey](#insert-yubikey)
  - [Import public key](#import-public-key)
  - [Trust master key](#trust-master-key)
  - [GnuPG](#gnupg)
    - [Create configuration](#create-configuration-1)
    - [Encryption/decryption](#encryptiondecryption)
    - [Signing](#signing)
  - [SSH](#ssh)
    - [Update configuration](#update-configuration)
    - [Replace ssh-agent with gpg-agent](#replace-ssh-agent-with-gpg-agent)
    - [Copy public key to server](#copy-public-key-to-server)
    - [Connect with public key authentication](#connect-with-public-key-authentication)
- [Notes](#notes)
- [References](#references)

# Purchase YubiKey

https://www.yubico.com/products/yubikey-hardware/

https://www.yubico.com/store/

https://www.amazon.com/Yubico/b/ref=bl_dp_s_web_10358012011?ie=UTF8&node=10358012011

Consider purchasing a pair and programming both in case of loss or damage.

# Install required software

    $ sudo apt-get install gnupg-agent pinentry-curses scdaemon pcscd yubikey-personalization

# Creating keys

## Create temporary working directory for GPG

    $ export GNUPGHOME=$(mktemp -d) ; echo $GNUPGHOME
    /tmp/tmp.EBbMfyVDDt

## Create configuration

    $ cat > $GNUPGHOME/gpg.conf
    use-agent
    personal-cipher-preferences AES256 AES192 AES CAST5
    personal-digest-preferences SHA512 SHA384 SHA256 SHA224
    default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed
    cert-digest-algo SHA512
    s2k-digest-algo SHA512
    charset utf-8
    fixed-list-mode
    no-comments
    no-emit-version
    keyid-format 0xlong
    list-options show-uid-validity
    verify-options show-uid-validity
    with-fingerprint
    ^D (Press Control-D)

## Create master key

    $ gpg --gen-key
    gpg (GnuPG) 1.4.18; Copyright (C) 2014 Free Software Foundation, Inc.
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.

    Please select what kind of key you want:
       (1) RSA and RSA (default)
       (2) DSA and Elgamal
       (3) DSA (sign only)
       (4) RSA (sign only)
    Your selection? 4
    RSA keys may be between 1024 and 4096 bits long.
    What keysize do you want? (2048) 4096
    Requested keysize is 4096 bits
    Please specify how long the key should be valid.
             0 = key does not expire
          <n>  = key expires in n days
          <n>w = key expires in n weeks
          <n>m = key expires in n months
          <n>y = key expires in n years
    Key is valid for? (0) 0
    Key does not expire at all
    Is this correct? (y/N) y

    You need a user ID to identify your key; the software constructs the user ID
    from the Real Name, Comment and Email Address in this form:
        "Heinrich Heine (Der Dichter) <heinrichh@duesseldorf.de>"

    Real name: Doctor Duh
    Email address: drduh@users.noreply.github.com
    Comment:
    You selected this USER-ID:
        "Doctor Duh <drduh@users.noreply.github.com>"

    Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? o
    You need a Passphrase to protect your secret key.

    We need to generate a lot of random bytes. It is a good idea to perform
    some other action (type on the keyboard, move the mouse, utilize the
    disks) during the prime generation; this gives the random number
    generator a better chance to gain enough entropy.

    gpg: /tmp/tmp.eBbMfyVDDt/trustdb.gpg: trustdb created
    gpg: key 0x47FE984F98EE7407 marked as ultimately trusted
    public and secret key created and signed.

    gpg: checking the trustdb
    gpg: 3 marginal(s) needed, 1 complete(s) needed, PGP trust model
    gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
    pub   4096R/0x47FE984F98EE7407 2016-01-30
          Key fingerprint = 044C ABD0 9043 F1E0 3785  3979 47FE 984F 98EE 7407
    uid                 [ultimate] Doctor Duh <drduh@users.noreply.github.com>

    Note that this key cannot be used for encryption.  You may want to use
    the command "--edit-key" to generate a subkey for this purpose.

## Create revocation certificate

    $ gpg --gen-revoke 0x47FE984F98EE7407 > $GNUPGHOME/revoke.txt

    sec  4096R/0x47FE984F98EE7407 2016-01-30 Doctor Duh <drduh@users.noreply.github.com>

    Create a revocation certificate for this key? (y/N) y
    Please select the reason for the revocation:
      0 = No reason specified
      1 = Key has been compromised
      2 = Key is superseded
      3 = Key is no longer used
      Q = Cancel
    (Probably you want to select 1 here)
    Your decision? 1
    Enter an optional description; end it with an empty line:
    >
    Reason for revocation: Key has been compromised
    (No description given)
    Is this okay? (y/N) y

    You need a passphrase to unlock the secret key for
    user: "Doctor Duh <drduh@users.noreply.github.com>"
    4096-bit RSA key, ID 0x47FE984F98EE7407, created 2016-01-30

    ASCII armored output forced.
    Revocation certificate created.

    Please move it to a medium which you can hide away; if Mallory gets
    access to this certificate he can use it to make your key unusable.
    It is smart to print this certificate and store it away, just in case
    your media become unreadable.  But have some caution:  The print system of
    your machine might store the data and make it available to others!

## Back up master key

    $ gpg --armor --export-secret-keys 0x47FE984F98EE7407 > $GNUPGHOME/master.key

## Create subkeys

    $ gpg --expert --edit-key 0x47FE984F98EE7407

    gpg (GnuPG) 1.4.18; Copyright (C) 2014 Free Software Foundation, Inc.
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.

    Secret key is available.

    pub  4096R/0x47FE984F98EE7407  created: 2016-01-30  expires: never       usage: SC

                                   trust: ultimate      validity: ultimate
    [ultimate] (1). Doctor Duh <drduh@users.noreply.github.com>

### Signing key

    gpg> addkey
    Key is protected.

    You need a passphrase to unlock the secret key for
    user: "Doctor Duh <drduh@users.noreply.github.com>"
    4096-bit RSA key, ID 0x47FE984F98EE7407, created 2016-01-30

    Please select what kind of key you want:
       (3) DSA (sign only)
       (4) RSA (sign only)
       (5) Elgamal (encrypt only)
       (6) RSA (encrypt only)
       (7) DSA (set your own capabilities)
       (8) RSA (set your own capabilities)
    Your selection? 4
    RSA keys may be between 1024 and 4096 bits long.
    What keysize do you want? (2048) 4096
    Requested keysize is 4096 bits
    Please specify how long the key should be valid.
             0 = key does not expire
          <n>  = key expires in n days
          <n>w = key expires in n weeks
          <n>m = key expires in n months
          <n>y = key expires in n years
    Key is valid for? (0) 0
    Key does not expire at all
    Is this correct? (y/N) y
    Really create? (y/N) y
    We need to generate a lot of random bytes. It is a good idea to perform
    some other action (type on the keyboard, move the mouse, utilize the
    disks) during the prime generation; this gives the random number
    generator a better chance to gain enough entropy.
    .....+++++
    .+++++

    pub  4096R/0x47FE984F98EE7407  created: 2016-01-30  expires: never       usage: SC

                                   trust: ultimate      validity: ultimate
    sub  4096R/0xE8E7855AA5AE79A7  created: 2016-01-30  expires: never       usage: S

    [ultimate] (1). Doctor Duh <drduh@users.noreply.github.com>

### Encryption key

    gpg> addkey
    Key is protected.

    You need a passphrase to unlock the secret key for
    user: "Doctor Duh <drduh@users.noreply.github.com>"
    4096-bit RSA key, ID 0x47FE984F98EE7407, created 2016-01-30

    Please select what kind of key you want:
       (3) DSA (sign only)
       (4) RSA (sign only)
       (5) Elgamal (encrypt only)
       (6) RSA (encrypt only)
       (7) DSA (set your own capabilities)
       (8) RSA (set your own capabilities)
    Your selection? 6
    RSA keys may be between 1024 and 4096 bits long.
    What keysize do you want? (2048) 4096
    Requested keysize is 4096 bits
    Please specify how long the key should be valid.
             0 = key does not expire
          <n>  = key expires in n days
          <n>w = key expires in n weeks
          <n>m = key expires in n months
          <n>y = key expires in n years
    Key is valid for? (0) 0
    Key does not expire at all
    Is this correct? (y/N) y
    Really create? (y/N) y
    We need to generate a lot of random bytes. It is a good idea to perform
    some other action (type on the keyboard, move the mouse, utilize the
    disks) during the prime generation; this gives the random number
    generator a better chance to gain enough entropy.

    .+++++
    ...........+++++

    pub  4096R/0x47FE984F98EE7407  created: 2016-01-30  expires: never       usage: SC
 
                                   trust: ultimate      validity: ultimate
    sub  4096R/0xE8E7855AA5AE79A7  created: 2016-01-30  expires: never       usage: S
 
    sub  4096R/0x39988E0390CB4B0C  created: 2016-01-30  expires: never       usage: E

    [ultimate] (1). Doctor Duh <drduh@users.noreply.github.com>

### Authentication key

    gpg> addkey
    Key is protected.
 
    You need a passphrase to unlock the secret key for
    user: "Doctor Duh <drduh@users.noreply.github.com>"
    4096-bit RSA key, ID 0x47FE984F98EE7407, created 2016-01-30
    
    Please select what kind of key you want:
       (3) DSA (sign only)
       (4) RSA (sign only)
       (5) Elgamal (encrypt only)
       (6) RSA (encrypt only)
       (7) DSA (set your own capabilities)
       (8) RSA (set your own capabilities)
    Your selection? 8
    
    Possible actions for a RSA key: Sign Encrypt Authenticate
    Current allowed actions: Sign Encrypt
    
       (S) Toggle the sign capability
       (E) Toggle the encrypt capability
       (A) Toggle the authenticate capability
       (Q) Finished
    
    Your selection? s
    
    Possible actions for a RSA key: Sign Encrypt Authenticate
    Current allowed actions: Encrypt
    
       (S) Toggle the sign capability
       (E) Toggle the encrypt capability
       (A) Toggle the authenticate capability
       (Q) Finished
    
    Your selection? e
    
    Possible actions for a RSA key: Sign Encrypt Authenticate
    Current allowed actions:
    
       (S) Toggle the sign capability
       (E) Toggle the encrypt capability
       (A) Toggle the authenticate capability
       (Q) Finished
    
    Your selection? a
    
    Possible actions for a RSA key: Sign Encrypt Authenticate
    Current allowed actions: Authenticate
    
       (S) Toggle the sign capability
       (E) Toggle the encrypt capability
       (A) Toggle the authenticate capability
       (Q) Finished

    Your selection? q
    RSA keys may be between 1024 and 4096 bits long.
    What keysize do you want? (2048) 4096
    Requested keysize is 4096 bits
    Please specify how long the key should be valid.
             0 = key does not expire
          <n>  = key expires in n days
          <n>w = key expires in n weeks
          <n>m = key expires in n months
          <n>y = key expires in n years
    Key is valid for? (0) 0
    Key does not expire at all
    Is this correct? (y/N) y
    Really create? (y/N) y
    We need to generate a lot of random bytes. It is a good idea to perform
    some other action (type on the keyboard, move the mouse, utilize the
    disks) during the prime generation; this gives the random number
    generator a better chance to gain enough entropy.

    +++++
    .....+++++

    pub  4096R/0x47FE984F98EE7407  created: 2016-01-30  expires: never       usage: SC

                                   trust: ultimate      validity: ultimate
    sub  4096R/0xE8E7855AA5AE79A7  created: 2016-01-30  expires: never       usage: S

    sub  4096R/0x39988E0390CB4B0C  created: 2016-01-30  expires: never       usage: E

    sub  4096R/0x218BCF996C7A6E31  created: 2016-01-30  expires: never       usage: A

    [ultimate] (1). Doctor Duh <drduh@users.noreply.github.com>

    gpg> save

## Check your work

    $ gpg --list-secret-keys
    /tmp/tmp.eBbMfyVDDt/secring.gpg
    -------------------------------
    sec   4096R/0x47FE984F98EE7407 2016-01-30
          Key fingerprint = 044C ABD0 9043 F1E0 3785  3979 47FE 984F 98EE 7407
    uid                            Doctor Duh <drduh@users.noreply.github.com>
    ssb   4096R/0xE8E7855AA5AE79A7 2016-01-30
    ssb   4096R/0x39988E0390CB4B0C 2016-01-30
    ssb   4096R/0x218BCF996C7A6E31 2016-01-30

## Export subkeys

    $ gpg --armor --export-secret-keys 0x47FE984F98EE7407 > $GNUPGHOME/mastersub.key

    $ gpg --armor --export-secret-subkeys 0x47FE984F98EE7407 > $GNUPGHOME/sub.key
    
## Back up everything

Once keys are moved to hardware, they cannot be extracted again (otherwise, what would be the point?), so make sure you have made a backup before proceeding.

    $ cp -avi $GNUPGHOME /mnt/offline-encrypted-usb/backup/

## Configure YubiKey

    $ ykpersonalize -m82
    Firmware version 4.2.7 Touch level 527 Program sequence 4

    The USB mode will be set to: 0x82

    Commit? (y/n) [n]: y

>The -m option is the mode command. To see the different modes, enter ykpersonalize –help. Mode 82 (in hex) enables the YubiKey NEO as a composite USB device (HID + CCID) and allows OTPs to be emitted while in use as a smart card.  Once you have changed the mode, you need to re-boot the YubiKey – so remove and re-insert it.

https://www.yubico.com/2012/12/yubikey-neo-openpgp/

## Configure smartcard

    $ gpg --card-edit

    Application ID ...: D2760001240102010006055532110000
    Version ..........: 2.1
    Manufacturer .....: unknown
    Serial number ....: 05553211
    Name of cardholder: [not set]
    Language prefs ...: [not set]
    Sex ..............: unspecified
    URL of public key : [not set]
    Login data .......: [not set]
    Private DO 1 .....: [not set]
    Private DO 2 .....: [not set]
    Signature PIN ....: not forced
    Key attributes ...: 2048R 2048R 2048R
    Max. PIN lengths .: 127 127 127
    PIN retry counter : 3 3 3
    Signature counter : 0
    Signature key ....: [none]
    Encryption key....: [none]
    Authentication key: [none]
    General key info..: [none]

### Change PINs

The default PIN codes are `12345678` and `123456`.

    gpg/card> admin
    Admin commands are allowed

    gpg/card> passwd
    gpg: OpenPGP card no. D2760001240102010006055532110000 detected

    1 - change PIN
    2 - unblock PIN
    3 - change Admin PIN
    4 - set the Reset Code
    Q - quit

    Your selection? 3
    PIN changed.

    1 - change PIN
    2 - unblock PIN
    3 - change Admin PIN
    4 - set the Reset Code
    Q - quit

    1 - change PIN
    2 - unblock PIN
    3 - change Admin PIN
    4 - set the Reset Code
    Q - quit

    Your selection? 1
    PIN changed.

    1 - change PIN
    2 - unblock PIN
    3 - change Admin PIN
    4 - set the Reset Code
    Q - quit

    Your selection? q

### Set optional card information

    gpg/card> name
    Cardholder's surname: Duh
    Cardholder's given name: Dr

    gpg/card> lang
    Language preferences: en

    gpg/card> login
    Login data (account name): drduh@users.noreply.github.com

    gpg/card>

    Application ID ...: D2760001240102010006055532110000
    Version ..........: 2.1
    Manufacturer .....: unknown
    Serial number ....: 05553211
    Name of cardholder: Dr Duh
    Language prefs ...: en
    Sex ..............: unspecified
    URL of public key : [not set]
    Login data .......: drduh@users.noreply.github.com
    Private DO 4 .....: [not set]
    Signature PIN ....: not forced
    Key attributes ...: 2048R 2048R 2048R
    Max. PIN lengths .: 127 127 127
    PIN retry counter : 3 3 3
    Signature counter : 0
    Signature key ....: [none]
    Encryption key....: [none]
    Authentication key: [none]
    General key info..: [none]

    gpg/card> quit

## Transfer keys

This is a one-way operation only. Make sure you've made a backup before proceeding!

    $ gpg --edit-key 0x47FE984F98EE7407
    gpg (GnuPG) 1.4.18; Copyright (C) 2014 Free Software Foundation, Inc.
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.

    Secret key is available.

    pub  4096R/0x47FE984F98EE7407  created: 2016-01-30  expires: never       usage: SC

                                   trust: ultimate      validity: ultimate
    sub  4096R/0xE8E7855AA5AE79A7  created: 2016-01-30  expires: never       usage: S

    sub  4096R/0x39988E0390CB4B0C  created: 2016-01-30  expires: never       usage: E

    sub  4096R/0x218BCF996C7A6E31  created: 2016-01-30  expires: never       usage: A

    [ultimate] (1). Doctor Duh <drduh@users.noreply.github.com>

    gpg> toggle

    sec  4096R/0x47FE984F98EE7407  created: 2016-01-30  expires: never
    ssb  4096R/0xE8E7855AA5AE79A7  created: 2016-01-30  expires: never
    ssb  4096R/0x39988E0390CB4B0C  created: 2016-01-30  expires: never
    ssb  4096R/0x218BCF996C7A6E31  created: 2016-01-30  expires: never
    (1)  Doctor Duh <drduh@users.noreply.github.com>

    gpg> key 1

    sec  4096R/0x47FE984F98EE7407  created: 2016-01-30  expires: never
    ssb* 4096R/0xE8E7855AA5AE79A7  created: 2016-01-30  expires: never
    ssb  4096R/0x39988E0390CB4B0C  created: 2016-01-30  expires: never
    ssb  4096R/0x218BCF996C7A6E31  created: 2016-01-30  expires: never
    (1)  Doctor Duh <drduh@users.noreply.github.com>

### Signature key

    gpg> keytocard
    Signature key ....: [none]
    Encryption key....: [none]
    Authentication key: [none]

    Please select where to store the key:
       (1) Signature key
       (3) Authentication key
    Your selection? 1

    You need a passphrase to unlock the secret key for
    user: "Doctor Duh <drduh@users.noreply.github.com>"
    4096-bit RSA key, ID 0xE8E7855AA5AE79A7, created 2016-01-30


    sec  4096R/0x47FE984F98EE7407  created: 2016-01-30  expires: never
    ssb* 4096R/0xE8E7855AA5AE79A7  created: 2016-01-30  expires: never
                         card-no: 0006 05553211
    ssb  4096R/0x39988E0390CB4B0C  created: 2016-01-30  expires: never
    ssb  4096R/0x218BCF996C7A6E31  created: 2016-01-30  expires: never
    (1)  Doctor Duh <drduh@users.noreply.github.com>

### Encryption key

Type `key 1` again to deselect and switch to the next key.

    gpg> key 1

    sec  4096R/0x47FE984F98EE7407  created: 2016-01-30  expires: never
    ssb  4096R/0xE8E7855AA5AE79A7  created: 2016-01-30  expires: never
                         card-no: 0006 05553211
    ssb  4096R/0x39988E0390CB4B0C  created: 2016-01-30  expires: never
    ssb  4096R/0x218BCF996C7A6E31  created: 2016-01-30  expires: never
    (1)  Doctor Duh <drduh@users.noreply.github.com>

    gpg> key 2

    sec  4096R/0x47FE984F98EE7407  created: 2016-01-30  expires: never
    ssb  4096R/0xE8E7855AA5AE79A7  created: 2016-01-30  expires: never
                         card-no: 0006 05553211
    ssb* 4096R/0x39988E0390CB4B0C  created: 2016-01-30  expires: never
    ssb  4096R/0x218BCF996C7A6E31  created: 2016-01-30  expires: never
    (1)  Doctor Duh <drduh@users.noreply.github.com>

    gpg> keytocard
    Signature key ....: 04CB BB4B 1D99 3398 A0B1  4C4B E8E7 855A A5AE 79A7
    Encryption key....: [none]
    Authentication key: [none]

    Please select where to store the key:
       (2) Encryption key
    Your selection? 2

    You need a passphrase to unlock the secret key for
    user: "Doctor Duh <drduh@users.noreply.github.com>"
    4096-bit RSA key, ID 0x39988E0390CB4B0C, created 2016-01-30


    sec  4096R/0x47FE984F98EE7407  created: 2016-01-30  expires: never
    ssb  4096R/0xE8E7855AA5AE79A7  created: 2016-01-30  expires: never
                         card-no: 0006 05553211
    ssb* 4096R/0x39988E0390CB4B0C  created: 2016-01-30  expires: never
                         card-no: 0006 05553211
    ssb  4096R/0x218BCF996C7A6E31  created: 2016-01-30  expires: never
    (1)  Doctor Duh <drduh@users.noreply.github.com>

### Authentication key

    gpg> key 2

    sec  4096R/0x47FE984F98EE7407  created: 2016-01-30  expires: never
    ssb  4096R/0xE8E7855AA5AE79A7  created: 2016-01-30  expires: never
                         card-no: 0006 05553211
    ssb  4096R/0x39988E0390CB4B0C  created: 2016-01-30  expires: never
                         card-no: 0006 05553211
    ssb  4096R/0x218BCF996C7A6E31  created: 2016-01-30  expires: never
    (1)  Doctor Duh <drduh@users.noreply.github.com>

    gpg> key 3

    sec  4096R/0x47FE984F98EE7407  created: 2016-01-30  expires: never
    ssb  4096R/0xE8E7855AA5AE79A7  created: 2016-01-30  expires: never
                         card-no: 0006 05553211
    ssb  4096R/0x39988E0390CB4B0C  created: 2016-01-30  expires: never
                         card-no: 0006 05553211
    ssb* 4096R/0x218BCF996C7A6E31  created: 2016-01-30  expires: never
    (1)  Doctor Duh <drduh@users.noreply.github.com>

    gpg> keytocard
    Signature key ....: 04CB BB4B 1D99 3398 A0B1  4C4B E8E7 855A A5AE 79A7
    Encryption key....: 8AB0 607B A1C1 0F19 2627  6EA6 3998 8E03 90CB 4B0C
    Authentication key: [none]

    Please select where to store the key:
       (3) Authentication key
    Your selection? 3

    You need a passphrase to unlock the secret key for
    user: "Doctor Duh <drduh@users.noreply.github.com>"
    4096-bit RSA key, ID 0x218BCF996C7A6E31, created 2016-01-30


    sec  4096R/0x47FE984F98EE7407  created: 2016-01-30  expires: never
    ssb  4096R/0xE8E7855AA5AE79A7  created: 2016-01-30  expires: never
                         card-no: 0006 05553211
    ssb  4096R/0x39988E0390CB4B0C  created: 2016-01-30  expires: never
                         card-no: 0006 05553211
    ssb* 4096R/0x218BCF996C7A6E31  created: 2016-01-30  expires: never
                         card-no: 0006 05553211
    (1)  Doctor Duh <drduh@users.noreply.github.com>

    gpg> save

## Check your work

    $ gpg --list-secret-keys
    /tmp/tmp.eBbMfyVDDt/secring.gpg
    -------------------------------
    sec   4096R/0x47FE984F98EE7407 2016-01-30
          Key fingerprint = 044C ABD0 9043 F1E0 3785  3979 47FE 984F 98EE 7407
    uid                            Doctor Duh <drduh@users.noreply.github.com>
    ssb>  4096R/0xE8E7855AA5AE79A7 2016-01-30
    ssb>  4096R/0x39988E0390CB4B0C 2016-01-30
    ssb>  4096R/0x218BCF996C7A6E31 2016-01-30

`ssb>` indicates a stub to the private key on smartcard.

## Export public key

    $ gpg --armor --export 0x47FE984F98EE7407 > /mnt/public-usb-key/

# Using keys

## Insert YubiKey

    $ gpg --card-status
    Application ID ...: D2760001240102010006055532110000
    Version ..........: 2.1
    Manufacturer .....: unknown
    Serial number ....: 05553211
    Name of cardholder: Dr Duh
    Language prefs ...: en
    Sex ..............: unspecified
    URL of public key : [not set]
    Login data .......: drduh@users.noreply.github.com
    Signature PIN ....: not forced
    Key attributes ...: 4096R 4096R 4096R
    Max. PIN lengths .: 127 127 127
    PIN retry counter : 3 3 3
    Signature counter : 0
    Signature key ....: 04CB BB4B 1D99 3398 A0B1  4C4B E8E7 855A A5AE 79A7
          created ....: 2016-01-30 16:36:40
    Encryption key....: 8AB0 607B A1C1 0F19 2627  6EA6 3998 8E03 90CB 4B0C
          created ....: 2016-01-30 16:42:29
    Authentication key: 3B81 E129 B7C3 26F4 2EA1  2F19 218B CF99 6C7A 6E31
          created ....: 2016-01-30 16:44:48
    General key info..: pub  4096R/0xE8E7855AA5AE79A7 2016-01-30 Doctor Duh <drduh@users.noreply.github.com>
    sec#  4096R/0x47FE984F98EE7407  created: 2016-01-30  expires: never
    ssb>  4096R/0xE8E7855AA5AE79A7  created: 2016-01-30  expires: never
                          card-no: 0006 05553211
    ssb>  4096R/0x39988E0390CB4B0C  created: 2016-01-30  expires: never
                          card-no: 0006 05553211
    ssb>  4096R/0x218BCF996C7A6E31  created: 2016-01-30  expires: never
                          card-no: 0006 05553211

`sec#` indicates master key is not available (as it should be stored encrypted and offline).

## Import public key

    $ gpg --import < /mnt/public-usb-key/pubkey.txt

## Trust master key

    $ gpg --edit-key 0x47FE984F98EE7407
    gpg (GnuPG) 1.4.18; Copyright (C) 2014 Free Software Foundation, Inc.
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.

    Secret key is available.

    pub  4096R/0x47FE984F98EE7407  created: 2016-01-30  expires: never       usage: SC

                                   trust: unknown       validity: unknown
    sub  4096R/0xE8E7855AA5AE79A7  created: 2016-01-30  expires: never       usage: S

    sub  4096R/0x39988E0390CB4B0C  created: 2016-01-30  expires: never       usage: E

    sub  4096R/0x218BCF996C7A6E31  created: 2016-01-30  expires: never       usage: A

    [ unknown] (1). Doctor Duh <drduh@users.noreply.github.com>

    gpg> trust
    pub  4096R/0x47FE984F98EE7407  created: 2016-01-30  expires: never       usage: SC

                                   trust: unknown       validity: unknown
    sub  4096R/0xE8E7855AA5AE79A7  created: 2016-01-30  expires: never       usage: S

    sub  4096R/0x39988E0390CB4B0C  created: 2016-01-30  expires: never       usage: E

    sub  4096R/0x218BCF996C7A6E31  created: 2016-01-30  expires: never       usage: A

    [ unknown] (1). Doctor Duh <drduh@users.noreply.github.com>

    Please decide how far you trust this user to correctly verify other users' keys
    (by looking at passports, checking fingerprints from different sources, etc.)

      1 = I don't know or won't say
      2 = I do NOT trust
      3 = I trust marginally
      4 = I trust fully
      5 = I trust ultimately
      m = back to the main menu

    Your decision? 5
    Do you really want to set this key to ultimate trust? (y/N) y

    pub  4096R/0x47FE984F98EE7407  created: 2016-01-30  expires: never       usage: SC

                                   trust: ultimate      validity: unknown
    sub  4096R/0xE8E7855AA5AE79A7  created: 2016-01-30  expires: never       usage: S

    sub  4096R/0x39988E0390CB4B0C  created: 2016-01-30  expires: never       usage: E

    sub  4096R/0x218BCF996C7A6E31  created: 2016-01-30  expires: never       usage: A

    [ unknown] (1). Doctor Duh <drduh@users.noreply.github.com>
    Please note that the shown key validity is not necessarily correct
    unless you restart the program.

    gpg> quit

## GnuPG

### Create configuration 

    $ cat > ~/.gnupg/gpg.conf
    use-agent
    personal-cipher-preferences AES256 AES192 AES CAST5
    personal-digest-preferences SHA512 SHA384 SHA256 SHA224
    default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed
    cert-digest-algo SHA512
    s2k-digest-algo SHA512
    charset utf-8
    fixed-list-mode
    no-comments
    no-emit-version
    keyid-format 0xlong
    list-options show-uid-validity
    verify-options show-uid-validity
    with-fingerprint
    ^D (Press Control-D)

### Encryption/decryption

    $ echo "$(uname -a)" | gpg --encrypt --armor -r 0x47FE984F98EE7407 | gpg --debug --decrypt --armor

    Please enter the PIN
    gpg: encrypted with 4096-bit RSA key, ID 0x39988E0390CB4B0C, created 2016-01-30
          "Doctor Duh <drduh@users.noreply.github.com>"
    Linux workstation 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt20-1+deb8u3 (2016-01-17) x86_64 GNU/Linux

### Signing

    $ echo "$(uname -a)" | gpg --encrypt --armor --sign -r 0x47FE984F98EE7407
    gpg: signatures created so far: 0

    Please enter the PIN
    [sigs done: 0]
    -----BEGIN PGP MESSAGE-----

    hQIMAzmYjgOQy0sMAQ//bG8YyEinTOFzL/aL/BN54/PAFzBZj6B//dEFXYu5NlHJ
    [...]
    sjLN5ZhJkQKJeUWIVdGeuZN+pIeIRWQHeKD7xRUgij6/nC7qCfPPkHFYxQ==
    =jztu
    -----END PGP MESSAGE-----

## SSH

### Update configuration

    $ cat > ~/.gnupg/gpg-agent.conf
    enable-ssh-support
    pinentry-program /usr/bin/pinentry-curses
    default-cache-ttl 60
    max-cache-ttl 120
    write-env-file
    use-standard-socket
    ^D (Press Control-D)

### Replace ssh-agent with gpg-agent

    $ pkill ssh-agent ; \
      eval $(gpg-agent --daemon --enable-ssh-support --use-standard-socket \
      --log-file ~/.gnupg/gpg-agent.log --write-env-file)

### Copy public key to server

    $ ssh-add -L
    ssh-rsa AAAAB4NzaC1yc2EAAAADAQABAAACAz[...]zreOKM+HwpkHzcy9DQcVG2Nw== cardno:000605553211

### Connect with public key authentication

    $ ssh git@github.com -vvv
    [...]
    debug2: key: cardno:000605553211 (0x1234567890),
    debug1: Authentications that can continue: publickey
    debug3: start over, passed a different list publickey
    debug3: preferred gssapi-keyex,gssapi-with-mic,publickey,keyboard-interactive,password
    debug3: authmethod_lookup publickey
    debug3: remaining preferred: keyboard-interactive,password
    debug3: authmethod_is_enabled publickey
    debug1: Next authentication method: publickey
    debug1: Offering RSA public key: cardno:000605553211
    debug3: send_pubkey_test
    debug2: we sent a publickey packet, wait for reply
    debug1: Server accepts key: pkalg ssh-rsa blen 535
    debug2: input_userauth_pk_ok: fp e5:de:a5:74:b1:3e:96:9b:85:46:e7:28:53:b4:82:c3
    debug3: sign_and_send_pubkey: RSA e5:de:a5:74:b1:3e:96:9b:85:46:e7:28:53:b4:82:c3
    debug1: Authentication succeeded (publickey).
    [...]

# Notes

- Don't write to drduh@users.noreply.github.com, open an issue on GitHub instead.
- Programming YubiKey for GPG keys still lets you use its two slots - OTP and static password modes, for example.
- ECC may be preferred to RSA 4096, but the 1.4.x branch of GnuPG does not support it.
- If you encounter problems, try unplugging and re-inserting your YubiKey. Also try installing and using GnuPG 2.x (`sudo apt-get install gnupg2` and `gpg2`)

# References

<https://developers.yubico.com/yubikey-personalization/>

<https://developers.yubico.com/PGP/Card_edit.html>

<https://blog.josefsson.org/2014/06/23/offline-gnupg-master-key-and-subkeys-on-yubikey-neo-smartcard/>

<https://www.esev.com/blog/post/2015-01-pgp-ssh-key-on-yubikey-neo/>

<https://blog.habets.se/2013/02/GPG-and-SSH-with-Yubikey-NEO>

<https://trmm.net/Yubikey>

<https://rnorth.org/8/gpg-and-ssh-with-yubikey-for-mac>

<https://jclement.ca/articles/2015/gpg-smartcard/>

<https://github.com/herlo/ssh-gpg-smartcard-config>

<http://www.bootc.net/archives/2013/06/09/my-perfect-gnupg-ssh-agent-setup/>

<https://help.riseup.net/en/security/message-security/openpgp/best-practices>
