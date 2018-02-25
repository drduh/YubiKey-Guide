This is a practical guide to using [YubiKey](https://www.yubico.com/faq/yubikey/) as a [SmartCard](https://security.stackexchange.com/questions/38924/how-does-storing-gpg-ssh-private-keys-on-smart-cards-compare-to-plain-usb-drives) for storing GPG encryption and signing keys.

An authentication key can also be created for SSH and used with [gpg-agent](https://unix.stackexchange.com/questions/188668/how-does-gpg-agent-work/188813#188813).

Keys stored on a smartcard like YubiKey seem more difficult to steal than ones stored on disk, and are convenient for everyday use.

Instructions written for Debian GNU/Linux 8 (jessie) using YubiKey 4 - with support for **4096 bit** RSA keys - in OTP+CCID mode, updated to GPG version 2.2.1. Some notes are included for macOS as well. Note, older YubiKeys like the Neo are limited to **2048 bit** RSA keys. Please see a comparison of the different YubiKeys [here](https://www.yubico.com/products/yubikey-hardware/compare-yubikeys/).

Debian live install images are available from [here](https://www.debian.org/CD/live/) and are suitable for writing to USB drives.

Programming YubiKey for GPG keys still lets you use its two slots - [OTP](https://www.yubico.com/faq/what-is-a-one-time-password-otp/) and [static password](https://www.yubico.com/products/services-software/personalization-tools/static-password/) modes, for example.

If you have a comment or suggestion, please open an [issue](https://github.com/drduh/YubiKey-Guide/issues) on GitHub.

- [Purchase YubiKey](#purchase-yubikey)
- [Install required software](#install-required-software)
  - [Install - Linux](#install---linux)
  - [Install - macOS](#install---macos)
- [Creating keys](#creating-keys)
  - [Create temporary working directory for GPG](#create-temporary-working-directory-for-gpg)
  - [Create configuration](#create-configuration)
  - [Create master key](#create-master-key)
  - [Save Key ID](#save-key-id)
  - [Create subkeys](#create-subkeys)
    - [Signing key](#signing-key)
    - [Encryption key](#encryption-key)
    - [Authentication key](#authentication-key)
  - [Check your work](#check-your-work)
  - [Export keys](#export-keys)
  - [Backup everything](#backup-everything)
  - [Configure YubiKey](#configure-yubikey)
  - [Configure smartcard](#configure-smartcard)
    - [Change PINs](#change-pins)
    - [Set card information](#set-card-information)
  - [Transfer keys](#transfer-keys)
    - [Signature key](#signature-key)
    - [Encryption key](#encryption-key-1)
    - [Authentication key](#authentication-key-1)
  - [Check your work](#check-your-work-1)
  - [Export public key](#export-public-key)
  - [Finish](#finish)
- [Using keys](#using-keys)
  - [Create GPG configuration](#create-gpg-configuration)
  - [Import public key](#import-public-key)
  - [Insert YubiKey](#insert-yubikey)
  - [GnuPG](#gnupg)
    - [Trust master key](#trust-master-key)
    - [Encryption](#encryption)
    - [Decryption](#decryption)
    - [Signing](#signing)
    - [Verifying signature](#verifying-signature)
  - [SSH](#ssh)
    - [Update configuration](#update-configuration)
    - [Replace ssh-agent with gpg-agent](#replace-ssh-agent-with-gpg-agent)
    - [Copy public key to server](#copy-public-key-to-server)
    - [Connect with public key authentication](#connect-with-public-key-authentication)
  - [Requiring touch to authenticate](#requiring-touch-to-authenticate)
- [Troubleshooting](#troubleshooting)
  - [Yubikey OTP Mode and cccccccc....](#yubikey-otp-mode-and-cccccccc)
- [References](#references)

# Purchase YubiKey

https://www.yubico.com/products/yubikey-hardware/

https://www.yubico.com/store/

https://www.amazon.com/Yubico/b/ref=bl_dp_s_web_10358012011?ie=UTF8&node=10358012011

Consider purchasing a pair and programming both in case of loss or damage to one of them.

# Install required software

## Install - Linux

You will need to install the following software:

    $ sudo apt-get install -y gnupg2 gnupg-agent pinentry-curses scdaemon pcscd yubikey-personalization libusb-1.0-0-dev

You may also need to download and install more recent versions of [yubikey-personalization](https://developers.yubico.com/yubikey-personalization/Releases/) and [yubico-c](https://developers.yubico.com/yubico-c/Releases/):

    $ curl -sO https://developers.yubico.com/yubikey-personalization/Releases/ykpers-1.17.3.tar.gz

    $ !!.sig
    curl -sO https://developers.yubico.com/yubikey-personalization/Releases/ykpers-1.17.3.tar.gz.sig

    $ gpg ykpers*sig
    gpg: assuming signed data in `ykpers-1.17.3.tar.gz'
    gpg: Signature made Mon 28 Dec 2015 11:56:41 AM UTC
    gpg:                using RSA key 0xBCA00FD4B2168C0A
    gpg: Can't check signature: public key not found

    $ gpg --recv 0xBCA00FD4B2168C0A
    gpg: requesting key 0xBCA00FD4B2168C0A from hkps server hkps.pool.sks-keyservers.net
    mp/2.3
    [...]
    gpg: key 0xBCA00FD4B2168C0A: public key "Klas Lindfors <klas@yubico.com>" imported
    gpg: 3 marginal(s) needed, 1 complete(s) needed, PGP trust model
    gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
    gpg: Total number processed: 1
    gpg:               imported: 1  (RSA: 1)

    $ gpg ykpers*sig
    gpg: assuming signed data in `ykpers-1.17.3.tar.gz'
    gpg: Signature made Mon 28 Dec 2015 11:56:41 AM UTC
    gpg:                using RSA key 0xBCA00FD4B2168C0A
    gpg: Good signature from "Klas Lindfors <klas@yubico.com>" [unknown]
    gpg: WARNING: This key is not certified with a trusted signature!
    gpg:          There is no indication that the signature belongs to the owner.
    Primary key fingerprint: 0A3B 0262 BCA1 7053 07D5  FF06 BCA0 0FD4 B216 8C0A

    $ curl -sO https://developers.yubico.com/yubico-c/Releases/libyubikey-1.13.tar.gz

    $ !!.sig
    curl -sO https://developers.yubico.com/yubico-c/Releases/libyubikey-1.13.tar.gz.sig

    $ gpg libyubi*sig
    gpg: assuming signed data in `libyubikey-1.13.tar.gz'
    gpg: Signature made Thu 05 Mar 2015 11:51:51 AM UTC
    gpg:                using RSA key 0xBCA00FD4B2168C0A
    gpg: Good signature from "Klas Lindfors <klas@yubico.com>" [unknown]
    gpg: WARNING: This key is not certified with a trusted signature!
    gpg:          There is no indication that the signature belongs to the owner.
    Primary key fingerprint: 0A3B 0262 BCA1 7053 07D5  FF06 BCA0 0FD4 B216 8C0A

    $ tar xf libyubikey-1.13.tar.gz

    $ cd libyubikey-1.13

    $ ./configure && make && sudo make install

    $ cd ..

    $ tar xf ykpers-1.17.3.tar.gz

    $ cd ykpers-1.17.3

    $ ./configure && make && sudo make install

    $ sudo ldconfig

If on [Tails](https://tails.boum.org/), you also need to install libykpers-1-1 from the testing repository. This is a temporary fix suggested on a [securedrop issue](https://github.com/freedomofpress/securedrop/issues/1035):

    $ sudo apt-get install -t testing libykpers-1-1

## Install - macOS

You will need to install [Homebrew](https://brew.sh/) and the following brew packages:

    $ brew install gnupg yubikey-personalization

# Creating keys

## Create temporary working directory for GPG

Create a directory in `/tmp` which won't survive a [reboot](https://serverfault.com/questions/377348/when-does-tmp-get-cleared):

    $ export GNUPGHOME=$(mktemp -d) ; echo $GNUPGHOME
    /tmp/tmp.aaiTTovYgo

## Create configuration

Paste the following [text](https://stackoverflow.com/questions/2500436/how-does-cat-eof-work-in-bash) into a terminal window to create a [recommended](https://github.com/drduh/config/blob/master/gpg.conf) GPG configuration:

    $ cat << EOF > $GNUPGHOME/gpg.conf
    use-agent
    personal-cipher-preferences AES256 AES192 AES CAST5
    personal-digest-preferences SHA512 SHA384 SHA256 SHA224
    default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed
    cert-digest-algo SHA512
    s2k-digest-algo SHA512
    s2k-cipher-algo AES256
    charset utf-8
    fixed-list-mode
    no-comments
    no-emit-version
    keyid-format 0xlong
    list-options show-uid-validity
    verify-options show-uid-validity
    with-fingerprint
    EOF

## Create master key

> A note on key expiry: setting an expiry essentially forces you to manage your subkeys and announces to the rest of the world that you are doing so. Setting an expiry on a primary key is ineffective for protecting the key from loss - whoever has the primary key can simply extend its expiry period. Revocation certificates are [better suited](https://security.stackexchange.com/questions/14718/does-openpgp-key-expiration-add-to-security/79386#79386) for this purpose. It may be appropriate for your use case to set expiry dates on subkeys. 

Generate a new key with GPG, selecting RSA (sign only) and the appropriate keysize:

    % gpg --full-generate-key
    gpg (GnuPG) 2.2.1; Copyright (C) 2017 Free Software Foundation, Inc.
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
                            
    GnuPG needs to construct a user ID to identify your key.

    Real name: Dr Duh
    Email address: doc@duh.to
    Comment:
    You selected this USER-ID:
        "Dr Duh <doc@duh.to>"

    Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? o

*You'll be prompted to enter and verify a passphrase. Keep the passphrase handy
as you'll need it throughout.*

    We need to generate a lot of random bytes. It is a good idea to perform
    some other action (type on the keyboard, move the mouse, utilize the
    disks) during the prime generation; this gives the random number
    generator a better chance to gain enough entropy.
    gpg: /tmp.FLZC0xcM/trustdb.gpg: trustdb created
    gpg: key 0xFF3E7D88647EBCDB marked as ultimately trusted
    gpg: directory '/tmp.FLZC0xcM/openpgp-revocs.d' created
    gpg: revocation certificate stored as '/tmp.FLZC0xcM/openpgp-revocs.d/011CE16BD45B27A55BA8776DFF3E7D88647EBCDB.rev'
    public and secret key created and signed.

    Note that this key cannot be used for encryption.  You may want to use
    the command "--edit-key" to generate a subkey for this purpose.
    pub   rsa4096/0xFF3E7D88647EBCDB 2017-10-09 [SC]
          Key fingerprint = 011C E16B D45B 27A5 5BA8  776D FF3E 7D88 647E BCDB
    uid                              Dr Duh <doc@duh.to>

Note that as of [v2.1](https://www.gnupg.org/faq/whats-new-in-2.1.html#autorev), gpg automatically generates a revocation certificate.

## Save Key ID

Export the key ID as a [variable](https://stackoverflow.com/questions/1158091/defining-a-variable-with-or-without-export/1158231#1158231) for use throughout:

    $ export KEYID=0xFF3E7D88647EBCDB

## Create subkeys

Note: If using a Yubikey 4, please use **4096 bit** as the size for the subkeys; if using a YubiKey Neo, please use **2048 bit** as the size for the subkeys.

Edit the key to add subkeys:

    $ gpg --expert --edit-key $KEYID

    Secret key is available.

    sec  rsa4096/0xEA5DE91459B80592
        created: 2017-10-09  expires: never       usage: SC  
        trust: ultimate      validity: ultimate
    [ultimate] (1). Dr Duh <doc@duh.to>

### Signing key

First, create a [signing key](https://stackoverflow.com/questions/5421107/can-rsa-be-both-used-as-encryption-and-signature/5432623#5432623), selecting RSA (sign only):

    gpg> addkey
    Key is protected.

    You need a passphrase to unlock the secret key for
    user: "Dr Duh <doc@duh.to>"
    4096-bit RSA key, ID 0xFF3E7D88647EBCDB, created 2016-05-24

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

    sec  rsa4096/0xFF3E7D88647EBCDB
        created: 2017-10-09  expires: never       usage: SC  
        trust: ultimate      validity: ultimate
    ssb  rsa4096/0xBECFA3C1AE191D15
        created: 2017-10-09  expires: never       usage: S   
    [ultimate] (1). Dr Duh <doc@duh.to>

### Encryption key

Next, create an [encryption key](https://www.cs.cornell.edu/courses/cs5430/2015sp/notes/rsa_sign_vs_dec.php), selecting RSA (encrypt only):

    gpg> addkey
    Please select what kind of key you want:
       (3) DSA (sign only)
       (4) RSA (sign only)
       (5) Elgamal (encrypt only)
       (6) RSA (encrypt only)
       (7) DSA (set your own capabilities)
       (8) RSA (set your own capabilities)
      (10) ECC (sign only)
      (11) ECC (set your own capabilities)
      (12) ECC (encrypt only)
      (13) Existing key
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

    sec  rsa4096/0xFF3E7D88647EBCDB
        created: 2017-10-09  expires: never       usage: SC  
        trust: ultimate      validity: ultimate
    ssb  rsa4096/0xBECFA3C1AE191D15
        created: 2017-10-09  expires: never       usage: S   
    ssb  rsa4096/0x5912A795E90DD2CF
        created: 2017-10-09  expires: never       usage: E   
    [ultimate] (1). Dr Duh <doc@duh.to>

### Authentication key

Finally, create an [authentication key](https://superuser.com/questions/390265/what-is-a-gpg-with-authenticate-capability-used-for).

GPG doesn't provide a 'RSA (authenticate only)' key type out of the box, so select 'RSA (set your own capabilities)' and toggle the required capabilities to end up with an Authenticate-only key:

    gpg> addkey
    Please select what kind of key you want:
       (3) DSA (sign only)
       (4) RSA (sign only)
       (5) Elgamal (encrypt only)
       (6) RSA (encrypt only)
       (7) DSA (set your own capabilities)
       (8) RSA (set your own capabilities)
      (10) ECC (sign only)
      (11) ECC (set your own capabilities)
      (12) ECC (encrypt only)
      (13) Existing key
    Your selection? 8
    
    Possible actions for a RSA key: Sign Encrypt Authenticate 
    Current allowed actions: Sign Encrypt 
    
       (S) Toggle the sign capability
       (E) Toggle the encrypt capability
       (A) Toggle the authenticate capability
       (Q) Finished
    
    Your selection? S
    
    Possible actions for a RSA key: Sign Encrypt Authenticate 
    Current allowed actions: Encrypt 
    
       (S) Toggle the sign capability
       (E) Toggle the encrypt capability
       (A) Toggle the authenticate capability
       (Q) Finished
    
    Your selection? E
    
    Possible actions for a RSA key: Sign Encrypt Authenticate 
    Current allowed actions: 
    
       (S) Toggle the sign capability
       (E) Toggle the encrypt capability
       (A) Toggle the authenticate capability
       (Q) Finished
    
    Your selection? A
    
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


    sec  rsa4096/0xFF3E7D88647EBCDB
        created: 2017-10-09  expires: never       usage: SC  
        trust: ultimate      validity: ultimate
    ssb  rsa4096/0xBECFA3C1AE191D15
        created: 2017-10-09  expires: never       usage: S   
    ssb  rsa4096/0x5912A795E90DD2CF
        created: 2017-10-09  expires: never       usage: E   
    ssb  rsa4096/0x3F29127E79649A3D
        created: 2017-10-09  expires: never       usage: A   
    [ultimate] (1). Dr Duh <doc@duh.to>

    gpg> save

## Check your work

List your new secret keys:

    $ gpg --list-secret-keys
    /tmp.FLZC0xcM/pubring.kbx
    -------------------------------------------------------------------------
    sec   rsa4096/0xFF3E7D88647EBCDB 2017-10-09 [SC]
          Key fingerprint = 011C E16B D45B 27A5 5BA8  776D FF3E 7D88 647E BCDB
    uid                            Dr Duh <doc@duh.to>
    ssb   rsa4096/0xBECFA3C1AE191D15 2017-10-09 [S]
    ssb   rsa4096/0x5912A795E90DD2CF 2017-10-09 [E]
    ssb   rsa4096/0x3F29127E79649A3D 2017-10-09 [A]

Verify with OpenPGP key checks:

Use the automated [key best practice checker](https://riseup.net/en/security/message-security/openpgp/best-practices#openpgp-key-checks):

```
$ sudo apt-get install hopenpgp-tools
$ gpg --export $KEYID | hokey lint
```

The output will display any problems with your key in red text. If everything is green, your key passes each of the tests. If it is red, your key has failed one of the tests.

>hokey may warn (orange text) about cross certification for the authentication key. GPG's [Signing Subkey Cross-Certification](https://gnupg.org/faq/subkey-cross-certify.html) documentation has more detail on cross certification, and gpg v2.2.1 notes "subkey <keyid> does not sign and so does not need to be cross-certified".

## Export keys

Save a copy of your keys:

    $ gpg --armor --export-secret-keys $KEYID > $GNUPGHOME/mastersub.key

    $ gpg --armor --export-secret-subkeys $KEYID > $GNUPGHOME/sub.key

The exported (primary) key will still have the passphrase in place.

In addition to the backup below, you might want to keep a separate copy of the
revocation certificate in a safe place:
`$GNUPGHOME/openpgp-revocs.d/<key fingerprint>.rev`

## Backup everything

Once keys are moved to hardware, they cannot be extracted again (otherwise, what would be the point?), so make sure you have made an *encrypted* backup before proceeding.

Also consider using a [paper copy](http://www.jabberwocky.com/software/paperkey/) of the keys as an additional backup measure.

To create an encrypted USB drive, first attach it and check its label:

    $ dmesg | tail
    [ 7667.607011] scsi8 : usb-storage 2-1:1.0
    [ 7667.608766] usbcore: registered new interface driver usb-storage
    [ 7668.874016] scsi 8:0:0:0: USB 0: 0 ANSI: 6
    [ 7668.874242] sd 8:0:0:0: Attached scsi generic sg4 type 0
    [ 7668.874682] sd 8:0:0:0: [sde] 62980096 512-byte logical blocks: (32.2 GB/30.0 GiB)
    [ 7668.875022] sd 8:0:0:0: [sde] Write Protect is off
    [ 7668.875023] sd 8:0:0:0: [sde] Mode Sense: 43 00 00 00
    [ 7668.877939]  sde: sde1
    [ 7668.879514] sd 8:0:0:0: [sde] Attached SCSI removable disk

Check the size to make sure it's the right drive:

    $ sudo fdisk -l | grep /dev/sde
    Disk /dev/sde: 30 GiB, 32245809152 bytes, 62980096 sectors
    /dev/sde1        2048 62980095 62978048  30G  6 FAT16

Erase and create a new partition table:

    $ sudo fdisk /dev/sde
    
    Welcome to fdisk (util-linux 2.25.2).
    Changes will remain in memory only, until you decide to write them.
    Be careful before using the write command.
    
    Command (m for help): o
    Created a new DOS disklabel with disk identifier 0xeac7ee35.
    
    Command (m for help): w
    The partition table has been altered.
    Calling ioctl() to re-read partition table.
    Syncing disks.

Remove and reinsert the USB drive, then create a new partition, selecting defaults::

    $ sudo fdisk /dev/sde
    
    Welcome to fdisk (util-linux 2.25.2).
    Changes will remain in memory only, until you decide to write them.
    Be careful before using the write command.
    
    Command (m for help): n
    Partition type
       p   primary (0 primary, 0 extended, 4 free)
       e   extended (container for logical partitions)
    Select (default p): p
    Partition number (1-4, default 1): 1
    First sector (2048-62980095, default 2048):
    Last sector, +sectors or +size{K,M,G,T,P} (2048-62980095, default 62980095):
    
    Created a new partition 1 of type 'Linux' and of size 30 GiB.
    Command (m for help): w
    The partition table has been altered.
    Calling ioctl() to re-read partition table.
    Syncing disks.

Use [LUKS](https://askubuntu.com/questions/97196/how-secure-is-an-encrypted-luks-filesystem) to encrypt the new partition:

    $ sudo cryptsetup luksFormat /dev/sde1
    
    WARNING!
    ========
    This will overwrite data on /dev/sde1 irrevocably.
    
    Are you sure? (Type uppercase yes): YES
    Enter passphrase:
    Verify passphrase:

Mount the partition:

    $ sudo cryptsetup luksOpen /dev/sde1 encrypted-usb
    Enter passphrase for /dev/sde1:

Create a filesystem:

    $ sudo mkfs.ext4 /dev/mapper/encrypted-usb -L encrypted-usb
    mke2fs 1.42.12 (29-Aug-2014)
    Creating filesystem with 7871744 4k blocks and 1970416 inodes
    Superblock backups stored on blocks:
            32768, 98304, 163840, 229376, 294912, 819200, 884736, 1605632, 2654208,
            4096000
    
    Allocating group tables: done
    Writing inode tables: done
    Creating journal (32768 blocks): done
    Writing superblocks and filesystem accounting information: done

Mount the filesystem:

    $ sudo mkdir /mnt/usb
    $ sudo mount /dev/mapper/encrypted-usb /mnt/usb

Finally, copy files to it:

    $ sudo cp -avi $GNUPGHOME /mnt/usb
    ‘/tmp/tmp.aaiTTovYgo’ -> ‘/mnt/usb/tmp.aaiTTovYgo’
    ‘/tmp/tmp.aaiTTovYgo/revoke.txt’ -> ‘/mnt/usb/tmp.aaiTTovYgo/revoke.txt’
    ‘/tmp/tmp.aaiTTovYgo/gpg.conf’ -> ‘/mnt/usb/tmp.aaiTTovYgo/gpg.conf’
    ‘/tmp/tmp.aaiTTovYgo/trustdb.gpg’ -> ‘/mnt/usb/tmp.aaiTTovYgo/trustdb.gpg’
    ‘/tmp/tmp.aaiTTovYgo/random_seed’ -> ‘/mnt/usb/tmp.aaiTTovYgo/random_seed’
    ‘/tmp/tmp.aaiTTovYgo/master.key’ -> ‘/mnt/usb/tmp.aaiTTovYgo/master.key’
    ‘/tmp/tmp.aaiTTovYgo/secring.gpg’ -> ‘/mnt/usb/tmp.aaiTTovYgo/secring.gpg’
    ‘/tmp/tmp.aaiTTovYgo/mastersub.key’ -> ‘/mnt/usb/tmp.aaiTTovYgo/mastersub.key’
    ‘/tmp/tmp.aaiTTovYgo/sub.key’ -> ‘/mnt/usb/tmp.aaiTTovYgo/sub.key’
    ‘/tmp/tmp.aaiTTovYgo/pubring.gpg~’ -> ‘/mnt/usb/tmp.aaiTTovYgo/pubring.gpg~’
    ‘/tmp/tmp.aaiTTovYgo/pubring.gpg’ -> ‘/mnt/usb/tmp.aaiTTovYgo/pubring.gpg’

Make sure the correct files were copied, then unmount and disconnected the encrypted USB drive:

    $ sudo umount /mnt/usb
    $ sudo cryptsetup luksClose encrypted-usb

## Configure YubiKey

YubiKey NEOs shipped after November 2015 have [all modes enabled](https://www.yubico.com/support/knowledge-base/categories/articles/yubikey-neo-manager/), skip to the next step.

Older versions of the YubiKey NEO may need to be reconfigured as a composite USB device (HID + CCID) which allows OTPs to be emitted while in use as a smart card.

Plug in your YubiKey and configure it:

    $ ykpersonalize -m82
    Firmware version 4.2.7 Touch level 527 Program sequence 4

    The USB mode will be set to: 0x82

    Commit? (y/n) [n]: y

> The -m option is the mode command. To see the different modes, enter `ykpersonalize –help`. Mode 82 (in hex) enables the YubiKey NEO as a composite USB device (HID + CCID).  Once you have changed the mode, you need to re-boot the YubiKey – so remove and re-insert it.

> On YubiKey NEO with firmware version 3.3 or higher you can enable composite USB device with -m86 instead of -m82.

https://www.yubico.com/2012/12/yubikey-neo-openpgp/
https://www.yubico.com/2012/12/yubikey-neo-composite-device/

## Configure smartcard

Use GPG to configure YubiKey as a smartcard:

    $ gpg --card-edit

    Reader ...........: Yubico Yubikey 4 OTP U2F CCID
    Application ID ...: D2760001240102010006055532110000
    Version ..........: 2.1
    Manufacturer .....: Yubico
    Serial number ....: 05553211
    Name of cardholder: [not set]
    Language prefs ...: [not set]
    Sex ..............: unspecified
    URL of public key : [not set]
    Login data .......: [not set]
    Signature PIN ....: not forced
    Key attributes ...: rsa4096 rsa4096 rsa4096
    Max. PIN lengths .: 127 127 127
    PIN retry counter : 3 3 3
    Signature counter : 0
    Signature key ....: [none]
    Encryption key....: [none]
    Authentication key: [none]
    General key info..: [none]

### Change PINs

The default PIN codes are `12345678` for the Admin PIN (aka PUK) and `123456` for the PIN. The CCID-mode PINs can be up to 127 ASCII characters long.

The Admin PIN is required for some card operations, and to unblock a PIN that has been entered incorrectly more than three times. See the GnuPG documentation on [Managing PINs](https://www.gnupg.org/howtos/card-howto/en/ch03s02.html) for details.

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

    Your selection? 1
    PIN changed.

    1 - change PIN
    2 - unblock PIN
    3 - change Admin PIN
    4 - set the Reset Code
    Q - quit

    Your selection? q

### Set card information

Some fields are optional:

    gpg/card> name
    Cardholder's surname: Duh
    Cardholder's given name: Dr

    gpg/card> lang
    Language preferences: en

    gpg/card> login
    Login data (account name): doc@duh.to

    gpg/card> (Press Enter)

    Application ID ...: D2760001240102010006055532110000
    Version ..........: 2.1
    Manufacturer .....: unknown
    Serial number ....: 05553211
    Name of cardholder: Dr Duh
    Language prefs ...: en
    Sex ..............: unspecified
    URL of public key : [not set]
    Login data .......: doc@duh.to
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

Transferring keys to YubiKey hardware is a one-way operation only, so make sure you've made a backup before proceeding. Previous gpg versions required the 'toggle' command before selecting keys. The currently selected key(s) are indicated with an `*`. When moving keys only one key should be selected at a time.

    % gpg --edit-key $KEYID

    Secret key is available.

    sec  rsa4096/0xFF3E7D88647EBCDB
        created: 2017-10-09  expires: never       usage: SC  
        trust: ultimate      validity: ultimate
    ssb  rsa4096/0xBECFA3C1AE191D15
        created: 2017-10-09  expires: never       usage: S   
    ssb  rsa4096/0x5912A795E90DD2CF
        created: 2017-10-09  expires: never       usage: E   
    ssb  rsa4096/0x3F29127E79649A3D
        created: 2017-10-09  expires: never       usage: A   
    [ultimate] (1). Dr Duh <doc@duh.to>

### Signature key

Select and move the signature key (you will be prompted for the key passphrase and admin PIN):

    gpg> key 1

    sec  rsa4096/0xFF3E7D88647EBCDB
        created: 2017-10-09  expires: never       usage: SC
        trust: ultimate      validity: ultimate
    ssb* rsa4096/0xBECFA3C1AE191D15
        created: 2017-10-09  expires: never       usage: S
    ssb  rsa4096/0x5912A795E90DD2CF
        created: 2017-10-09  expires: never       usage: E
    ssb  rsa4096/0x3F29127E79649A3D
        created: 2017-10-09  expires: never       usage: A
    [ultimate] (1). Dr Duh <doc@duh.to>

    gpg> keytocard
    Please select where to store the key:
       (1) Signature key
       (3) Authentication key
    Your selection? 1

    You need a passphrase to unlock the secret key for
    user: "Dr Duh <doc@duh.to>"
    4096-bit RSA key, ID 0xBECFA3C1AE191D15, created 2016-05-24

### Encryption key

Type `key 1` again to deselect and `key 2` to select the next key:

    gpg> key 1
    ...
    gpg> key 2

    sec  rsa4096/0xFF3E7D88647EBCDB
        created: 2017-10-09  expires: never       usage: SC
        trust: ultimate      validity: ultimate
    ssb  rsa4096/0xBECFA3C1AE191D15
        created: 2017-10-09  expires: never       usage: S
    ssb* rsa4096/0x5912A795E90DD2CF
        created: 2017-10-09  expires: never       usage: E
    ssb  rsa4096/0x3F29127E79649A3D
        created: 2017-10-09  expires: never       usage: A
    [ultimate] (1). Dr Duh <doc@duh.to>

Move the encryption key to card:

    gpg> keytocard
    Please select where to store the key:
       (2) Encryption key
    Your selection? 2
    ...

### Authentication key

Type `key 2` again to deselect and `key 3` to select the next key:

    gpg> key 2
    ...
    gpg> key 3

    sec  rsa4096/0xFF3E7D88647EBCDB
        created: 2017-10-09  expires: never       usage: SC
        trust: ultimate      validity: ultimate
    ssb  rsa4096/0xBECFA3C1AE191D15
        created: 2017-10-09  expires: never       usage: S
    ssb  rsa4096/0x5912A795E90DD2CF
        created: 2017-10-09  expires: never       usage: E
    ssb* rsa4096/0x3F29127E79649A3D
        created: 2017-10-09  expires: never       usage: A
    [ultimate] (1). Dr Duh <doc@duh.to>

Move the authentication key to card:

    gpg> keytocard
    Please select where to store the key:
       (3) Authentication key
    Your selection? 3

Save and quit:

    gpg> save

## Check your work

`ssb>` indicates a stub to the private key on smartcard:

    % gpg --list-secret-keys
    /tmp.FLZC0xcM/pubring.kbx
    -------------------------------------------------------------------------
    sec   rsa4096/0xFF3E7D88647EBCDB 2017-10-09 [SC]
          Key fingerprint = 011C E16B D45B 27A5 5BA8  776D FF3E 7D88 647E BCDB
    uid                            Dr Duh <doc@duh.to>
    ssb>  rsa4096/0xBECFA3C1AE191D15 2017-10-09 [S]
    ssb>  rsa4096/0x5912A795E90DD2CF 2017-10-09 [E]
    ssb>  rsa4096/0x3F29127E79649A3D 2017-10-09 [A]

## Export public key

This file should be publicly shared:

    $ gpg --armor --export $KEYID > /mnt/public-usb-key/pubkey.txt

Optionally, it may be uploaded to a [public keyserver](https://debian-administration.org/article/451/Submitting_your_GPG_key_to_a_keyserver):

    $ gpg --send-key $KEYID
    gpg: sending key 0xFF3E7D88647EBCDB to hkps server hkps.pool.sks-keyservers.net
    [...]

After a little while, it ought to propagate to [other](https://pgp.key-server.io/pks/lookup?search=doc%40duh.to&fingerprint=on&op=vindex) [servers](https://pgp.mit.edu/pks/lookup?search=doc%40duh.to&op=index).

## Finish

If all went well, you should now reboot or [securely delete](http://srm.sourceforge.net/) `$GNUPGHOME`.

# Using keys

## Create GPG configuration 

Paste the following text into a terminal window to create a [recommended](https://github.com/drduh/config/blob/master/gpg.conf) GPG configuration:

    $ cat << EOF > ~/.gnupg/gpg.conf
    auto-key-locate keyserver
    keyserver hkps://hkps.pool.sks-keyservers.net
    keyserver-options no-honor-keyserver-url
    keyserver-options no-honor-keyserver-url
    keyserver-options debug
    keyserver-options verbose
    personal-cipher-preferences AES256 AES192 AES CAST5
    personal-digest-preferences SHA512 SHA384 SHA256 SHA224
    default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed
    cert-digest-algo SHA512
    s2k-cipher-algo AES256
    s2k-digest-algo SHA512
    charset utf-8
    fixed-list-mode
    no-comments
    no-emit-version
    keyid-format 0xlong
    list-options show-uid-validity
    verify-options show-uid-validity
    with-fingerprint
    use-agent
    require-cross-certification
    EOF

## Import public key

Import it from a file:

    $ gpg --import < /mnt/public-usb-key/pubkey.txt
    gpg: key 0xFF3E7D88647EBCDB: public key "Dr Duh <doc@duh.to>" imported
    gpg: Total number processed: 1
    gpg:               imported: 1  (RSA: 1)

Or download from a keyserver:

    $ gpg --recv 0xFF3E7D88647EBCDB
    gpg: requesting key 0xFF3E7D88647EBCDB from hkps server hkps.pool.sks-keyservers.net
    [...]
    gpg: key 0xFF3E7D88647EBCDB: public key "Dr Duh <doc@duh.to>" imported
    gpg: Total number processed: 1
    gpg:               imported: 1  (RSA: 1)

You may get an error `gpgkeys: HTTP fetch error 1: unsupported protocol` -- this means you need to install a special version of curl which supports gnupg:

```
$ sudo apt-get install gnupg-curl
```

## Insert YubiKey

Unplug and replug the Yubikey. Check the card's status:

    $ gpg --card-status
    Application ID ...: D2760001240102010006055532110000
    Version ..........: 2.1
    Manufacturer .....: Yubico
    Serial number ....: 05553211
    Name of cardholder: Dr Duh
    Language prefs ...: en
    Sex ..............: unspecified
    URL of public key : [not set]
    Login data .......: doc@duh.to
    Signature PIN ....: not forced
    Key attributes ...: 4096R 4096R 4096R
    Max. PIN lengths .: 127 127 127
    PIN retry counter : 3 3 3
    Signature counter : 0
    Signature key ....: 07AA 7735 E502 C5EB E09E  B8B0 BECF A3C1 AE19 1D15
          created ....: 2016-05-24 23:22:01
    Encryption key....: 6F26 6F46 845B BEB8 BDF3  7E9B 5912 A795 E90D D2CF
          created ....: 2016-05-24 23:29:03
    Authentication key: 82BE 7837 6A3F 2E7B E556  5E35 3F29 127E 7964 9A3D
          created ....: 2016-05-24 23:36:40
    General key info..: pub  4096R/0xBECFA3C1AE191D15 2016-05-24 Dr Duh <doc@duh.to>
    sec#  4096R/0xFF3E7D88647EBCDB  created: 2016-05-24  expires: never
    ssb>  4096R/0xBECFA3C1AE191D15  created: 2016-05-24  expires: never
                          card-no: 0006 05553211
    ssb>  4096R/0x5912A795E90DD2CF  created: 2016-05-24  expires: never
                          card-no: 0006 05553211
    ssb>  4096R/0x3F29127E79649A3D  created: 2016-05-24  expires: never
                          card-no: 0006 05553211

`sec#` indicates master key is not available (as it should be stored encrypted offline).

**Note** If you see `General key info..: [none]` in the output instead, first import your public key using the previous step.

## GnuPG

### Trust master key

Edit the imported key to assign it ultimate trust:

    $ gpg --edit-key 0xFF3E7D88647EBCDB

    Secret key is available.

    pub  4096R/0xFF3E7D88647EBCDB  created: 2016-05-24  expires: never       usage: SC
                                   trust: unknown       validity: unknown
    sub  4096R/0xBECFA3C1AE191D15  created: 2016-05-24  expires: never       usage: S
    sub  4096R/0x5912A795E90DD2CF  created: 2016-05-24  expires: never       usage: E
    sub  4096R/0x3F29127E79649A3D  created: 2016-05-24  expires: never       usage: A
    [ unknown] (1). Dr Duh <doc@duh.to>

    gpg> trust
    pub  4096R/0xFF3E7D88647EBCDB  created: 2016-05-24  expires: never       usage: SC
                                   trust: unknown       validity: unknown
    sub  4096R/0xBECFA3C1AE191D15  created: 2016-05-24  expires: never       usage: S
    sub  4096R/0x5912A795E90DD2CF  created: 2016-05-24  expires: never       usage: E
    sub  4096R/0x3F29127E79649A3D  created: 2016-05-24  expires: never       usage: A
    [ unknown] (1). Dr Duh <doc@duh.to>

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

    pub  4096R/0xFF3E7D88647EBCDB  created: 2016-05-24  expires: never       usage: SC
                                   trust: ultimate      validity: unknown
    sub  4096R/0xBECFA3C1AE191D15  created: 2016-05-24  expires: never       usage: S
    sub  4096R/0x5912A795E90DD2CF  created: 2016-05-24  expires: never       usage: E
    sub  4096R/0x3F29127E79649A3D  created: 2016-05-24  expires: never       usage: A
    [ unknown] (1). Dr Duh <doc@duh.to>
    Please note that the shown key validity is not necessarily correct
    unless you restart the program.

    gpg> quit

### Encryption

Encrypt some sample text:

    $ echo "$(uname -a)" | gpg --encrypt --armor --recipient 0xFF3E7D88647EBCDB
    -----BEGIN PGP MESSAGE-----

    hQIMA1kSp5XpDdLPAQ/+JyYfLaUS/+llEzQaKDb5mWhG4HlUgD99dNJUXakm085h
    PSSt3I8Ac0ctwyMnenZvBEbHMqdRnfZJsj5pHidKcAZrhgs+he+B1tdZ/KPa8inx
    NIGqd8W1OraVSFmPEdC1kQ5he6R/WCDH1NNel9+fvLtQDCBQaFae/s3yXCSSQU6q
    HKCJLyHK8K9hDvgFmXOY8j1qTknBvDbmYdcCKVE1ejgpUCi3WatusobpWozsp0+b
    6DN8bXyfxLPYm1PTLfW7v4kwddktB8eVioV8A45lndJZvliSqDwxhrwyE5VGsArS
    NmqzBkCaOHQFr0ofL91xgwpCI5kM2ukIR5SxUO4hvzlHn58QVL9GfAyCHMFtJs3o
    Q9eiR0joo9TjTwR8XomVhRJShrrcPeGgu3YmIak4u7OndyBFpu2E79RQ0ehpl2gY
    tSECB6mNd/gt0Wy3y15ccaFI4CVP6jrMN6q3YhXqNC7GgI/OWkVZIAgUFYnbmIQe
    tQ3z3wlbvFFngeFy5IlhsPduK8T9XgPnOtgQxHaepKz0h3m2lJegmp4YZ4CbS9h6
    kcBTUjys5Vin1SLuqL4PhErzmlAZgVzG2PANsnHYPe2hwN4NlFtOND1wgBCtBFBs
    1pqz1I0O+jmyId+jVlAK076c2AwdkVbokKUcIT/OcTc0nwHjOUttJGmkUHlbt/nS
    iAFNniSfzf6fwAFHgsvWiRJMa3keolPiqoUdh0tBIiI1zxOMaiTL7C9BFdpnvzYw
    Krj0pDc7AlF4spWhm58WgAW20P8PGcVQcN6mSTG8jKbXVSP3bvgPXkpGAOLKMV/i
    pLORcRPbauusBqovgaBWU/i3pMYrbhZ+LQbVEaJlvblWu6xe8HhS/jo=
    =pzkv
    -----END PGP MESSAGE-----

### Decryption

Decrypt the sample text by pasting it:

    $ gpg --decrypt --armor
    -----BEGIN PGP MESSAGE-----

    hQIMA1kSp5XpDdLPAQ/+JyYfLaUS/+llEzQaKDb5mWhG4HlUgD99dNJUXakm085h
    PSSt3I8Ac0ctwyMnenZvBEbHMqdRnfZJsj5pHidKcAZrhgs+he+B1tdZ/KPa8inx
    NIGqd8W1OraVSFmPEdC1kQ5he6R/WCDH1NNel9+fvLtQDCBQaFae/s3yXCSSQU6q
    HKCJLyHK8K9hDvgFmXOY8j1qTknBvDbmYdcCKVE1ejgpUCi3WatusobpWozsp0+b
    6DN8bXyfxLPYm1PTLfW7v4kwddktB8eVioV8A45lndJZvliSqDwxhrwyE5VGsArS
    NmqzBkCaOHQFr0ofL91xgwpCI5kM2ukIR5SxUO4hvzlHn58QVL9GfAyCHMFtJs3o
    Q9eiR0joo9TjTwR8XomVhRJShrrcPeGgu3YmIak4u7OndyBFpu2E79RQ0ehpl2gY
    tSECB6mNd/gt0Wy3y15ccaFI4CVP6jrMN6q3YhXqNC7GgI/OWkVZIAgUFYnbmIQe
    tQ3z3wlbvFFngeFy5IlhsPduK8T9XgPnOtgQxHaepKz0h3m2lJegmp4YZ4CbS9h6
    kcBTUjys5Vin1SLuqL4PhErzmlAZgVzG2PANsnHYPe2hwN4NlFtOND1wgBCtBFBs
    1pqz1I0O+jmyId+jVlAK076c2AwdkVbokKUcIT/OcTc0nwHjOUttJGmkUHlbt/nS
    iAFNniSfzf6fwAFHgsvWiRJMa3keolPiqoUdh0tBIiI1zxOMaiTL7C9BFdpnvzYw
    Krj0pDc7AlF4spWhm58WgAW20P8PGcVQcN6mSTG8jKbXVSP3bvgPXkpGAOLKMV/i
    pLORcRPbauusBqovgaBWU/i3pMYrbhZ+LQbVEaJlvblWu6xe8HhS/jo=
    =pzkv
    -----END PGP MESSAGE-----
    gpg: encrypted with 4096-bit RSA key, ID 0x5912A795E90DD2CF, created
    2016-05-24
          "Dr Duh <doc@duh.to>"

    (Press Control-D)

    Linux workstation 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt25-2 (2016-04-08) x86_64 GNU/Linux

### Signing

Sign some sample text using the signing subkey:

    $ echo "$(uname -a)" | gpg --armor --clearsign --default-key 0xBECFA3C1AE191D15
    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    Linux workstation 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt25-2 (2016-04-08) x86_64 GNU/Linux
    -----BEGIN PGP SIGNATURE-----

    iQIcBAEBCgAGBQJXRPo8AAoJEL7Po8GuGR0Vh8wP/jYXTR8SAZIZSMVCOyAjH37f
    k6JxB0rF928WDYPihjo/d0Jd+XpoV1g+oipDRjP78xqR9H/CJZlE10IPQbNaomFs
    +3RGxA3Zr085cVFoixI8rxYOSu0Vs2cAzAbJHNcOcD7vXxTHcX4T8kfKoF9A4U1u
    XTJ42eEjpO0fX76tFX2/Uzxl43ES0dO7Y82ho7xcnaYwakVUEcWfUpfDAroLKZOs
    wCZGr8Z64QDQzxQ9L45Zc61wMx9JEIWD4BnagllfeOYrEwTJfYG8uhDDNYx0jjJp
    j1PBHn5d556aX6DHUH05kq3wszvQ4W40RctLgAA3l1VnEKebhBKjLZA/EePAvQV4
    QM7MFUV1X/pi2zlyoZSnHkVl8b5Q7RU5ZtRpq9fdkDDepeiUo5PNBUMJER1gn4bm
    ri8DtavkwTNWBRLnVR2gHBmVQNN7ZDOkHcfyqR4I9chx6TMpfcxk0zATAHh8Donp
    FVPKySifuXpunn+0MwdZl5XkhHGdpdYQz4/LAZUGhrA9JTnFtc4cl4JrTzufF8Sr
    c3JJumMsyGvw9OQKQHF8gHme4PBu/4P31LpfX9wzPOTpJaI31Sg5kdJLTo9M9Ppo
    uvkmJS7ETjLQZOsRyAEn7gcEKZQGPQcNAgfEgQPoepS/KvvI68u+JMJm4n24k2kQ
    fEkp501u8kAZkWauhiL+
    =+ylJ
    -----END PGP SIGNATURE-----

### Verifying signature

Verify the previous signature:

    $ gpg
    gpg: Go ahead and type your message ...
    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    Linux workstation 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt25-2 (2016-04-08) x86_64 GNU/Linux
    -----BEGIN PGP SIGNATURE-----

    iQIcBAEBCgAGBQJXRPo8AAoJEL7Po8GuGR0Vh8wP/jYXTR8SAZIZSMVCOyAjH37f
    +3RGxA3Zr085cVFoixI8rxYOSu0Vs2cAzAbJHNcOcD7vXxTHcX4T8kfKoF9A4U1u
    XTJ42eEjpO0fX76tFX2/Uzxl43ES0dO7Y82ho7xcnaYwakVUEcWfUpfDAroLKZOs
    wCZGr8Z64QDQzxQ9L45Zc61wMx9JEIWD4BnagllfeOYrEwTJfYG8uhDDNYx0jjJp
    j1PBHn5d556aX6DHUH05kq3wszvQ4W40RctLgAA3l1VnEKebhBKjLZA/EePAvQV4
    QM7MFUV1X/pi2zlyoZSnHkVl8b5Q7RU5ZtRpq9fdkDDepeiUo5PNBUMJER1gn4bm
    ri8DtavkwTNWBRLnVR2gHBmVQNN7ZDOkHcfyqR4I9chx6TMpfcxk0zATAHh8Donp
    FVPKySifuXpunn+0MwdZl5XkhHGdpdYQz4/LAZUGhrA9JTnFtc4cl4JrTzufF8Sr
    c3JJumMsyGvw9OQKQHF8gHme4PBu/4P31LpfX9wzPOTpJaI31Sg5kdJLTo9M9Ppo
    uvkmJS7ETjLQZOsRyAEn7gcEKZQGPQcNAgfEgQPoepS/KvvI68u+JMJm4n24k2kQ
    fEkp501u8kAZkWauhiL+
    =+ylJ
    -----END PGP SIGNATURE-----

    (Press Control-D)

    gpg: Signature made Wed 25 May 2016 00:00:00 AM UTC
    gpg:                using RSA key 0xBECFA3C1AE191D15
    gpg: Good signature from "Dr Duh <doc@duh.to>" [ultimate]
    Primary key fingerprint: 011C E16B D45B 27A5 5BA8  776D FF3E 7D88 647E BCDB
         Subkey fingerprint: 07AA 7735 E502 C5EB E09E  B8B0 BECF A3C1 AE19 1D15

Putting it all together:

    $ echo "$(uname -a)" | gpg --encrypt --sign --armor --default-key 0xFF3E7D88647EBCDB --recipient 0xBECFA3C1AE191D15 | gpg --decrypt --armor
    gpg: encrypted with 4096-bit RSA key, ID 0x5912A795E90DD2CF, created 2016-05-24
          "Dr Duh <doc@duh.to>"
    Linux workstation 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt25-2 (2016-04-08) x86_64 GNU/Linux
    gpg: Signature made Wed 25 May 2016 01:00:00 AM UTC
    gpg:                using RSA key 0xBECFA3C1AE191D15
    gpg: Good signature from "Dr Duh <doc@duh.to>" [ultimate]
    Primary key fingerprint: 011C E16B D45B 27A5 5BA8  776D FF3E 7D88 647E BCDB
         Subkey fingerprint: 07AA 7735 E502 C5EB E09E  B8B0 BECF A3C1 AE19 1D15

## SSH

### Update configuration

Paste the following text into a terminal window to create a [recommended](https://github.com/drduh/config/blob/master/gpg-agent.conf) GPG agent configuration:

    $ cat << EOF > ~/.gnupg/gpg-agent.conf
    enable-ssh-support
    pinentry-program /usr/bin/pinentry-curses
    default-cache-ttl 60
    max-cache-ttl 120
    write-env-file
    EOF

If you are using Linux on the desktop, you may want to use `/usr/bin/pinentry-gnome3` to use a GUI manager. For macOS, try `brew install pinentry-mac`, and adjust the `pinentry-program` setting to suit.

### Replace ssh-agent with gpg-agent

[gpg-agent](https://wiki.archlinux.org/index.php/GnuPG#SSH_agent) provides OpenSSH agent emulation. To launch the agent for use by ssh use the `gpg-connect-agent /bye` or `gpgconf --launch gpg-agent` commands.

Depending on how your environment is set up, you might need to add these to your shell `rc` file:

    export GPG_TTY="$(tty)"
    export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
    gpgconf --launch gpg-agent
    
**Note** On some systems, for example Arch Linux-based distributions, you may need to replace the second and the third line with:

```
export SSH_AUTH_SOCK="/run/user/$UID/gnupg/S.gpg-agent.ssh"
gpg-connect-agent updatestartuptty /bye
```


### Copy public key to server

There is a `-L` option of `ssh-add` that lists public key parameters of all identities currently represented by the agent.  Copy and paste the following output to the server authorized_keys file:

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

**Note** To make multiple connections or securely transfer many files, consider using the [ControlMaster](https://en.wikibooks.org/wiki/OpenSSH/Cookbook/Multiplexing) ssh option. Also see [drduh/config/ssh_config](https://github.com/drduh/config/blob/master/ssh_config).

## Requiring touch to authenticate

By default the Yubikey will perform key operations without requiring a touch from the user. To require a touch for every SSH connection, use the [Yubikey Manager](https://developers.yubico.com/yubikey-manager/) (you'll need the Admin PIN):

    ykman openpgp touch aut on

To require a touch for the signing and encrypting keys as well:

    ykman openpgp touch sig on
    ykman openpgp touch enc on

The Yubikey will blink when it's waiting for the touch.

# Troubleshooting

- If you don't understand some option, read `man gpg`.

- If you encounter problems connecting to YubiKey with GPG, simply try unplugging and re-inserting your YubiKey, and restarting the `gpg-agent` process.

- If you receive the error, `gpg: decryption failed: secret key not available` - you likely need to install GnuPG version 2.x.

- If you receive the error, `Yubikey core error: no yubikey present` - make sure the YubiKey is inserted correctly. It should blink once when plugged in.

- If you still receive the error, `Yubikey core error: no yubikey present` - you likely need to install newer versions of yubikey-personalize as outlined in [Install required software](#install-required-software).

- If you receive the error, `Yubikey core error: write error` - YubiKey is likely locked. Install and run yubikey-personalization-gui to unlock it.

- If you receive the error, `Key does not match the card's capability` - you likely need to use 2048 bit RSA key sizes.

- If you receive the error, `sign_and_send_pubkey: signing failed: agent refused operation` - you probably have ssh-agent running.  Make sure you replaced ssh-agent with gpg-agent as noted above.

- If you still receive the error, `sign_and_send_pubkey: signing failed: agent refused operation` - On Debian, [try](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=835394) `gpg-connect-agent updatestartuptty /bye`

- If you receive the error, `Error connecting to agent: No such file or directory` from `ssh-add -L`, the UNIX file socket that the agent uses for communication with other processes may not be set up correctly. On Debian, try `export SSH_AUTH_SOCK="/run/user/$UID/gnupg/S.gpg-agent.ssh"`

- If you totally screw up, you can [reset the card](https://developers.yubico.com/ykneo-openpgp/ResetApplet.html).

## Yubikey OTP Mode and cccccccc....

The Yubikey has two configurations, one invoked with a short press, and the other with a long press. By default the short-press mode is configured for HID OTP - a brief touch will emit an OTP string starting with `cccccccc`. If you rarely use the OTP mode, you can swap it to the second configuration via the Yubikey Personalization tool. If you *never* use OTP, you can disable it entirely using the [Yubikey Manager](https://developers.yubico.com/yubikey-manager) application (note, this not the similarly named Yubikey NEO Manager).

# References

<https://developers.yubico.com/yubikey-personalization/>

<https://developers.yubico.com/PGP/Card_edit.html>

<https://blog.josefsson.org/2014/06/23/offline-gnupg-master-key-and-subkeys-on-yubikey-neo-smartcard/>

<https://www.esev.com/blog/post/2015-01-pgp-ssh-key-on-yubikey-neo/>

<https://blog.habets.se/2013/02/GPG-and-SSH-with-Yubikey-NEO>

<https://trmm.net/Yubikey>

<https://rnorth.org/gpg-and-ssh-with-yubikey-for-mac>

<https://jclement.ca/articles/2015/gpg-smartcard/>

<https://github.com/herlo/ssh-gpg-smartcard-config>

<http://www.bootc.net/archives/2013/06/09/my-perfect-gnupg-ssh-agent-setup/>

<https://help.riseup.net/en/security/message-security/openpgp/best-practices>

<https://alexcabal.com/creating-the-perfect-gpg-keypair/>

<https://www.void.gr/kargig/blog/2013/12/02/creating-a-new-gpg-key-with-subkeys/>

