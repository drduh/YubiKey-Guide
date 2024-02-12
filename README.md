This is a guide to using [YubiKey](https://www.yubico.com/products/) as a [smart card](https://security.stackexchange.com/questions/38924/how-does-storing-gpg-ssh-private-keys-on-smart-cards-compare-to-plain-usb-drives) for secure encryption, signing and authentication operations.

Keys stored on YubiKey are [non-exportable](https://web.archive.org/web/20201125172759/https://support.yubico.com/hc/en-us/articles/360016614880-Can-I-Duplicate-or-Back-Up-a-YubiKey-), unlike filesystem-based credentials, while remaining convenient for daily use. YubiKey can be configured to require a physical touch for cryptographic operations, reducing the risk of credential compromise.

**Important** If you followed this guide before Jan 2021, *PIN* and *Admin PIN* may be set to default values of `123456` and `12345678`. See [Change PIN](#change-pin) to change PINs.

To suggest an improvement, please send a pull request or open an [issue](https://github.com/drduh/YubiKey-Guide/issues).

**Tip** [drduh/Purse](https://github.com/drduh/Purse) is a password manager which uses GnuPG and YubiKey to securely store and use credentials.

- [Purchase](#purchase)
- [Prepare environment](#prepare-environment)
- [Required software](#required-software)
   * [Debian and Ubuntu](#debian-and-ubuntu)
   * [Fedora](#fedora)
   * [Arch](#arch)
   * [RHEL7](#rhel7)
   * [NixOS](#nixos)
   * [OpenBSD](#openbsd)
   * [macOS](#macos)
   * [Windows](#windows)
- [Entropy](#entropy)
   * [YubiKey](#yubikey)
   * [OneRNG](#onerng)
- [Generate keys](#generate-keys)
   * [Temporary working directory](#temporary-working-directory)
   * [Harden configuration](#harden-configuration)
- [Certify key](#certify-key)
- [Sign with existing key](#sign-with-existing-key)
- [Subkeys](#subkeys)
   * [Signing](#signing)
   * [Encryption](#encryption)
   * [Authentication](#authentication)
   * [Add extra identities](#add-extra-identities)
- [Verify](#verify)
- [Export secret keys](#export-secret-keys)
- [Revocation certificate](#revocation-certificate)
- [Backup](#backup)
- [Export public keys](#export-public-keys)
- [Configure YubiKey](#configure-yubikey)
   * [Enable KDF](#enable-kdf)
   * [Change PIN](#change-pin)
   * [Set information](#set-information)
- [Transfer keys](#transfer-keys)
   * [Signing](#signing-1)
   * [Encryption](#encryption-1)
   * [Authentication](#authentication-1)
- [Verify card](#verify-card)
- [Multiple YubiKeys](#multiple-yubikeys)
   * [Switching between YubiKeys](#switching-between-yubikeys)
- [Multiple Hosts](#multiple-hosts)
- [Finish](#finish)
- [Using keys](#using-keys)
- [Rotating keys](#rotating-keys)
   * [Setup environment](#setup-environment)
   * [Renewing Subkeys](#renewing-subkeys)
   * [Rotating keys](#rotating-keys-1)
- [Adding notations](#adding-notations)
- [SSH](#ssh)
   * [Create configuration](#create-configuration)
   * [Replace agents](#replace-agents)
   * [Copy public key](#copy-public-key)
   * [(Optional) Save public key for identity file configuration](#optional-save-public-key-for-identity-file-configuration)
   * [Connect with public key authentication](#connect-with-public-key-authentication)
   * [Import SSH keys](#import-ssh-keys)
   * [Remote Machines (SSH Agent Forwarding)](#remote-machines-ssh-agent-forwarding)
      + [Use ssh-agent ](#use-ssh-agent)
      + [Use S.gpg-agent.ssh](#use-sgpg-agentssh)
      + [Chained SSH Agent Forwarding](#chained-ssh-agent-forwarding)
   * [GitHub](#github)
   * [OpenBSD](#openbsd-1)
   * [Windows](#windows-1)
      + [WSL](#wsl)
         - [Use ssh-agent or use S.weasel-pageant](#use-ssh-agent-or-use-sweasel-pageant)
         - [Prerequisites](#prerequisites)
         - [WSL configuration](#wsl-configuration)
         - [Remote host configuration](#remote-host-configuration)
   * [macOS](#macos-1)
- [Remote Machines (GPG Agent Forwarding)](#remote-machines-gpg-agent-forwarding)
   * [Steps for older distributions](#steps-for-older-distributions)
   * [Chained GPG Agent Forwarding](#chained-gpg-agent-forwarding)
- [Using Multiple Keys](#using-multiple-keys)
- [Adding an identity](#adding-an-identity)
   * [Updating YubiKey](#updating-yubikey)
- [Require touch](#require-touch)
- [Email](#email)
   * [Mailvelope](#mailvelope)
   * [Mutt](#mutt)
- [Reset](#reset)
   * [Recovery after reset](#recovery-after-reset)
- [Notes](#notes)
- [Troubleshooting](#troubleshooting)
- [Alternatives](#alternatives)
   * [Create keys with batch](#create-keys-with-batch)
- [Additional resources](#additional-resources)

# Purchase

All YubiKeys except the blue "security key" model and the "Bio Series - FIDO Edition" are compatible with this guide. NEO models are limited to 2048-bit RSA keys. Compare YubiKeys [here](https://www.yubico.com/products/yubikey-hardware/compare-products-series/). A list of the YubiKeys compatible with OpenPGP is available [here](https://support.yubico.com/hc/en-us/articles/360013790259-Using-Your-YubiKey-with-OpenPGP). In May 2021, Yubico also released a press release and blog post about supporting resident ssh keys on their YubiKeys including blue "security key 5 NFC" with OpenSSH 8.2 or later, see [here](https://www.yubico.com/blog/github-now-supports-ssh-security-keys/) for more information.

To [verify a YubiKey](https://support.yubico.com/hc/en-us/articles/360013723419-How-to-Confirm-Your-Yubico-Device-is-Genuine), visit [yubico.com/genuine](https://www.yubico.com/genuine/). Insert a Yubico device, and select *Verify Device* to begin the process. Touch the YubiKey when prompted, and if asked, allow the site to see the make and model of the device. This device attestation may help mitigate [supply chain attacks](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEF%20CON%2025%20-%20r00killah-and-securelyfitz-Secure-Tokin-and-Doobiekeys.pdf).

Several portable storage devices (such as microSD cards) for storing encrypted backups are also recommended.

# Prepare environment

To generate cryptographic keys, creating a dedicated secure environment is recommended.

The following is a general ranking of environments most to least likely to be compromised:

1. Daily-use system with unrestricted network access
1. Virtual machine on daily-use host OS (using [virt-manager](https://virt-manager.org/), VirtualBox or VMware)
1. Dedicated and hardened [Debian](https://www.debian.org/) or [OpenBSD](https://www.openbsd.org/) system
1. Live image, such as [Debian Live](https://www.debian.org/CD/live/) or [Tails](https://tails.boum.org/index.en.html)
1. Hardened hardware and firmware ([Coreboot](https://www.coreboot.org/), [Intel ME removed](https://github.com/corna/me_cleaner))
1. Dedicated air-gapped system without network capabilities (ARM-based Raspberry Pi or other architecturally diverse equivalent)

A Debian Linux live image is recommended to balance usability and security.

Download the latest image and signature files:

```console
curl -fLO "https://cdimage.debian.org/debian-cd/current-live/amd64/iso-hybrid/SHA512SUMS"

curl -fLO "https://cdimage.debian.org/debian-cd/current-live/amd64/iso-hybrid/SHA512SUMS.sign"

curl -fLO "https://cdimage.debian.org/debian-cd/current-live/amd64/iso-hybrid/$(awk '/xfce.iso$/ {print $2}' SHA512SUMS)"
```

Download the Debian signing public key:

```console
gpg --keyserver hkps://keyring.debian.org --recv DF9B9C49EAA9298432589D76DA87E80D6294BE9B
```

If the public key cannot be received, use a different keyserver or DNS server:

```console
gpg --keyserver hkps://keyserver.ubuntu.com:443 --recv DF9B9C49EAA9298432589D76DA87E80D6294BE9B
```

Verify the signature:

```console
gpg --verify SHA512SUMS.sign SHA512SUMS
```

`gpg: Good signature from "Debian CD signing key <debian-cd@lists.debian.org>"` must appear in the output.

Verify the cryptographic hash of the image file matches the one in the signed file:

```console
grep $(sha512sum debian-live-*-amd64-xfce.iso) SHA512SUMS
```

See [Verifying authenticity of Debian CDs](https://www.debian.org/CD/verify) for more information.

Mount a portable storage device and copy the image:

**Linux**

```console
$ sudo dmesg | tail
usb-storage 3-2:1.0: USB Mass Storage device detected
scsi host2: usb-storage 3-2:1.0
scsi 2:0:0:0: Direct-Access     TS-RDF5  SD  Transcend    TS3A PQ: 0 ANSI: 6
sd 2:0:0:0: Attached scsi generic sg1 type 0
sd 2:0:0:0: [sdb] 31116288 512-byte logical blocks: (15.9 GB/14.8 GiB)
sd 2:0:0:0: [sdb] Write Protect is off
sd 2:0:0:0: [sdb] Mode Sense: 23 00 00 00
sd 2:0:0:0: [sdb] Write cache: disabled, read cache: enabled, doesn't support DPO or FUA
sdb: sdb1 sdb2
sd 2:0:0:0: [sdb] Attached SCSI removable disk

$ sudo dd if=debian-live-*-amd64-xfce.iso of=/dev/sdb bs=4M status=progress ; sync
465+1 records in
465+1 records out
1951432704 bytes (2.0 GB, 1.8 GiB) copied, 42.8543 s, 45.5 MB/s
```

**OpenBSD**

```console
$ dmesg | tail -n2
sd2 at scsibus4 targ 1 lun 0: <TS-RDF5, SD Transcend, TS3A> SCSI4 0/direct removable serial.0000000000000
sd2: 15193MB, 512 bytes/sector, 31116288 sectors

$ doas dd if=debian-live-*-amd64-xfce.iso of=/dev/rsd2c bs=4m
465+1 records in
465+1 records out
1951432704 bytes transferred in 139.125 secs (14026448 bytes/sec)
```

Power off, then disconnect internal hard drives and all unnecessary devices, such as the wireless card.

# Required software

Boot the live image and configure networking.

**Note** If the screen locks, unlock with `user` / `live`

Open terminal and install required software packages.

## Debian and Ubuntu

```console
sudo apt update

sudo apt -y upgrade

sudo apt -y install \
    wget gnupg2 gnupg-agent dirmngr \
    cryptsetup scdaemon pcscd secure-delete \
    yubikey-personalization
```

**Note** `hopenpgp-tools` is no longer part of the latest Debian stable package repositories. To install it, go to [https://packages.debian.org/sid/hopenpgp-tools](https://packages.debian.org/sid/hopenpgp-tools) to select the correct architecture (likely `amd64`) and then an ftp server.

Edit `/etc/apt/sources.list` and add the ftp server:

```
deb http://ftp.debian.org/debian sid main
```

Then add this to `/etc/apt/preferences` (or a fragment, e.g. `/etc/apt/preferences.d/00-sid`) so that APT still prioritizes packages from the stable repository over sid.

```
Package: *
Pin: release n=sid
Pin-Priority: 10
```

**Note** Live Ubuntu images [may require modification](https://github.com/drduh/YubiKey-Guide/issues/116) to `/etc/apt/sources.list` and may need additional packages:

```console
sudo apt -y install libssl-dev swig libpcsclite-dev
```

**Optional** Install the `ykman` utility, which will allow you to enable touch policies (requires admin PIN):

```console
sudo apt -y install python3-pip python3-pyscard

pip3 install PyOpenSSL

pip3 install yubikey-manager

sudo service pcscd start

~/.local/bin/ykman openpgp info
```

**Note** Debian 12 does not recommend installing non-Debian packaged Python applications globally. But fortunately, it is not necessary as `yubikey-manager` is available in the stable main repository:

```console
sudo apt install yubikey-manager
```

## Fedora

```console
sudo dnf install wget

wget https://github.com/rpmsphere/noarch/raw/master/r/rpmsphere-release-38-1.noarch.rpm

sudo rpm -Uvh rpmsphere-release*rpm

sudo dnf install \
    gnupg2 dirmngr cryptsetup gnupg2-smime \
    pcsc-tools opensc pcsc-lite secure-delete \
    pgp-tools yubikey-personalization-gui
```

## Arch

```console
sudo pacman -Syu gnupg pcsclite ccid hopenpgp-tools yubikey-personalization
```

## RHEL7

```console
sudo yum install -y gnupg2 pinentry-curses pcsc-lite pcsc-lite-libs gnupg2-smime
```

## NixOS

Build an air-gapped NixOS LiveCD image:

```console
ref=$(git ls-remote https://github.com/drduh/Yubikey-Guide refs/heads/master | awk '{print $1}')

nix build --experimental-features "nix-command flakes" github:drduh/YubiKey-Guide/$ref#nixosConfigurations.yubikeyLive.x86_64-linux.config.system.build.isoImage
```

If you have this repository checked out:

Recommended, but optional: update `nixpkgs` and `drduh/config`:

```console
nix flake update --commit-lock-file
```

Build the ISO:

```console
nix build --experimental-features "nix-command flakes" .#nixosConfigurations.yubikeyLive.x86_64-linux.config.system.build.isoImage
```

Copy it to a USB drive:

```console
sudo cp -v result/iso/yubikeyLive.iso /dev/sdb; sync
```

With this image, you won't need to create a [temporary working directory](#temporary-working-directory) or [harden the configuration](#harden-configuration), as it was done when creating the image.

## OpenBSD

```console
doas pkg_add gnupg pcsc-tools
```

## macOS

Download and install [Homebrew](https://brew.sh/) and the following packages:

```console
brew install gnupg yubikey-personalization hopenpgp-tools ykman pinentry-mac wget
```

**Note** An additional Python package dependency may need to be installed to use [`ykman`](https://support.yubico.com/support/solutions/articles/15000012643-yubikey-manager-cli-ykman-user-guide) - `pip install yubikey-manager`

## Windows

Download and install [Gpg4Win](https://www.gpg4win.org/) and [PuTTY](https://putty.org).

You may also need more recent versions of [yubikey-personalization](https://developers.yubico.com/yubikey-personalization/Releases/) and [yubico-c](https://developers.yubico.com/yubico-c/Releases/).

# Entropy

Generating cryptographic keys requires high-quality [randomness](https://www.random.org/randomness/), measured as entropy.

Most operating systems use software-based pseudorandom number generators or CPU-based hardware random number generators (HRNG).

**Optional** A device such as [OneRNG](https://onerng.info/onerng/) may be used to [increase the speed](https://lwn.net/Articles/648550/) and possibly the quality of available entropy.

## YubiKey

YubiKey version 5.2.3 introduced "Enhancements to OpenPGP 3.4 Support" which can gather additional entropy from YubiKey.

To seed PRNG with an additional 512 bytes retrieved from the YubiKey:

```console
echo "SCD RANDOM 512" | gpg-connect-agent | sudo tee /dev/random | hexdump -C
```

## OneRNG

Configure [rng-tools](https://wiki.archlinux.org/index.php/Rng-tools) software:

```console
sudo apt -y install at rng-tools python3-gnupg openssl

wget https://github.com/OneRNG/onerng.github.io/raw/master/sw/onerng_3.7-1_all.deb
```

Verify the package:

```console
$ sha256sum onerng_3.7-1_all.deb
b7cda2fe07dce219a95dfeabeb5ee0f662f64ba1474f6b9dddacc3e8734d8f57  onerng_3.7-1_all.deb
```

Install the package:

```console
sudo dpkg -i onerng_3.7-1_all.deb

echo "HRNGDEVICE=/dev/ttyACM0" | sudo tee /etc/default/rng-tools
```

Insert the device and restart rng-tools:

```console
sudo atd

sudo service rng-tools restart
```

# Generate keys

## Temporary working directory

Create a temporary directory which will be cleared on [reboot](https://en.wikipedia.org/wiki/Tmpfs) and set it as the GnuPG directory:

```console
export GNUPGHOME=$(mktemp -d -t gnupg_$(date +%Y%m%d%H%M)_XXX)
```

## Harden configuration

Import or create a hardened configuration for GnuPG:

```console
wget -O $GNUPGHOME/gpg.conf https://raw.githubusercontent.com/drduh/config/master/gpg.conf
```

The options will look similar to:

```console
$ grep -ve "^#" $GNUPGHOME/gpg.conf
personal-cipher-preferences AES256 AES192 AES
personal-digest-preferences SHA512 SHA384 SHA256
personal-compress-preferences ZLIB BZIP2 ZIP Uncompressed
default-preference-list SHA512 SHA384 SHA256 AES256 AES192 AES ZLIB BZIP2 ZIP Uncompressed
cert-digest-algo SHA512
s2k-digest-algo SHA512
s2k-cipher-algo AES256
charset utf-8
fixed-list-mode
no-comments
no-emit-version
no-greeting
keyid-format 0xlong
list-options show-uid-validity
verify-options show-uid-validity
with-fingerprint
require-cross-certification
no-symkey-cache
use-agent
throw-keyids
```

**Tip** Networking can be disabled for the remainder of the setup.

# Certify key

The primary key to generate is the Certify key, which will be used to issue Subkeys for Encrypt, Sign and Authenticate operations.

The Certify key should be kept offline at all times and only accessed from a secure environment to revoke or issue Subkeys. Keys can also be generated on the YubiKey itself to avoid duplication, however for usability and durability reasons this guide recommends against doing so.

Generate a passphrase which will be needed throughout the guide to create and export Subkeys. The passphrase should be memorized or written down in a secure location, ideally separate from the portable storage device used for key material.

The passphrase is recommended to consist of only upper case letters and numbers for improved readability.

The following command will generate strong passphrases while avoiding ambiguous characters:

```console
LC_ALL=C tr -dc 'A-Z1-9' < /dev/urandom | \
    tr -d "1IOS5U" | fold -w 30 | head -n10 | \
    sed "-es/./ /"{1..26..5} | cut -c2- | tr " " "-"
```

Example output:

```console
A4ZK-YRRJ-8WPM-82NY-CX9T-AGKT
PH9Z-HFDX-QDB9-YMMC-GQZB-Z3EV
EC3H-C42G-8E9K-VF7F-ZWT7-BTL6
B3CA-QCCE-JMNE-VAZG-ZEYD-J3XP
YKP4-M42X-4WWE-WEKR-C3J7-GZYF
ZQWC-E7MN-M7CT-4Y4Z-9QFV-44VY
KY4F-C83Q-BTYQ-V8EM-WGCR-DPZN
GYWQ-WNAC-ERWM-XGAD-6XVD-ZCLD
L8JL-EK8H-Z4ZF-MA93-NND8-FPKA
WM2J-XF7L-QV6D-AWLY-Y2D8-4TQQ
```

**Tip** On Linux or OpenBSD, select the passphrase using the mouse or by double-clicking on it to copy to clipboard. Paste using the middle mouse button or `Shift`-`Insert`

Generate the Certify key with GnuPG:

```console
gpg --expert --full-generate-key
```

Select `(8) RSA (set your own capabilities)`, then type `E` and `S` deselect Encrypt and Sign actions and only the Certify capability remains:

```console
Please select what kind of key you want:
   (1) RSA and RSA (default)
   (2) DSA and Elgamal
   (3) DSA (sign only)
   (4) RSA (sign only)
   (7) DSA (set your own capabilities)
   (8) RSA (set your own capabilities)
   (9) ECC and ECC
  (10) ECC (sign only)
  (11) ECC (set your own capabilities)
  (13) Existing key
  (14) Existing key from card
Your selection? 8

Possible actions for a RSA key: Sign Certify Encrypt Authenticate
Current allowed actions: Sign Certify Encrypt

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? E

Possible actions for a RSA key: Sign Certify Encrypt Authenticate
Current allowed actions: Sign Certify

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished

Your selection? S

Possible actions for a RSA key: Sign Certify Encrypt Authenticate
Current allowed actions: Certify

   (S) Toggle the sign capability
   (E) Toggle the encrypt capability
   (A) Toggle the authenticate capability
   (Q) Finished
```

Type `Q` then `4096` as the requested keysize.

Do **not** set the Certify key to expire (see [Note #3](#notes)).

```console
Your selection? Q
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
```

Input any value for Real name and Email address; Comment is optional:

```console
GnuPG needs to construct a user ID to identify your key.

Real name: YubiKey User
Email address: yubikey@example
Comment:
You selected this USER-ID:
    "YubiKey User <yubikey@example>"

Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? O
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: /tmp/gnupg_202401011200_TnL/trustdb.gpg: trustdb created
gpg: directory '/tmp/gnupg_202401011200_TnL/openpgp-revocs.d' created
gpg: revocation certificate stored as '/tmp/gnupg_202401011200_TnL/openpgp-revocs.d/4E2C1FA3372CBA96A06AC34AF0F2CFEB04341FB5.rev'
public and secret key created and signed.

pub   rsa4096/0xF0F2CFEB04341FB5 2024-01-01 [C]
      Key fingerprint = 4E2C 1FA3 372C BA96 A06A  C34A F0F2 CFEB 0434 1FB5
uid                              YubiKey User <yubikey@example>
```

Copy the Certify key identifier beginning with `0x` and export it as a [variable](https://stackoverflow.com/questions/1158091/defining-a-variable-with-or-without-export/1158231#1158231) (`KEYID`):

```console
export KEYID=0xF0F2CFEB04341FB5
```

# Sign with existing key

**Optional** Existing PGP keys may be used to sign new ones to prove ownership.

Export the existing key to move it to the working keyring:

```console
gpg --export-secret-keys --armor --output /tmp/new.sec
```

Sign the new key:

```console
gpg --default-key $OLDKEY --sign-key $KEYID
```

# Subkeys

Edit the identity to add Subkeys:

```console
gpg --expert --edit-key $KEYID
```

RSA with 4096-bit key length is recommended.

Subkeys are recommended to have one or several year expirations. They must be renewed using the Certify key - see [Rotating keys](#rotating-keys).

## Signing

Create a [signing key](https://stackoverflow.com/questions/5421107/can-rsa-be-both-used-as-encryption-and-signature/5432623#5432623) by typing `addkey` then select the `(4) RSA (sign only)` option:

```console
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
  (14) Existing key from card
Your selection? 4
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (3072) 4096
Requested keysize is 4096 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 2y
Is this correct? (y/N) y
Really create? (y/N) y
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.

sec  rsa4096/0xF0F2CFEB04341FB5
     created: 2024-01-01  expires: never       usage: C
     trust: ultimate      validity: ultimate
ssb  rsa4096/0xB3CD10E502E19637
     created: 2024-01-01  expires: 2026-01-01  usage: S
[ultimate] (1). YubiKey User <yubikey@example>
```

## Encryption

Next, create an [encryption key](https://www.cs.cornell.edu/courses/cs5430/2015sp/notes/rsa_sign_vs_dec.php) by typing `addkey` then select the `(6) RSA (encrypt only)` option:

```console
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
  (14) Existing key from card
Your selection? 6
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (3072) 4096
Requested keysize is 4096 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 2y
Is this correct? (y/N) y
Really create? (y/N) y
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.

sec  rsa4096/0xF0F2CFEB04341FB5
     created: 2024-01-01  expires: never       usage: C
     trust: ultimate      validity: ultimate
ssb  rsa4096/0xB3CD10E502E19637
     created: 2024-01-01  expires: 2026-01-01  usage: S
ssb  rsa4096/0x30CBE8C4B085B9F7
     created: 2024-01-01  expires: 2026-01-01  usage: E
[ultimate] (1). YubiKey User <yubikey@example>
```

## Authentication

Finally, create an [authentication key](https://superuser.com/questions/390265/what-is-a-gpg-with-authenticate-capability-used-for) by typing `addkey` then select the `(8) RSA (set your own capabilities)` option.

Toggle the required capabilities with `S`, `E` and `A` until `Authenticate` is the only selected action:

```console
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
  (14) Existing key from card
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

Your selection? Q
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048) 4096
Requested keysize is 4096 bits
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 2y
Is this correct? (y/N) y
Really create? (y/N) y
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.

sec  rsa4096/0xF0F2CFEB04341FB5
     created: 2024-01-01  expires: never       usage: C
     trust: ultimate      validity: ultimate
ssb  rsa4096/0xB3CD10E502E19637
     created: 2024-01-01  expires: 2026-01-01  usage: S
ssb  rsa4096/0x30CBE8C4B085B9F7
     created: 2024-01-01  expires: 2026-01-01  usage: E
ssb  rsa4096/0xAD9E24E1B8CB9600
     created: 2024-01-01  expires: 2026-01-01  usage: A
[ultimate] (1). YubiKey User <yubikey@example>
```

Finish by saving the keys:

```console
gpg> save
```

## Add extra identities

**Optional** To add additional email addresses or identities, use `adduid`

Edit the identity:

```console
gpg --expert --edit-key $KEYID
```

Add the new identity:

```console
gpg> adduid
Real name: YubiKey User
Email address: yubikey@somewhere
Comment:
You selected this USER-ID:
    "YubiKey User <yubikey@somewhere>"

Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? o

sec  rsa4096/0xF0F2CFEB04341FB5
     created: 2024-01-01  expires: never       usage: C
     trust: ultimate      validity: ultimate
ssb  rsa4096/0xB3CD10E502E19637
     created: 2024-01-01  expires: 2026-01-01  usage: S
ssb  rsa4096/0x30CBE8C4B085B9F7
     created: 2024-01-01  expires: 2026-01-01  usage: E
ssb  rsa4096/0xAD9E24E1B8CB9600
     created: 2024-01-01  expires: 2026-01-01  usage: A
[ultimate] (1)  YubiKey User <yubikey@example>
[ unknown] (2). YubiKey User <yubikey@somewhere>
```

Configure trust:

```console
gpg> trust
[...]
Your decision? 5
Do you really want to set this key to ultimate trust? (y/N) y
[...]
gpg> save
```

By default, the latest identity added will be the primary user ID. Select `uid 2` or equivalent and `primary` to change it.

# Verify

List available secret keys:

```console
gpg -K
```

Verify output:

```console
---------------------------------------
sec   rsa4096/0xF0F2CFEB04341FB5 2024-01-01 [C]
      Key fingerprint = 4E2C 1FA3 372C BA96 A06A  C34A F0F2 CFEB 0434 1FB5
uid                   [ultimate] YubiKey User <yubikey@example>
ssb   rsa4096/0xB3CD10E502E19637 2024-01-01 [S] [expires: 2026-01-01]
ssb   rsa4096/0x30CBE8C4B085B9F7 2024-01-01 [E] [expires: 2026-01-01]
ssb   rsa4096/0xAD9E24E1B8CB9600 2024-01-01 [A] [expires: 2026-01-01]
```

**Optional** Verify with a OpenPGP [key best practice checker](https://riseup.net/en/security/message-security/openpgp/best-practices#openpgp-key-checks):

```console
gpg --export $KEYID | hokey lint
```

hokey may warn (orange text) about cross certification for the authentication key. GnuPG [Signing Subkey Cross-Certification](https://gnupg.org/faq/subkey-cross-certify.html) documentation has more detail on cross certification, and version 2.2.1 notes "subkey <keyid> does not sign and so does not need to be cross-certified".

hokey may also indicate a problem (red text) with `Key expiration times: []` on the primary key - see [Note #3](#notes).

# Export secret keys

Save a copy of all keys:

```console
gpg --armor --export-secret-keys $KEYID > $GNUPGHOME/certify.key

gpg --armor --export-secret-subkeys $KEYID > $GNUPGHOME/subkeys.key
```

On Windows, note that using any extension other than `.gpg` or attempting IO redirection to a file will garble the secret key, making it impossible to import it again at a later date:

```console
gpg -o \path\to\dir\certify.gpg --armor --export-secret-keys $KEYID

gpg -o \path\to\dir\subkeys.gpg --armor --export-secret-subkeys $KEYID
```

# Revocation certificate

Although the Certify key may be backed up to a secure place, the possibility of losing it cannot be ruled out. Without the Certify key, it will be impossible to renew or rotate Subkeys or generate a revocation certificate; the PGP identity will be useless. To mitigate this risk, deprecate an orphaned identity with a revocation certificate.

To create one:

``` console
gpg --output $GNUPGHOME/revoke.asc --gen-revoke $KEYID
```

The `revoke.asc` file should be stored in a secondary location to the primary backup.

# Backup

Create an **encrypted** backup on portable storage to be kept offline in a secure and durable location.
	
**Tip** The [ext2](https://en.wikipedia.org/wiki/Ext2) filesystem without encryption can be mounted on Linux and OpenBSD. Use [FAT32](https://en.wikipedia.org/wiki/Fat32) or [NTFS](https://en.wikipedia.org/wiki/Ntfs) filesystem for macOS and Windows compatibility instead.

As an additional backup measure, use [Paperkey](https://www.jabberwocky.com/software/paperkey/) to make a physical copy of materials. See [Linux Kernel Maintainer PGP Guide](https://www.kernel.org/doc/html/latest/process/maintainer-pgp-guide.html#back-up-your-master-key-for-disaster-recovery) for more information.

It is strongly recommended to keep even encrypted OpenPGP private key material offline to deter [key overwriting attacks](https://www.kopenpgp.com/), for example.

**Linux**

Attach another portable storage device and check its label:

```console
$ sudo dmesg | tail
mmc0: new high speed SDHC card at address a001
mmcblk0: mmc0:a001 SS16G 14.8 GiB

$ sudo fdisk -l /dev/mmcblk0
Disk /dev/mmcblk0: 14.9 GiB, 15931539456 bytes, 31116288 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
```

Write it with random data to prepare for encryption:

```console
sudo dd if=/dev/urandom of=/dev/mmcblk0 bs=4M status=progress
```

Erase and create a new partition table:

```console
$ sudo fdisk /dev/mmcblk0

Welcome to fdisk (util-linux 2.33.1).

Command (m for help): g
Created a new GPT disklabel (GUID: 4E7495FD-85A3-3E48-97FC-2DD8D41516C3).

Command (m for help): w
The partition table has been altered.
Calling ioctl() to re-read partition table.
Syncing disks.

```

Create a new partition with a 25 Megabyte size:

```console
$ sudo fdisk /dev/mmcblk0

Welcome to fdisk (util-linux 2.36.1).

Command (m for help): n
Partition number (1-128, default 1):
First sector (2048-30261214, default 2048):
Last sector, +/-sectors or +/-size{K,M,G,T,P} (2048-30261214, default 30261214): +25M

Created a new partition 1 of type 'Linux filesystem' and of size 25 MiB.

Command (m for help): w
The partition table has been altered.
Calling ioctl() to re-read partition table.
Syncing disks.
```

Use [LUKS](https://askubuntu.com/questions/97196/how-secure-is-an-encrypted-luks-filesystem) to encrypt the new partition. Generate a unique passphrase which will be used to protect the filesystem:

```console
sudo cryptsetup luksFormat /dev/mmcblk0p1
```

Mount the partition:

```console
sudo cryptsetup luksOpen /dev/mmcblk0p1 secret
```

Create an ext2 filesystem:

```console
sudo mkfs.ext2 /dev/mapper/secret -L gpg-$(date +%F)
```

Mount the filesystem and copy the temporary GnuPG directory with keyring:

```console
sudo mkdir /mnt/encrypted-storage

sudo mount /dev/mapper/secret /mnt/encrypted-storage

sudo cp -avi $GNUPGHOME /mnt/encrypted-storage/
```

**Optional** Backup the OneRNG package:

```console
sudo cp onerng_3.7-1_all.deb /mnt/encrypted-storage/
```

**Note** To set up multiple keys, keep the backup mounted or remember to terminate the GnuPG process before [saving](https://lists.gnupg.org/pipermail/gnupg-users/2016-July/056353.html).

Unmount, close and disconnect the encrypted volume:

```console
sudo umount /mnt/encrypted-storage/

sudo cryptsetup luksClose secret
```

**OpenBSD**

Attach a USB disk and determine its label:

```console
$ dmesg | grep sd.\ at
sd2 at scsibus5 targ 1 lun 0: <TS-RDF5, SD Transcend, TS37> SCSI4 0/direct removable serial.00000000000000000000
```

Print the existing partitions to make sure it's the right device:

```console
doas disklabel -h sd2
```

Initialize the disk by creating an `a` partition with FS type `RAID` and size of 25 Megabytes:

```console
$ doas fdisk -giy sd2
Writing MBR at offset 0.
Writing GPT.

$ doas disklabel -E sd2
Label editor (enter '?' for help at any prompt)
sd2> a a
offset: [64]
size: [31101776] 25M
FS type: [4.2BSD] RAID
sd2*> w
sd2> q
No label changes
```

Encrypt with bioctl:

```console
$ doas bioctl -c C -l sd2a softraid0
New passphrase:
Re-type passphrase:
softraid0: CRYPTO volume attached as sd3
```

Create an `i` partition on the new crypto volume and the filesystem:

```console
$ doas fdisk -giy sd3
Writing MBR at offset 0.
Writing GPT.

$ doas disklabel -E sd3
Label editor (enter '?' for help at any prompt)
sd3> a i
offset: [64]
size: [16001]
FS type: [4.2BSD]
sd3*> w
sd3> q
No label changes.

$ doas newfs sd3i
```

Mount the filesystem and copy the temporary directory with the keyring:

```console
doas mkdir /mnt/encrypted-storage

doas mount /dev/sd3i /mnt/encrypted-storage

doas cp -avi $GNUPGHOME /mnt/encrypted-storage
```

**Note** To set up multiple YubiKeys, keep the backup mounted or remember to terminate GnuPG before [saving](https://lists.gnupg.org/pipermail/gnupg-users/2016-July/056353.html).

Otherwise, unmount and disconnect the encrypted volume:

```console
doas umount /mnt/encrypted-storage

doas bioctl -d sd3
```

See [OpenBSD FAQ#14](https://www.openbsd.org/faq/faq14.html#softraidCrypto) for more information.

# Export public keys

**Important** Without the *public* key, it will **not** be possible to use GnuPG to encrypt, decrypt, nor sign messages. However, YubiKey may still be used for SSH authentication.

Create another partition on the portable storage device to store the public key, or reconnect networking and upload to a key server.

**Linux**

Provision the portable storage device:

```console
$ sudo fdisk /dev/mmcblk0

Welcome to fdisk (util-linux 2.36.1).

Command (m for help): n
Partition number (2-128, default 2):
First sector (53248-30261214, default 53248):
Last sector, +/-sectors or +/-size{K,M,G,T,P} (53248-30261214, default 30261214): +25M

Created a new partition 2 of type 'Linux filesystem' and of size 25 MiB.

Command (m for help): w
The partition table has been altered.
Calling ioctl() to re-read partition table.
Syncing disks.
```

Create a filesystem and export the public key to it:

```console
sudo mkfs.ext2 /dev/mmcblk0p2

sudo mkdir /mnt/public

sudo mount /dev/mmcblk0p2 /mnt/public/

gpg --armor --export $KEYID | sudo tee /mnt/public/$KEYID-$(date +%F).asc
```

**OpenBSD**

```console
$ doas disklabel -E sd2
Label editor (enter '?' for help at any prompt)
sd2> a b
offset: [32130]
size: [31069710] 25M
FS type: [swap] 4.2BSD
sd2*> w
sd2> q
No label changes.
```

Create a filesystem and export the public key to it:

```console
doas newfs sd2b

doas mkdir /mnt/public

doas mount /dev/sd2b /mnt/public

gpg --armor --export $KEYID | doas tee /mnt/public/$KEYID-$(date +%F).asc
```

**Windows**

```console
gpg -o \path\to\dir\pubkey.gpg --armor --export $KEYID
```

**Keyserver**

**Optional** Upload the public key to a [public keyserver](https://debian-administration.org/article/451/Submitting_your_GPG_key_to_a_keyserver):

```console
gpg --send-key $KEYID

gpg --keyserver keys.gnupg.net --send-key $KEYID

gpg --keyserver hkps://keyserver.ubuntu.com:443 --send-key $KEYID
```

Or if [uploading to keys.openpgp.org](https://keys.openpgp.org/about/usage):

```console
gpg --send-key $KEYID | curl -T - https://keys.openpgp.org
```

# Configure YubiKey

Insert YubiKey and use GnuPG to configure it:

```console
$ gpg --card-edit

Reader ...........: Yubico Yubikey 4 OTP U2F CCID
Application ID ...: D2760001240102010006055532110000
Application type .: OpenPGP
Version ..........: 3.4
Manufacturer .....: Yubico
Serial number ....: 05553211
Name of cardholder: [not set]
Language prefs ...: [not set]
Salutation .......:
URL of public key : [not set]
Login data .......: [not set]
Signature PIN ....: not forced
Key attributes ...: rsa2048 rsa2048 rsa2048
Max. PIN lengths .: 127 127 127
PIN retry counter : 3 0 3
Signature counter : 0
KDF setting ......: off
Signature key ....: [none]
Encryption key....: [none]
Authentication key: [none]
General key info..: [none]
```

Enter administrative mode:

```console
gpg/card> admin
Admin commands are allowed
```

**Note** If the card is locked, see [Reset](#reset).

**Windows**

Use the [YubiKey Manager](https://developers.yubico.com/yubikey-manager) application (note, this is not the similarly named older YubiKey NEO Manager) to enable CCID functionality.

## Enable KDF

Key Derived Function (KDF) enables YubiKey to store the hash of PIN, preventing the PIN from being passed as plain text.

**Note** This feature may not be compatible with older GnuPG versions, especially mobile clients. These incompatible clients will not function because the PIN will always be rejected.

```console
gpg/card> kdf-setup
```

This step must be completed before changing PINs or moving keys or an error will occur: `gpg: error for setup KDF: Conditions of use not satisfied`

## Change PIN

The [PGP interface](https://developers.yubico.com/PGP/) is separate from other modules on YubiKey, such as the [PIV interface](https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html) - the PGP interface has its own *PIN*, *Admin PIN*, and *Reset Code* which must be changed from default values.

Entering the *PIN* incorrectly three times will cause the PIN to become blocked. It can be unblocked with either the *Admin PIN* or *Reset Code*.

Entering the *Admin PIN* or *Reset Code* incorrectly three times destroys all GnuPG data on the card.

Name       | Default Value | Use
-----------|---------------|-------------------------------------------------------------
PIN        | `123456`      | cryptographic operations (decrypt, sign, authenticate) PIN
Admin PIN  | `12345678`    | reset PIN, change Reset Code, add keys and owner information
Reset Code | None          | reset PIN ([more information](https://forum.yubico.com/viewtopicd01c.html?p=9055#p9055))

*PIN* values must be at least 6 characters. *Admin PIN* values must be at least 8 characters.

A maximum of 127 ASCII characters are allowed. See the GnuPG documentation on [Managing PINs](https://www.gnupg.org/howtos/card-howto/en/ch03s02.html) for more information.

Update PINs:

```console
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
```

**Note** The number of retry attempts can be changed later with the following command, documented [here](https://docs.yubico.com/software/yubikey/tools/ykman/OpenPGP_Commands.html#ykman-openpgp-access-set-retries-options-pin-retries-reset-code-retries-admin-pin-retries):

```bash
ykman openpgp access set-retries 5 5 5 -f -a YOUR_ADMIN_PIN
```

## Set information

While still in administrative mode:

```console
gpg/card> list

gpg/card> name
Cardholder's surname: User
Cardholder's given name: YubiKey

gpg/card> lang
Language preferences: en

gpg/card> login
Login data (account name): yubikey@example

gpg/card> quit
```

# Transfer keys

**Important** Transferring keys to YubiKey is a one-way operation. Verify backups were made before proceeding. `keytocard` converts the local, on-disk key into a stub, which means the on-disk copy is no longer usable to transfer to subsequent YubiKeys.

The currently selected key(s) are indicated with an `*`. When transferring keys, only one subkey should be selected at a time.

```console
gpg --edit-key $KEYID
```

## Signing

The Certify key passphrase and Admin PIN are required for this step.

Select and transfer the signature key - `*` will appear next to the selected subkey (`ssb*`):

```console
gpg> key 1

sec  rsa4096/0xF0F2CFEB04341FB5
     created: 2024-01-01  expires: never       usage: C
     trust: ultimate      validity: ultimate
ssb* rsa4096/0xB3CD10E502E19637
     created: 2024-01-01  expires: 2026-01-01  usage: S
ssb  rsa4096/0x30CBE8C4B085B9F7
     created: 2024-01-01  expires: 2026-01-01  usage: E
ssb  rsa4096/0xAD9E24E1B8CB9600
     created: 2024-01-01  expires: 2026-01-01  usage: A
[ultimate] (1). YubiKey User <yubikey@example>

gpg> keytocard
Please select where to store the key:
   (1) Signature key
   (3) Authentication key
Your selection? 1
```

## Encryption

Type `key 1` again to deselect the first key and `key 2` to select the next key:

```console
gpg> key 1

gpg> key 2

sec  rsa4096/0xF0F2CFEB04341FB5
     created: 2024-01-01  expires: never       usage: C
     trust: ultimate      validity: ultimate
ssb  rsa4096/0xB3CD10E502E19637
     created: 2024-01-01  expires: 2026-01-01  usage: S
ssb* rsa4096/0x30CBE8C4B085B9F7
     created: 2024-01-01  expires: 2026-01-01  usage: E
ssb  rsa4096/0xAD9E24E1B8CB9600
     created: 2024-01-01  expires: 2026-01-01  usage: A
[ultimate] (1). YubiKey User <yubikey@example>

gpg> keytocard
Please select where to store the key:
   (2) Encryption key
Your selection? 2
```

## Authentication

Type `key 2` again to deselect the second key and `key 3` to select the last key:

```console
gpg> key 2

gpg> key 3

sec  rsa4096/0xF0F2CFEB04341FB5
     created: 2024-01-01  expires: never       usage: C
     trust: ultimate      validity: ultimate
ssb  rsa4096/0xB3CD10E502E19637
     created: 2024-01-01  expires: 2026-01-01  usage: S
ssb  rsa4096/0x30CBE8C4B085B9F7
     created: 2024-01-01  expires: 2026-01-01  usage: E
ssb* rsa4096/0xAD9E24E1B8CB9600
     created: 2024-01-01  expires: 2026-01-01  usage: A
[ultimate] (1). YubiKey User <yubikey@example>

gpg> keytocard
Please select where to store the key:
   (3) Authentication key
Your selection? 3
```

Save and quit:

```console
gpg> save
```

# Verify card

Verify Subkeys have been moved to YubiKey as indicated by `ssb>` with `gpg -K`, for example:

```console
sec   rsa4096/0xF0F2CFEB04341FB5 2024-01-01 [C]
      Key fingerprint = 4E2C 1FA3 372C BA96 A06A  C34A F0F2 CFEB 0434 1FB5
uid                   [ultimate] YubiKey User <yubikey@example>
ssb>  rsa4096/0xB3CD10E502E19637 2024-01-01 [S] [expires: 2026-01-01]
ssb>  rsa4096/0x30CBE8C4B085B9F7 2024-01-01 [E] [expires: 2026-01-01]
ssb>  rsa4096/0xAD9E24E1B8CB9600 2024-01-01 [A] [expires: 2026-01-01]
```

# Multiple YubiKeys

To provision additional YubiKeys, restore the Certify key backup and repeat [Configure YubiKey](#configure-yubikey).

```console
mv -vi $GNUPGHOME $GNUPGHOME.1

cp -avi /mnt/encrypted-storage/tmp.XXX $GNUPGHOME

cd $GNUPGHOME
```

## Switching between YubiKeys

When GnuPG key is added to YubiKey using the *keytocard* command, the key is deleted from the keyring and a *stub* is added, pointing to the YubiKey. The stub identifies the GnuPG key ID and YubiKey serial number.

However, when the operation is repeated for an additional YubiKey, the stub is overwritten by the *keytocard* operation and now will point to the latest YubiKey.

GnuPG will request a specific YubiKey by serial number, as referenced by the stub, and will not recognize another YubiKey with a different serial number without manual intervention.

Insert the first YubiKey (which has a different serial number) and run the following command:

```console
gpg-connect-agent "scd serialno" "learn --force" /bye
```

GnuPG will scan the first YubiKey for keys and recreate the stubs to point to the key ID and YubiKey serial number of the first YubiKey.

To use the second YubiKey, repeat the command.

# Multiple Hosts

Export the public key and trust setting from the current host:

```console
gpg --armor --export $KEYID > gpg-public-key-$KEYID.asc

gpg --export-ownertrust > gpg-owner-trust.txt
```

Move both files to the second host, then define the key ID:

```console
export KEYID=0xF0F2CFEB04341FB5
```

Import the public key:

```console
gpg --import gpg-public-key-$KEYID.asc
```

Import the trust setting:

```console
gpg --import-ownertrust < gpg-owner-trust.txt
```

Insert YubiKey and import key stubs:

```console
gpg --card-status
```

Or download from a public key server:

```console
gpg --keyserver hkps://keyserver.ubuntu.com:443 --recv $KEYID
```

Configure trust:

```console
$ gpg --edit-key $KEYID
gpg> trust
Your decision? 5
Do you really want to set this key to ultimate trust? (y/N) y
gpg> quit
```

The public key URL can also be added to YubiKey (based on [Shaw 2003](https://datatracker.ietf.org/doc/html/draft-shaw-openpgp-hkp-00)):

```console
[[ ! "$KEYID" =~ ^"0x" ]] && KEYID="0x${KEYID}"
URL="hkps://keyserver.ubuntu.com:443/pks/lookup?op=get&search=${KEYID}"
```

Edit YubiKey with `gpg --edit-card` and the Admin PIN:

```console
gpg/card> admin

gpg/card> url
URL to retrieve public key: hkps://keyserver.ubuntu.com:443/pks/lookup?op=get&search=0xFF00000000000000

gpg/card> quit
```

With the URL on YubiKey, retrieve the public key:

```console
gpg/card> fetch

gpg/card> quit
```

# Finish

Before completing setup, verify the following:

- [ ] Saved encryption, signing and authentication Subkeys to YubiKey (`gpg -K` will show `ssb>` for Subkeys)
- [ ] Saved YubiKey user and admin PINs, which are unique and were changed from default values
- [ ] Saved Certify key passphrase to a secure and durable location
- [ ] Saved Certify key, Subkeys and revocation certificate on encrypted portable storage, to be kept offline
- [ ] Saved passphrase to encrypted volume on portable storage
- [ ] Saved copy of public key where is can be easily accessed later

Reboot to finish.

If an ephemeral environment was not used for setup, delete secret keys from the keyring and [securely delete](https://srm.sourceforge.net/) `$GNUPGHOME`.

```console
gpg --delete-secret-key $KEYID

sudo srm -r $GNUPGHOME || sudo rm -rf $GNUPGHOME

unset GNUPGHOME
```

# Using keys

Initialize GnuPG:

```console
gpg -k
```

Change the working directory:

```console
cd ~/.gnupg
```

Download [drduh/config/gpg.conf](https://github.com/drduh/config/blob/master/gpg.conf):

```console
wget https://raw.githubusercontent.com/drduh/config/master/gpg.conf

chmod 600 gpg.conf
```

Set the following option. This avoids the problem where GnuPG will prompt, repeatedly, for the insertion of an already-inserted YubiKey:

```console
touch scdaemon.conf

echo "disable-ccid" >>scdaemon.conf
```

> The `disable-ccid` option is only required for GnuPG versions 2.3 or later. However, setting this option does not appear to interfere with the operation of earlier versions of GnuPG so it is recommended for all installations.

Install the required packages and mount the non-encrypted volume created earlier:

**Linux**

```console
sudo apt update

sudo apt install -y gnupg2 gnupg-agent gnupg-curl scdaemon pcscd

sudo mount /dev/mmcblk0p2 /mnt
```

**OpenBSD**

```console
doas pkg_add gnupg pcsc-tools

doas mount /dev/sd2b /mnt
```

Import the public key file:

```console
gpg --import /mnt/gpg-0x*.asc
```

Or download the public key from a keyserver:

```console
gpg --recv $KEYID
```

Edit the Certify key:

```console
export KEYID=0xF0F2CFEB04341FB5

gpg --edit-key $KEYID
```

Assign ultimate trust by tying `trust` and selecting option `5`:

```console
gpg> trust

Your decision? 5
Do you really want to set this key to ultimate trust? (y/N) y

gpg> quit
```

Remove and re-insert YubiKey.

Verify the status with `gpg --card-status` which should be similar to:

```console
Reader ...........: Yubico YubiKey OTP FIDO CCID 00 00
Application ID ...: D2760001240102010006055532110000
Application type .: OpenPGP
Version ..........: 3.4
Manufacturer .....: Yubico
Serial number ....: 05553211
Name of cardholder: YubiKey User
Language prefs ...: en
Salutation .......:
URL of public key : [not set]
Login data .......: yubikey@example
Signature PIN ....: not forced
Key attributes ...: rsa4096 rsa4096 rsa4096
Max. PIN lengths .: 127 127 127
PIN retry counter : 3 3 3
Signature counter : 0
KDF setting ......: on
Signature key ....: CF5A 305B 808B 7A0F 230D  A064 B3CD 10E5 02E1 9637
      created ....: 2024-01-01 12:00:00
Encryption key....: A5FA A005 5BED 4DC9 889D  38BC 30CB E8C4 B085 B9F7
      created ....: 2024-01-01 12:00:00
Authentication key: 570E 1355 6D01 4C04 8B6D  E2A3 AD9E 24E1 B8CB 9600
      created ....: 2024-01-01 12:00:00
General key info..: sub  rsa4096/0xB3CD10E502E19637 2024-01-01 YubiKey User <yubikey@example>
sec#  rsa4096/0xF0F2CFEB04341FB5  created: 2024-01-01  expires: never
ssb>  rsa4096/0xB3CD10E502E19637  created: 2024-01-01  expires: 2026-01-01
                                  card-no: 0006 05553211
ssb>  rsa4096/0x30CBE8C4B085B9F7  created: 2024-01-01  expires: 2026-01-01
                                  card-no: 0006 05553211
ssb>  rsa4096/0xAD9E24E1B8CB9600  created: 2024-01-01  expires: 2026-01-01
                                  card-no: 0006 05553211
```

`sec#` indicates the corresponding key is not available.

**Note** If `General key info..: [none]` appears in the output instead - go back and import the public key using the previous step.

Encrypt a message to yourself (useful for storing credentials):

```console
echo "test message string" | gpg --encrypt --armor --recipient $KEYID -o encrypted.txt
```

To encrypt to multiple recipients or keys (the preferred key ID should be last):

```console
echo "test message string" | \
    gpg --encrypt --armor \
    --recipient $KEYID_0 --recipient $KEYID_1 --recipient $KEYID_2 \
    -o encrypted.txt
```

Decrypt the message:

```console
$ gpg --decrypt --armor encrypted.txt
gpg: anonymous recipient; trying secret key 0x0000000000000000 ...
gpg: okay, we are the anonymous recipient.
gpg: encrypted with RSA key, ID 0x0000000000000000
test message string
```

Sign a message:

```console
echo "test message string" | gpg --armor --clearsign > signed.txt
```

Verify the signature:

```console
$ gpg --verify signed.txt
gpg: Signature made Mon 01 Jan 2024 12:00:00 PM UTC
gpg:                using RSA key CF5A305B808B7A0F230DA064B3CD10E502E19637
gpg: Good signature from "YubiKey User <yubikey@example>" [ultimate]
Primary key fingerprint: 4E2C 1FA3 372C BA96 A06A  C34A F0F2 CFEB 0434 1FB5
     Subkey fingerprint: CF5A 305B 808B 7A0F 230D  A064 B3CD 10E5 02E1 9637
```

Use a [shell function](https://github.com/drduh/config/blob/master/zshrc) to make encrypting files easier:

```
secret () {
        output=~/"${1}".$(date +%s).enc
        gpg --encrypt --armor --output ${output} -r 0x0000 -r 0x0001 -r 0x0002 "${1}" && echo "${1} -> ${output}"
}

reveal () {
        output=$(echo "${1}" | rev | cut -c16- | rev)
        gpg --decrypt --output ${output} "${1}" && echo "${1} -> ${output}"
}
```

```console
$ secret document.pdf
document.pdf -> document.pdf.1580000000.enc

$ reveal document.pdf.1580000000.enc
gpg: anonymous recipient; trying secret key 0xF0F2CFEB04341FB5 ...
gpg: okay, we are the anonymous recipient.
gpg: encrypted with RSA key, ID 0x0000000000000000
document.pdf.1580000000.enc -> document.pdf
```

# Rotating keys

PGP does not provide [forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy) - a compromised key may be used to decrypt all past messages. Although keys stored on YubiKey are difficult to exploit, it is not impossible; the key and PIN could be physically compromised, or a vulnerability may be discovered in firmware or in the random number generator used to create keys, for example. Therefore, it is good practice to rotate Subkeys periodically.

When a Subkey expires, it can either be renewed or replaced. Both actions require access to the Certify key.

- Renewing Subkeys by updating expiration indicates continued possession of the Certify key and is more convenient.

- Replacing Subkeys is less convenient but potentially more secure: the new Subkeys will **not** be able to decrypt previous messages, authenticate with SSH, etc. Contacts will need to receive the updated public key and any encrypted secrets need to be decrypted and re-encrypted to new Subkeys to be usable. This process is functionally equivalent to losing the YubiKey and provisioning a new one.

Neither rotation method is superior and it is up to personal philosophy on identity management and individual threat modeling to decide which one to use, or whether to expire Subkeys at all. Ideally, Subkeys would be ephemeral: used only once for each unique encryption, signing and authentication event, however in practice that is not really practical nor worthwhile with YubiKey. Advanced users may dedicate an air-gapped machine for frequent credential rotation.

## Setup environment

To renew or rotate Subkeys, follow the same process as generating keys: boot to a secure environment, install required software and disconnect networking.

Connect the portable storage device with the Certify key and identify the disk label:

```console
$ sudo dmesg | tail
mmc0: new high speed SDHC card at address a001
mmcblk0: mmc0:a001 SS16G 14.8 GiB (ro)
mmcblk0: p1 p2
```

Decrypt and mount the encrypted volume:

```console
sudo cryptsetup luksOpen /dev/mmcblk0p1 secret

sudo mount /dev/mapper/secret /mnt/encrypted-storage
```

Import the Certify key and configuration to a temporary working directory.

Note that Windows users should import certify.gpg:

```console
export GNUPGHOME=$(mktemp -d -t gnupg_$(date +%Y%m%d%H%M)_XXX)

gpg --import /mnt/encrypted-storage/tmp.XXX/certify.key

cp -v /mnt/encrypted-storage/tmp.XXX/gpg.conf $GNUPGHOME
```

Edit the Certify key:

```console
export KEYID=0xF0F2CFEB04341FB5

gpg --expert --edit-key $KEYID
```

## Renewing Subkeys

To renew Subkeys, the expiry time associated with the corresponding public key will need to be updated, which will require access to the Certify key.

Start by editing the identity:

```console
gpg --edit-key $KEYID
```

Select all expired keys:

```console
gpg> key 1

gpg> key 2

gpg> key 3

sec  rsa4096/0xF0F2CFEB04341FB5
     created: 2024-01-01  expires: never       usage: C
     trust: ultimate      validity: ultimate
ssb* rsa4096/0xB3CD10E502E19637
     created: 2024-01-01  expires: 2026-01-01  usage: S
ssb* rsa4096/0x30CBE8C4B085B9F7
     created: 2024-01-01  expires: 2026-01-01  usage: E
ssb* rsa4096/0xAD9E24E1B8CB9600
     created: 2024-01-01  expires: 2026-01-01  usage: A
[ultimate] (1). YubiKey User <yubikey@example>
```

Use `expire` to configure the expiration date. This will **not** expire valid keys.

```console
gpg> expire
Changing expiration time for a subkey.
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0)
```

Set the expiration date, then `save`

Next, [Export public keys](#export-public-keys):

```console
gpg --armor --export $KEYID > gpg-$KEYID-$(date +%F).asc
```

Transfer the public key to the destination host, and then import it:

```console
gpg --import gpg-0x*.asc
```

Alternatively, publish to a public key server to update the expiration:

```console
gpg --send-key $KEYID
```

Download the public key with updated expiration:

```console
gpg --recv $KEYID
```

The validity of the GnuPG identity will be extended, allowing it to be used again for encryption, signing and authentication operations. The SSH public key does **not** need to be updated on remote hosts.

## Rotating keys

Follow the original steps to generate and add each Subkey.

Previous Subkeys may be kept or deleted from the identity.

Finish by exporting new keys:

```console
gpg --armor --export-secret-keys $KEYID > $GNUPGHOME/certify.key

gpg --armor --export-secret-subkeys $KEYID > $GNUPGHOME/subkeys.key
```

Copy the **new** temporary working directory to encrypted storage, which should still be mounted:

```console
sudo cp -avi $GNUPGHOME /mnt/encrypted-storage
```

There should now be at least two versions of the Certify and Subkeys:

```console
ls /mnt/encrypted-storage
```

Unmount and close the encrypted volume:

```console
sudo umount /mnt/encrypted-storage

sudo cryptsetup luksClose /dev/mapper/secret
```

Export the updated public key:

```console
sudo mkdir /mnt/public

sudo mount /dev/mmcblk0p2 /mnt/public

gpg --armor --export $KEYID | sudo tee /mnt/public/$KEYID-$(date +%F).asc

sudo umount /mnt/public
```

Disconnect the storage device and follow the original steps to transfer new Subkeys (4, 5 and 6) to YubiKey, replacing existing ones. Reboot or securely erase the GnuPG temporary working directory.

# Adding notations

Notations can be added to user ID(s) and can be used in conjunction with [Keyoxide](https://keyoxide.org) to create [OpenPGP identity proofs](https://docs.keyoxide.org/wiki/identity-proof-formats/).

Adding notations requires access to the Certify key.

After configuring the environment, follow any of the guides listed under "Adding proofs" in the Keyoxide ["Guides"](https://keyoxide.org/guides/) page up until the notation is saved using the `save` command.

Export the public key:

```console
gpg --export $KEYID > pubkey.asc
```

Transfer the public key and import it:

```console
gpg --import pubkey.asc
```

Use `showpref` to verify notions were correctly added.

# SSH

**Tip** YubiKey can be used directly for SSH only, without GnuPG features, starting in [OpenSSH v8.2](https://www.openssh.com/txt/release-8.2). For more information, see [ed25519-sk.md](https://github.com/vorburger/vorburger.ch-Notes/blob/develop/security/ed25519-sk.md) and [Yubico - GitHub now supports SSH security keys](https://www.yubico.com/blog/github-now-supports-ssh-security-keys/).

[gpg-agent](https://wiki.archlinux.org/title/GnuPG#SSH_agent) supports the OpenSSH ssh-agent protocol (`enable-ssh-support`) as well as PuTTy's Pageant on Windows (`enable-putty-support`). This means it can be used instead of the traditional ssh-agent / pageant. There are some differences from ssh-agent, notably that gpg-agent does not _cache_ keys rather it converts, encrypts and stores them persistently as keys, then makes them available to ssh clients. Any existing ssh private keys should be deleted after importing to GnuPG agent.

When importing the key to `gpg-agent`, a passphrase will be required to encrypt within the key store. GnuPG can cache both passphrases with `cache-ttl` options. Note than when removing the old private key after importing to `gpg-agent`, keep the `.pub` key file around for use in specifying ssh identities (e.g. `ssh -i /path/to/identity.pub`).

Missing from `gpg-agent` ssh agent support is the ability to remove keys. `ssh-add -d/-D` have no effect. Instead, use the `gpg-connect-agent` utility to lookup a keygrip, match it with the desired ssh key fingerprint (as an MD5) and then delete that keygrip. The [gnupg-users mailing list](https://lists.gnupg.org/pipermail/gnupg-users/2016-August/056499.html) has more information.

## Create configuration

Create a hardened configuration for gpg-agent by downloading [drduh/config/gpg-agent.conf](https://github.com/drduh/config/blob/master/gpg-agent.conf):

```console
cd ~/.gnupg

wget https://raw.githubusercontent.com/drduh/config/master/gpg-agent.conf
```

**Important** The `cache-ttl` options do **not** apply when using YubiKey as a smart card, because the PIN is [cached by the smart card itself](https://dev.gnupg.org/T3362). To clear the PIN from cache (equivalent to `default-cache-ttl` and `max-cache-ttl`), unplug YubiKey, or set `forcesig` when editing the card to be prompted for the PIN each time.

**Tip** Set `pinentry-program /usr/bin/pinentry-gnome3` for a GUI-based prompt. If the _pinentry_ graphical dialog doesn't show and this error appears: `sign_and_send_pubkey: signing failed: agent refused operation`, install the `dbus-user-session` package and restart the computer for the `dbus` user session to be fully inherited; this is because behind the scenes, `pinentry` complains about `No $DBUS_SESSION_BUS_ADDRESS found`, falls back to `curses` but doesn't find the expected `tty`.

On macOS, use `brew install pinentry-mac` and set the program path to `pinentry-program /usr/local/bin/pinentry-mac` for Intel Macs, `/opt/homebrew/bin/pinentry-mac` for ARM/Apple Silicon Macs or `pinentry-program /usr/local/MacGPG2/libexec/pinentry-mac.app/Contents/MacOS/pinentry-mac` if using MacGPG Suite. For the configuration to take effect, run `gpgconf --kill gpg-agent`

## Replace agents

To launch `gpg-agent` for use by SSH, use the `gpg-connect-agent /bye` or `gpgconf --launch gpg-agent` commands.

Add the following to the shell rc file:

```console
export GPG_TTY="$(tty)"
export SSH_AUTH_SOCK="/run/user/$UID/gnupg/S.gpg-agent.ssh"
gpg-connect-agent updatestartuptty /bye > /dev/null
```

On modern systems, `gpgconf --list-dirs agent-ssh-socket` will automatically set `SSH_AUTH_SOCK` to the correct value and is better than hard-coding to `run/user/$UID/gnupg/S.gpg-agent.ssh`, if available:

```console
export GPG_TTY="$(tty)"
export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
gpgconf --launch gpg-agent
```

For fish, `config.fish` should look like this (consider putting them into the `is-interactive` block):

```fish
set -x GPG_TTY (tty)
set -x SSH_AUTH_SOCK (gpgconf --list-dirs agent-ssh-socket)
gpgconf --launch gpg-agent
```

When using `ForwardAgent` for ssh-agent forwarding, `SSH_AUTH_SOCK` only needs to be set on the *local* host, where YubiKey is connected. On the *remote* host, `ssh` will set `SSH_AUTH_SOCK` to something like `/tmp/ssh-mXzCzYT2Np/agent.7541` upon connection. Do **not** set `SSH_AUTH_SOCK` on the remote host - doing so will break [SSH Agent Forwarding](#remote-machines-ssh-agent-forwarding).

For `S.gpg-agent.ssh` (see [SSH Agent Forwarding](#remote-machines-ssh-agent-forwarding) for more info), `SSH_AUTH_SOCK` should also be set on the *remote*. However, `GPG_TTY` should not be set on the *remote*, explanation specified in that section.

## Copy public key

**Note** It is **not** necessary to import the GnuPG public key in order to use SSH.

Copy and paste the output from `ssh-add` to the server's `authorized_keys` file:

```console
$ ssh-add -L
ssh-rsa AAAAB4NzaC1yc2EAAAADAQABAAACAz[...]zreOKM+HwpkHzcy9DQcVG2Nw== cardno:000605553211
```

## (Optional) Save public key for identity file configuration

By default, SSH attempts to use all the identities available via the agent. It's often a good idea to manage exactly which keys SSH will use to connect to a server, for example to separate different roles or [to avoid being fingerprinted by untrusted ssh servers](https://blog.filippo.io/ssh-whoami-filippo-io/). To do this you'll need to use the command line argument `-i [identity_file]` or the `IdentityFile` and `IdentitiesOnly` options in `.ssh/config`.

The argument provided to `IdentityFile` is traditionally the path to the _private_ key file (for example `IdentityFile ~/.ssh/id_rsa`). For YubiKey, `IdentityFile` must point to the _public_ key file, and `ssh` will select the appropriate private key from those available via ssh-agent. To prevent `ssh` from trying all keys in the agent, use `IdentitiesOnly yes` along with one or more `-i` or `IdentityFile` options for the target host.

To reiterate, with `IdentitiesOnly yes`, `ssh` will not enumerate public keys loaded into `ssh-agent` or `gpg-agent`. This means public-key authentication will not proceed unless explicitly named by `ssh -i [identity_file]` or in `.ssh/config` on a per-host basis.

In the case of YubiKey usage, to extract the public key from the ssh agent:

```console
ssh-add -L | grep "cardno:000605553211" > ~/.ssh/id_rsa_yubikey.pub
```

Then explicitly associate this YubiKey-stored key for used with a host, `github.com` for example, as follows:

```console
$ cat << EOF >> ~/.ssh/config
Host github.com
    IdentitiesOnly yes
    IdentityFile ~/.ssh/id_rsa_yubikey.pub
EOF
```

## Connect with public key authentication

```console
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
```

**Tip** To make multiple connections or securely transfer many files, use the [ControlMaster](https://en.wikibooks.org/wiki/OpenSSH/Cookbook/Multiplexing) ssh option.

## Import SSH keys

If there are existing SSH keys to make available via `gpg-agent`, they will need to be imported. Then, remove the original private keys. When importing the key, `gpg-agent` uses the key filename as the label - this makes it easier to follow where the key originated from. In this example, we're starting with just the YubiKey in place and importing `~/.ssh/id_rsa`:

```console
$ ssh-add -l
4096 SHA256:... cardno:00060123456 (RSA)

$ ssh-add ~/.ssh/id_rsa && rm ~/.ssh/id_rsa
```

When invoking `ssh-add`, a prompt for the SSH key passphrase will appear, then the `pinentry` program will prompt and confirm a new passphrase to encrypt the converted key within the GnuPG key store.

The migrated key will be listed in `ssh-add -l`:

```console
$ ssh-add -l
4096 SHA256:... cardno:00060123456 (RSA)
2048 SHA256:... /Users/username/.ssh/id_rsa (RSA)
```

To show the keys with MD5 fingerprints, as used by `gpg-connect-agent`'s `KEYINFO` and `DELETE_KEY` commands:

```console
$ ssh-add -E md5 -l
4096 MD5:... cardno:00060123456 (RSA)
2048 MD5:... /Users/username/.ssh/id_rsa (RSA)
```

When using the key `pinentry` will be invoked to request the key passphrase. The passphrase will be cached for up to 10 idle minutes between uses, up to a maximum of 2 hours.

## Remote Machines (SSH Agent Forwarding)

**Note** SSH Agent Forwarding can [add additional risk](https://matrix.org/blog/2019/05/08/post-mortem-and-remediations-for-apr-11-security-incident/#ssh-agent-forwarding-should-be-disabled) - proceed with caution!

There are two methods for ssh-agent forwarding, one is provided by OpenSSH and the other is provided by GnuPG.

The latter one may be more insecure as raw socket is just forwarded (not like `S.gpg-agent.extra` with only limited functionality; if `ForwardAgent` implemented by OpenSSH is just forwarding the raw socket, then they are insecure to the same degree). But for the latter one, one convenience is that one may forward once and use this agent everywhere in the remote. So again, proceed with caution!

For example, tmux does not have environment variables such as `$SSH_AUTH_SOCK` when connecting to remote hosts and attaching an existing session. For each shell, find the socket and `export SSH_AUTH_SOCK=/tmp/ssh-agent-xxx/xxxx.socket`. However, with `S.gpg-agent.ssh` in a fixed place, it can be used as the ssh-agent in shell rc files.

### Use ssh-agent 

You should now be able to use `ssh -A remote` on the _local_ host to log into _remote_ host, and should then be able to use YubiKey as if it were connected to the remote host. For example, using e.g. `ssh-add -l` on that remote host should show the public key from the YubiKey (note `cardno:`).  (If you don't want to have to remember to use `ssh -A`, you can use `ForwardAgent yes` in `~/.ssh/config`.  As a security best practice, always use `ForwardAgent yes` only for a single `Hostname`, never for all servers.)

### Use S.gpg-agent.ssh

First you need to go through [Remote Machines (GPG Agent Forwarding)](#remote-machines-gpg-agent-forwarding), know the conditions for gpg-agent forwarding and know the location of `S.gpg-agent.ssh` on both the local and the remote.

You may use the command:

```console
$ gpgconf --list-dirs agent-ssh-socket
```

Edit `.ssh/config` to add the remote host:

```console
Host
  Hostname remote-host.tld
  StreamLocalBindUnlink yes
  RemoteForward /run/user/1000/gnupg/S.gpg-agent.ssh /run/user/1000/gnupg/S.gpg-agent.ssh
  # RemoteForward [remote socket] [local socket]
  # Note that ForwardAgent is not wanted here!
```

After successfully ssh into the remote host, confirm `/run/user/1000/gnupg/S.gpg-agent.ssh` exists.

Then in the *remote* you can type in command line or configure in the shell rc file with:

```console
export SSH_AUTH_SOCK="/run/user/$UID/gnupg/S.gpg-agent.ssh"
```

After sourcing the shell rc file, `ssh-add -l` will return the correct public key.

**Note** In this process no gpg-agent in the remote is involved, hence `gpg-agent.conf` in the remote is of no use. Also pinentry is invoked locally.

### Chained SSH Agent Forwarding

If you use `ssh-agent` provided by OpenSSH and want to forward it into a *third* box, you can just `ssh -A third` on the *remote*.

Meanwhile, if you use `S.gpg-agent.ssh`, assume you have gone through the steps above and have `S.gpg-agent.ssh` on the *remote*, and you would like to forward this agent into a *third* box, first you may need to configure `sshd_config` and `SSH_AUTH_SOCK` of *third* in the same way as *remote*, then in the ssh config of *remote*, add the following lines

```console
Host third
  Hostname third-host.tld
  StreamLocalBindUnlink yes
  RemoteForward /run/user/1000/gnupg/S.gpg-agent.ssh /run/user/1000/gnupg/S.gpg-agent.ssh
  # RemoteForward [remote socket] [local socket]
  # Note that ForwardAgent is not wanted here!
```

The path must be set according to `gpgconf --list-dirs agent-ssh-socket` on *remote* and *third* hosts.

## GitHub

YubiKey can be used to sign commits and tags, and authenticate SSH to GitHub.

Manage SSH and PGP keys in [Settings](https://github.com/settings/keys).

Configure a signing key:

```console
git config --global user.signingkey $KEYID
```

The `user.email` option must match the email address associated with the PGP identity.

To sign commits or tags, use the `-S` option.

**Windows**

To configure authentication:

```console
git config --global core.sshcommand "plink -agent"

git config --global gpg.program 'C:\Program Files (x86)\GnuPG\bin\gpg.exe'
```

Update the repository URL to `git@github.com:USERNAME/repository` and any authenticated commands will be authorized by YubiKey.

**Note** For the error `gpg: signing failed: No secret key` - run `gpg --card-status` with YubiKey plugged in and try the git command again.

## OpenBSD

Install and enable tools for use with PC/SC drivers, cards, readers, then reboot to recognize YubiKey:

```console
doas pkg_add pcsc-tools

doas rcctl enable pcscd

doas reboot
```

## Windows

Windows can already have some virtual smart card readers installed, like the one provided for Windows Hello. To verify YubiKey is the correct one used by scdaemon, add it to its configuration.

Find the YubiKey label using PowerShell:

```powershell
PS C:\WINDOWS\system32> Get-PnpDevice -Class SoftwareDevice | Where-Object {$_.FriendlyName -like "*YubiKey*"} | Select-Object -ExpandProperty FriendlyName
Yubico YubiKey OTP+FIDO+CCID 0
```

See [How to setup Signed Git Commits with a YubiKey NEO and GPG and Keybase on Windows (2018)](https://www.hanselman.com/blog/HowToSetupSignedGitCommitsWithAYubiKeyNEOAndGPGAndKeybaseOnWindows.aspx) for more information.

Edit `%APPDATA%/gnupg/scdaemon.conf` to add:

```console
reader-port <device name, e.g. Yubico YubiKey OTP+FIDO+CCID 0>
```

Edit `%APPDATA%/gnupg/gpg-agent.conf` to add:

```console
enable-ssh-support
enable-putty-support
```

Restart the agent:

```console
gpg-connect-agent killagent /bye
gpg-connect-agent /bye
```

Verify YubiKey details:

```console
gpg --card-status
```

Import the public key and set ultimate trust:

```console
gpg --import <path to public key file>
```

Retrieve the public key id:

```console
gpg --list-public-keys
```

Export the SSH public key:

```console
gpg --export-ssh-key <public key id>
```

Copy the public SSH key to a file - it corresponds to the secret key on YubiKey and can be copied to SSH destination hosts.

Create a shortcut that points to `gpg-connect-agent /bye` and place it in the startup folder `shell:startup` to make sure the agent starts after reboot. Modify the shortcut properties so it starts in a "Minimized" window.

PuTTY can now be used for public-key SSH authentication. When the server asks for public-key verification, PuTTY will forward the request to GnuPG, which will prompt for a PIN to authorize the operation.

### WSL

The goal is to configure SSH client inside WSL work together with the Windows agent, such as gpg-agent.exe.

![WSL agent architecture](media/schema_gpg.png)

**Note** this works only for SSH agent forwarding. GnuPG forwarding for cryptographic operations is not supported. See [vuori/weasel-pageant](https://github.com/vuori/weasel-pageant) for more information.

#### Use ssh-agent or use S.weasel-pageant

One way to forward is just `ssh -A` (still need to eval weasel to setup local ssh-agent), and only relies on OpenSSH. In this track, `ForwardAgent` and `AllowAgentForwarding` in ssh/sshd config may be involved. However, when using ssh socket forwarding, do not enable `ForwardAgent` in ssh config. See [SSH Agent Forwarding](#remote-machines-ssh-agent-forwarding) for more information.

#### Prerequisites

* Ubuntu 16.04 or newer for WSL
* Kleopatra
* [Windows configuration](#windows)

#### WSL configuration

Download [vuori/weasel-pageant](https://github.com/vuori/weasel-pageant).

Add `eval $(/mnt/c/<path of extraction>/weasel-pageant -r -a /tmp/S.weasel-pageant)` to the shell rc file. Use a named socket here so it can be used in the `RemoteForward` directive of `~/.ssh/config`. Source it with `source ~/.bashrc`.

Display the SSH key with `$ ssh-add -l`

Edit `~/.ssh/config` to add the following for each agent forwarding host:

```console
RemoteForward <remote SSH socket path> /tmp/S.weasel-pageant
```

**Note** The remote SSH socket path can be found with `gpgconf --list-dirs agent-ssh-socket`

#### Remote host configuration

Add the following to the shell rc file:

```console
export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
```

Add the following to `/etc/ssh/sshd_config`:

```console
StreamLocalBindUnlink yes
```

Reload SSH daemon:

```console
sudo service sshd reload
```

Unplug YubiKey, disconnect or reboot. Log back into Windows, open a WSL console and enter `ssh-add -l` - no output should appear.

Plug in YubiKey, enter the same command to display the ssh key.

Connect to the remote host and use `ssh-add -l` to confirm forwarding works.

Agent forwarding may be chained through multiple hosts. Follow the same [protocol](#remote-host-configuration) to configure each host.

## macOS

To use gui applications on macOS, [a little bit more setup is needed](https://jms1.net/yubikey/make-ssh-use-gpg-agent.md).

Create `$HOME/Library/LaunchAgents/gnupg.gpg-agent.plist` with the following contents:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>gnupg.gpg-agent</string>
        <key>RunAtLoad</key>
        <true/>
        <key>KeepAlive</key>
        <false/>
        <key>ProgramArguments</key>
        <array>
            <string>/usr/local/MacGPG2/bin/gpg-connect-agent</string>
            <string>/bye</string>
        </array>
    </dict>
</plist>
```

```console
launchctl load $HOME/Library/LaunchAgents/gnupg.gpg-agent.plist
```

Create `$HOME/Library/LaunchAgents/gnupg.gpg-agent-symlink.plist` with the following contens:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/ProperyList-1.0/dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>gnupg.gpg-agent-symlink</string>
        <key>ProgramArguments</key>
        <array>
            <string>/bin/sh</string>
            <string>-c</string>
            <string>/bin/ln -sf $HOME/.gnupg/S.gpg-agent.ssh $SSH_AUTH_SOCK</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
    </dict>
</plist>
```

```console
launchctl load $HOME/Library/LaunchAgents/gnupg.gpg-agent-symlink.plist
```

Reboot or log out and log back in to activate these changes.

# Remote Machines (GPG Agent Forwarding)

YubiKey can be used sign git commits and decrypt files on remote hosts with GPG Agent Forwarding. To ssh through another network, especially to push to/pull from GitHub using ssh, see [Remote Machines (SSH Agent forwarding)](#remote-machines-ssh-agent-forwarding).

`gpg-agent.conf` is not needed on the remote host; after forwarding, remote GnuPG directly communicates with `S.gpg-agent` without starting `gpg-agent` on the remote host.

On the remote host, edit `/etc/ssh/sshd_config` to set `StreamLocalBindUnlink yes`

**Optional** Without root access on the remote host to edit `/etc/ssh/sshd_config`, socket located at `gpgconf --list-dir agent-socket` on the remote host will need to be removed before forwarding works. See [AgentForwarding GNUPG wiki page](https://wiki.gnupg.org/AgentForwarding) for more information.

Import public keys on the remote host. On the local host, copy the public keyring to the remote host:

```console
scp ~/.gnupg/pubring.kbx remote:~/.gnupg/
```

On modern distributions such as Fedora 30, there is no need to set `RemoteForward` in `~/.ssh/config`

## Steps for older distributions

On the local host, run:

```console
gpgconf --list-dirs agent-extra-socket
```

This should return a path to agent-extra-socket - `/run/user/1000/gnupg/S.gpg-agent.extra` - though on older Linux distros (and macOS) it may be `/home/<user>/.gnupg/S/gpg-agent.extra`

Find the agent socket on the **remote** host:

```console
gpgconf --list-dirs agent-socket
```

This should return a path such as `/run/user/1000/gnupg/S.gpg-agent`

Finally, enable agent forwarding for a given host by adding the following to the local host's `~/.ssh/config` (agent sockets may differ):

```
Host
  Hostname remote-host.tld
  StreamLocalBindUnlink yes
  RemoteForward /run/user/1000/gnupg/S.gpg-agent /run/user/1000/gnupg/S.gpg-agent.extra
  # RemoteForward [remote socket] [local socket]
```

It may be necessary to edit `gpg-agent.conf` on the *local* host to add the following information:

```
pinentry-program /usr/bin/pinentry-gtk-2
extra-socket /run/user/1000/gnupg/S.gpg-agent.extra
```

**Note** The pinentry program starts on the *local* host, not remote.

**Important** Any pinentry program except `pinentry-tty` or `pinentry-curses` may be used. This is because local `gpg-agent` may start headlessly (by systemd without `$GPG_TTY` set locally telling which tty it is on), thus failed to obtain the pin. Errors on the remote may be misleading saying that there is *IO Error*. (Yes, internally there is actually an *IO Error* since it happens when writing to/reading from tty while finding no tty to use, but for end users this is not friendly.)

See [Issue #85](https://github.com/drduh/YubiKey-Guide/issues/85) for more information and troubleshooting.

## Chained GPG Agent Forwarding

Assume you have gone through the steps above and have `S.gpg-agent` on the *remote*, and you would like to forward this agent into a *third* box, first you may need to configure `sshd_config` of *third* in the same way as *remote*, then in the ssh config of *remote*, add the following lines:

```console
Host third
  Hostname third-host.tld
  StreamLocalBindUnlink yes
  RemoteForward /run/user/1000/gnupg/S.gpg-agent /run/user/1000/gnupg/S.gpg-agent
  # RemoteForward [remote socket] [local socket]
```

You should change the path according to `gpgconf --list-dirs agent-socket` on *remote* and *third*.

**Note** On *local* you have `S.gpg-agent.extra` whereas on *remote* and *third*, you only have `S.gpg-agent`

# Using Multiple Keys

To use a single identity with multiple YubiKeys - or to replace a lost card with another - issue this command to switch keys:

```console
gpg-connect-agent "scd serialno" "learn --force" /bye
```

Alternatively, use a script to delete the GnuPG shadowed key, where the card serial number is stored (see [GnuPG #T2291](https://dev.gnupg.org/T2291)):

```console
cat >> ~/scripts/remove-keygrips.sh <<EOF
#!/usr/bin/env bash
(( $# )) || { echo "Specify a key." >&2; exit 1; }
KEYGRIPS=$(gpg --with-keygrip --list-secret-keys "$@" | awk '/Keygrip/ { print $3 }')
for keygrip in $KEYGRIPS
do
    rm "$HOME/.gnupg/private-keys-v1.d/$keygrip.key" 2> /dev/null
done

gpg --card-status
EOF

chmod +x ~/scripts/remove-keygrips.sh

~/scripts/remove-keygrips.sh $KEYID
```

See discussion in Issues [#19](https://github.com/drduh/YubiKey-Guide/issues/19) and [#112](https://github.com/drduh/YubiKey-Guide/issues/112) for more information and troubleshooting steps.

# Adding an identity

To add an identity after creating and backing up a YubiKey, first add the identity to the Certify key, and then reset YubiKey and use `keytocard` to move the Subkeys to the card again.

Follow the same process as generating keys: boot to a secure environment, install required software and disconnect networking.

Connect the portable storage device with the Certify key and identify the disk label:

```console
$ sudo dmesg | tail
mmc0: new high speed SDHC card at address a001
mmcblk0: mmc0:a001 SS16G 14.8 GiB (ro)
mmcblk0: p1 p2
```

Decrypt and mount the encrypted volume:

```console
sudo cryptsetup luksOpen /dev/mmcblk0p1 secret

sudo mount /dev/mapper/secret /mnt/encrypted-storage
```

Restore the backup to a temporary directory:

```console
export GNUPGHOME=$(mktemp -d -t gnupg_$(date +%Y%m%d%H%M)_XXX)

cp -avi /mnt/encrypted-storage/tmp.XXX/* $GNUPGHOME
```

Edit the Certify key:

```console
gpg --expert --edit-key $KEYID
```

Add the identity and set ultimate trust:

```console
gpg> adduid

gpg> trust
Your decision? 5

gpg> save
```

Export Certify and Subkeys again:

```console
gpg --armor --export-secret-keys $KEYID > $GNUPGHOME/certify.key

gpg --armor --export-secret-subkeys $KEYID > $GNUPGHOME/subkeys.key
```

Export the public key:

```console
gpg --armor --export $KEYID | sudo tee /mnt/public/gpg-$KEYID-$(date +%F).asc
```

**Note** On Windows, using an extension other than `.gpg` or attempting IO redirection to a file will result in a nonfunctional private key.

```console
gpg -o \path\to\dir\certify.gpg --armor --export-secret-keys $KEYID

gpg -o \path\to\dir\subkeys.gpg --armor --export-secret-subkeys $KEYID

gpg -o \path\to\dir\pubkey.gpg --armor --export $KEYID
```

Copy the **new** working directory to encrypted storage, which should still be mounted:

```console
sudo cp -avi $GNUPGHOME /mnt/encrypted-storage
```

Unmount and close the encrypted volume:

```console
sudo umount /mnt/encrypted-storage

sudo cryptsetup luksClose /dev/mapper/secret
```

## Updating YubiKey

Now that keys have been updated with the new identity, they will need to be loaded to YubiKey.

First, [Reset](#reset) the OpenPGP applet, then follow the steps to [Configure YubiKey](#configure-yubikey) again.

Next, [Transfer Keys](#transfer-keys) and reboot or securely erase the temporary working directory.

Finally, re-import the public key, as described in [Using Keys](#using-keys).

Use `gpg -K` to verify the identity is listed.

# Require touch

**Note** This is not possible on YubiKey NEO.

By default, YubiKey will perform encryption, signing and authentication operations without requiring any action from the user after the key is plugged in and unlocked once with the PIN.

To require a touch for each key operation, install [YubiKey Manager](https://developers.yubico.com/yubikey-manager/) and recall the Admin PIN:

Authentication:

```console
ykman openpgp keys set-touch aut on
```

Signing:

```console
ykman openpgp keys set-touch sig on
```

Encryption:

```console
ykman openpgp keys set-touch dec on
```

**Note** Versions of YubiKey Manager before 5.1.0 use `enc` instead of `dec` for encryption.

**Note** Older versions of YubiKey Manager use `touch` instead of `set-touch`

To view and adjust policy options:

```
ykman openpgp keys set-touch -h
```

If the YubiKey is going to be used within an email client which opens and verifies mail, `Cached` or `Cached-Fixed` may be desirable.

YubiKey will blink when it is waiting for a touch. On Linux, [maximbaz/yubikey-touch-detector](https://github.com/maximbaz/yubikey-touch-detector) can be used to indicate YubiKey is waiting for a touch.

# Email

YubiKey can be used to decrypt and sign emails and attachments using [Thunderbird](https://www.thunderbird.net/), [Enigmail](https://www.enigmail.net) and [Mutt](http://www.mutt.org/). Thunderbird supports OAuth 2 authentication and can be used with Gmail. See [this EFF guide](https://ssd.eff.org/en/module/how-use-pgp-linux) for more information. Mutt has OAuth 2 support since version 2.0.

## Mailvelope

[Mailvelope](https://www.mailvelope.com/en) allows YubiKey to be used with Gmail and others.

**Important** Mailvelope [does not work](https://github.com/drduh/YubiKey-Guide/issues/178) with the `throw-keyids` option set in `gpg.conf`

On macOS, install gpgme using Homebrew:

```console
brew install gpgme
```

To allow Chrome to run gpgme, edit `~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/gpgmejson.json` to add:

```json
{
    "name": "gpgmejson",
    "description": "Integration with GnuPG",
    "path": "/usr/local/bin/gpgme-json",
    "type": "stdio",
    "allowed_origins": [
        "chrome-extension://kajibbejlbohfaggdiogboambcijhkke/"
    ]
}
```

Edit the default path to allow Chrome to find GnuPG:

```console
sudo launchctl config user path /usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
```

Finally, install the [Mailvelope extension](https://chromewebstore.google.com/detail/mailvelope/kajibbejlbohfaggdiogboambcijhkke) from the Chrome web store.

## Mutt

Mutt has both CLI and TUI interfaces - the latter provides powerful functions for processing email. In addition, PGP can be integrated such that cryptographic operations can be done without leaving TUI.

To enable GnuPG support, copy `/usr/share/doc/mutt/samples/gpg.rc`

Edit the file to enable options `pgp_default_key`, `pgp_sign_as` and `pgp_autosign`

`source` the file in `muttrc`

**Important** `pinentry-tty` set as the pinentry program in `gpg-agent.conf` is reported to cause problems with Mutt TUI, because it uses curses. It is recommended to use `pinentry-curses` or other graphic pinentry program instead.

# Reset

If PIN attempts are exceeded, the YubiKey is locked and must be [Reset](https://developers.yubico.com/ykneo-openpgp/ResetApplet.html) and set up again using the encrypted backup.

Copy the following to a file and run `gpg-connect-agent -r $file` to lock and terminate the card. Then re-insert YubiKey to complete reset.

```console
/hex
scd serialno
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 81 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 20 00 83 08 40 40 40 40 40 40 40 40
scd apdu 00 e6 00 00
scd apdu 00 44 00 00
/echo Card has been successfully reset.
```

Or use `ykman` (sometimes in `~/.local/bin/`):

```console
$ ykman openpgp reset
WARNING! This will delete all stored OpenPGP keys and data and restore factory settings? [y/N]: y
Resetting OpenPGP data, don't remove your YubiKey...
Success! All data has been cleared and default PINs are set.
PIN:         123456
Reset code:  NOT SET
Admin PIN:   12345678
```

## Recovery after reset

To reset YubiKey from the Certify key backup (such as the one on encrypted portable storage described in [Backup](#backup)), follow [Rotating keys](#rotating-keys) to setup the environment, then [Configure YubiKey](#configure-yubikey).

# Notes

1. YubiKey has two configurations, invoked with either a short or long press. By default, the short-press mode is configured for HID OTP; a brief touch will emit an OTP string starting with `cccccccc`. OTP mode can be swapped to the second configuration via the YubiKey Personalization tool or disabled entirely using [YubiKey Manager](https://developers.yubico.com/yubikey-manager): `ykman config usb -d OTP`

1. Using YubiKey for GnuPG keys does not prevent use of other features, such as [WebAuthn](https://en.wikipedia.org/wiki/WebAuthn), [OTP](https://www.yubico.com/resources/glossary/otp/) and [static password](https://support.yubico.com/hc/en-us/articles/360016614980-Understanding-Core-Static-Password-Features).

1. Setting a key expiry forces identity and credential lifecycle management. However, setting an expiry on the primary Certify key is useless, because it can be used to simply extend itself. [Revocation certificates](https://security.stackexchange.com/questions/14718/does-openpgp-key-expiration-add-to-security/79386#79386) should be used instead.

1. To switch between multiple identities on different YubiKeys, unplug the first YubiKey and restart gpg-agent, ssh-agent and pinentry with `pkill gpg-agent ; pkill ssh-agent ; pkill pinentry ; eval $(gpg-agent --daemon --enable-ssh-support)` then insert the other YubiKey and run `gpg-connect-agent updatestartuptty /bye`

1. To use YubiKey on multiple computers, import the corresponding public keys on them. Confirm see YubiKey is visible with `gpg --card-status`, then trust the imported public keys ultimately. `gpg --list-secret-keys` will show the correct and trusted key.

# Troubleshooting

- Use `man gpg` to understand GnuPG options and command-line flags.

- To get more information on potential errors, restart the `gpg-agent` process with debug output to the console with `pkill gpg-agent; gpg-agent --daemon --no-detach -v -v --debug-level advanced --homedir ~/.gnupg`.

- If you encounter problems connecting to YubiKey with GnuPG - try unplugging and re-inserting YubiKey, and restarting the `gpg-agent` process.

- If you receive the error, `gpg: decryption failed: secret key not available` - you likely need to install GnuPG version 2.x. Another possibility is that there is a problem with the PIN, e.g. it is too short or blocked.

- If you receive the error, `Yubikey core error: no yubikey present` - make sure the YubiKey is inserted correctly. It should blink once when plugged in.

- If you still receive the error, `Yubikey core error: no yubikey present` - you likely need to install newer versions of yubikey-personalize as outlined in [Required software](#required-software).

- If you receive the error, `Yubikey core error: write error` - YubiKey is likely locked. Install and run yubikey-personalization-gui to unlock it.

- If you receive the error, `Key does not match the card's capability` - you likely need to use 2048 bit RSA key sizes.

- If you receive the error, `sign_and_send_pubkey: signing failed: agent refused operation` - make sure you replaced `ssh-agent` with `gpg-agent` as noted above.

- If you still receive the error, `sign_and_send_pubkey: signing failed: agent refused operation` - [run the command](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=835394) `gpg-connect-agent updatestartuptty /bye`

- If you still receive the error, `sign_and_send_pubkey: signing failed: agent refused operation` - edit `~/.gnupg/gpg-agent.conf` to set a valid `pinentry` program path. `gpg: decryption failed: No secret key` could also indicate an invalid `pinentry` path

- If you still receive the error, `sign_and_send_pubkey: signing failed: agent refused operation` - it is a [known issue](https://bbs.archlinux.org/viewtopic.php?id=274571) that openssh 8.9p1 and higher has issues with YubiKey. Adding `KexAlgorithms -sntrup761x25519-sha512@openssh.com` to `/etc/ssh/ssh_config` often resolves the issue.

- If you receive the error, `The agent has no identities` from `ssh-add -L`, make sure you have installed and started `scdaemon`.

- If you receive the error, `Error connecting to agent: No such file or directory` from `ssh-add -L`, the UNIX file socket that the agent uses for communication with other processes may not be set up correctly. On Debian, try `export SSH_AUTH_SOCK="/run/user/$UID/gnupg/S.gpg-agent.ssh"`. Also see that `gpgconf --list-dirs agent-ssh-socket` is returning single path, to existing `S.gpg-agent.ssh` socket.

- If you receive the error, `Permission denied (publickey)`, increase ssh verbosity with the `-v` flag and verify the public key from the card is being offered: `Offering public key: RSA SHA256:abcdefg... cardno:00060123456`. If it is, verify the correct user the target system - not the user on the local system. Otherwise, be sure `IdentitiesOnly` is not [enabled](https://github.com/FiloSottile/whosthere#how-do-i-stop-it) for this host.

- If SSH authentication still fails - add up to 3 `-v` flags to the `ssh` client to increase verbosity.

- If it still fails, it may be useful to stop the background `sshd` daemon process service on the server (e.g. using `sudo systemctl stop sshd`) and instead start it in the foreground with extensive debugging output, using `/usr/sbin/sshd -eddd`. Note that the server will not fork and will only process one connection, therefore has to be re-started after every `ssh` test.

- If you receive the error, `Please insert the card with serial number` see [Using Multiple Keys](#using-multiple-keys).

- If you receive the error, `There is no assurance this key belongs to the named user` or `encryption failed: Unusable public key` use `gpg --edit-key` to set `trust` to `5 = I trust ultimately`.

- If, when you try the above command, you get the error `Need the secret key to do this` - specify trust for the key in `~/.gnupg/gpg.conf` by using the `trust-key [key ID]` directive.

- If, when using a previously provisioned YubiKey on a new computer with `pass`, you see the following error on `pass insert`, you need to adjust the trust associated with the key. See the note above.

```
gpg: 0x0000000000000000: There is no assurance this key belongs to the named user
gpg: [stdin]: encryption failed: Unusable public key
```

- If you receive the error, `gpg: 0x0000000000000000: skipped: Unusable public key`, `signing failed: Unusable secret key`, or `encryption failed: Unusable public key` the Subkey may be expired and can no longer be used to encrypt nor sign messages. It can still be used to decrypt and authenticate, however.

- If the GnuPG public key is lost, follow [this guide](https://www.nicksherlock.com/2021/08/recovering-lost-gpg-public-keys-from-your-yubikey/) to recover it from YubiKey.

- Refer to Yubico article [Troubleshooting Issues with GPG](https://support.yubico.com/hc/en-us/articles/360013714479-Troubleshooting-Issues-with-GPG) for additional guidance.

- If, when you try the above `--card-status` command, you get receive the error, `gpg: selecting card failed: No such device` or `gpg: OpenPGP card not available: No such device`, it's possible that the latest release of pcscd is now requires polkit rules to operate properly. Create the following file to allow users in the `wheel` group to use the card. Be sure to restart pcscd when you're done to allow the new rules to take effect.
```
cat << EOF >  /etc/polkit-1/rules.d/99-pcscd.rules
polkit.addRule(function(action, subject) {
        if (action.id == "org.debian.pcsc-lite.access_card" &&
                subject.isInGroup("wheel")) {
                return polkit.Result.YES;
        }
});
polkit.addRule(function(action, subject) {
        if (action.id == "org.debian.pcsc-lite.access_pcsc" &&
                subject.isInGroup("wheel")) {
                return polkit.Result.YES;
        }
});
EOF
```

# Alternatives

* [`smlx/piv-agent`](https://github.com/smlx/piv-agent) - SSH and GnuPG agent which can be used with PIV devices
* [`keytotpm`](https://www.gnupg.org/documentation/manuals/gnupg/OpenPGP-Key-Management.html) - use GnuPG with TPM systems

## Create keys with batch

Keys can also be generated using template files and the `batch` parameter - see [GnuPG documentation](https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html).

Use the example [gen-params-rsa4096](contrib/gen-params-rsa4096) or [gen-params-ed25519](contrib/gen-params-ed25519) template (the latter requires GnuPG v2.1.7).

Generate the Certify key:

```console
gpg --batch --generate-key gen-params-rsa4096
```

Verify results:

```console
gpg --list-key
```

The fingerprint is used to create the three Subkeys for encryption, signing and authentication operations.

Use a one or several year expiration for Subkeys - they can be renewed using the Certify key, see [rotating keys](#rotating-keys).

Create a [signing subkey](https://stackoverflow.com/questions/5421107/can-rsa-be-both-used-as-encryption-and-signature/5432623#5432623):

```console
gpg --quick-add-key "$KEYID" rsa4096 sign 1y
```

Create an [encryption subkey](https://www.cs.cornell.edu/courses/cs5430/2015sp/notes/rsa_sign_vs_dec.php):

```console
gpg --quick-add-key "$KEYID" rsa4096 encrypt 1y
```

Finally, create an [authentication subkey](https://superuser.com/questions/390265/what-is-a-gpg-with-authenticate-capability-used-for):

```console
gpg --quick-add-key "$KEYID" rsa4096 auth 1y
```

# Additional resources

* [Yubico - PGP](https://developers.yubico.com/PGP/)
* [Yubico - PGP Card edit](https://developers.yubico.com/PGP/Card_edit.html)
* [Yubico - Yubikey Personalization](https://developers.yubico.com/yubikey-personalization/)
* [A Visual Explanation of GPG Subkeys (2022)](https://rgoulter.com/blog/posts/programming/2022-06-10-a-visual-explanation-of-gpg-subkeys.html)
* [dhess/nixos-yubikey](https://github.com/dhess/nixos-yubikey)
* [lsasolutions/makegpg](https://gitlab.com/lsasolutions/makegpg)
* [Trammell Hudson - Yubikey (2020)](https://trmm.net/Yubikey)
* [Yubikey forwarding SSH keys (2019)](https://blog.onefellow.com/post/180065697833/yubikey-forwarding-ssh-keys)
* [GPG Agent Forwarding (2018)](https://mlohr.com/gpg-agent-forwarding/)
* [Stick with security: YubiKey, SSH, GnuPG, macOS (2018)](https://evilmartians.com/chronicles/stick-with-security-yubikey-ssh-gnupg-macos)
* [PGP and SSH keys on a Yubikey NEO (2015)](https://www.esev.com/blog/post/2015-01-pgp-ssh-key-on-yubikey-neo/)
* [Offline GnuPG Master Key and Subkeys on YubiKey NEO Smartcard (2014)](https://blog.josefsson.org/2014/06/23/offline-gnupg-master-key-and-subkeys-on-yubikey-neo-smartcard/)
* [Creating the perfect GPG keypair (2013)](https://alexcabal.com/creating-the-perfect-gpg-keypair/)
* [GPG and SSH with Yubikey NEO (2013)](https://blog.habets.se/2013/02/GPG-and-SSH-with-Yubikey-NEO)
* [Riseup - OpenPGP Best Practices](https://help.riseup.net/en/security/message-security/openpgp/best-practices)
