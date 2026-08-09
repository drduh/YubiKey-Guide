This guide demonstrates how to store credentials on a [YubiKey](https://www.yubico.com/products/identifying-your-yubikey/). The private keys cannot be copied back out of the device; a separate offline "Certify" key is retained only to replace or renew them.

- [Purchase YubiKey](#purchase-yubikey)
- [Prepare setup environment](#prepare-setup-environment)
  - [Download and verify Debian](#download-and-verify-debian)
  - [Create bootable USB device](#create-bootable-usb-drive)
  - [Prepare hardware](#prepare-hardware)
- [Install software](#install-software)
- [Prepare GnuPG](#prepare-gnupg)
  - [Configuration](#configuration)
  - [Identity](#identity)
  - [Key algorithm](#key-algorithm)
  - [Expiration](#expiration)
  - [Passphrase](#passphrase)
- [Create Certify key](#create-certify-key)
- [Create Subkeys](#create-subkeys)
- [Verify keys](#verify-keys)
- [Backup keys](#backup-keys)
- [Export public key](#export-public-key)
- [Configure YubiKey](#configure-yubikey)
  - [Change PIN](#change-pin)
  - [Set attributes](#set-attributes)
- [Transfer Subkeys](#transfer-subkeys)
  - [Signature key](#signature-key)
  - [Encryption key](#encryption-key)
  - [Authentication key](#authentication-key)
- [Verify transfer](#verify-transfer)
- [Finish setup](#finish-setup)
- [Using YubiKey](#using-yubikey)
  - [Encryption](#encryption)
  - [Signature](#signature)
  - [Configure touch](#configure-touch)
  - [SSH](#ssh)
    - [Replace agents](#replace-agents)
    - [Copy public key](#copy-public-key)
    - [Import SSH keys](#import-ssh-keys)
    - [SSH agent forwarding](#ssh-agent-forwarding)
      - [Use ssh-agent](#use-ssh-agent)
      - [Use S.gpg-agent.ssh](#use-sgpg-agentssh)
      - [Chained forwarding](#chained-forwarding)
  - [GitHub](#github)
  - [GnuPG agent forwarding](#gnupg-agent-forwarding)
    - [Legacy distributions](#legacy-distributions)
    - [Chained GnuPG agent forwarding](#chained-gnupg-agent-forwarding)
  - [Using multiple YubiKeys](#using-multiple-yubikeys)
  - [Email](#email)
    - [Thunderbird](#thunderbird)
    - [Mailvelope](#mailvelope)
    - [Mutt](#mutt)
  - [Keyserver](#keyserver)
- [Updating keys](#updating-keys)
  - [Renew Subkeys](#renew-subkeys)
  - [Rotate Subkeys](#rotate-subkeys)
- [Reset YubiKey](#reset-yubikey)
- [Optional hardening](#optional-hardening)
  - [Improving entropy](#improving-entropy)
  - [Enable KDF](#enable-kdf)
  - [Network considerations](#network-considerations)
- [Notes](#notes)
- [Troubleshooting](#troubleshooting)
- [Alternative solutions](#alternative-solutions)
- [Additional resources](#additional-resources)

---

# Purchase YubiKey

Choose a [YubiKey model](https://www.yubico.com/store/compare/) that includes the OpenPGP application. YubiKey Security Key and YubiKey Bio models do not include OpenPGP support and cannot be used with this guide.

Verify the YubiKey at [yubico.com/genuine](https://www.yubico.com/genuine/). Select Verify Device, touch the key when prompted, and allow the site to identify the device model. This can help detect some [supply chain tampering](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEF%20CON%2025%20-%20r00killah-and-securelyfitz-Secure-Tokin-and-Doobiekeys.pdf).

Have at least two USB drives or microSD cards for storing encrypted offline backups in different physical locations.

# Prepare setup environment

Use a dedicated, hardened environment to generate the keys and backups.

The following environments are ordered from least to most secure for this task:

1. Public, shared or other computer owned by someone else
1. Daily-use personal operating system with unrestricted network access
1. Virtualized system with limited capabilities (using [virt-manager](https://virt-manager.org/), VirtualBox or VMware, for example)
1. Dedicated and hardened [Debian](https://www.debian.org/) or [OpenBSD](https://www.openbsd.org/) installation
1. Ephemeral [Debian Live](https://www.debian.org/CD/live/) or [Tails](https://tails.boum.org/index.en.html) booted without primary storage attached
1. Hardened hardware and firmware (e.g., [Coreboot](https://www.coreboot.org/), [Intel ME removed](https://github.com/corna/me_cleaner))
1. Air-gapped system without network capabilities, preferably ARM-based Raspberry Pi or other architecturally diverse equivalent

Network isolation and dedicated hardware generally provide stronger protection than a daily-use online system. For most people, booting Debian Live from USB on a personal computer is a practical baseline.

## Download and verify Debian

Download the latest Debian Live image and signature files. These commands download the checksum file, its signature, and the current 64-bit XFCE Live ISO:

```bash
imageUrl="https://cdimage.debian.org/debian-cd/current-live/amd64/iso-hybrid/"
curl -sfL -O "$imageUrl/SHA512SUMS" -O "$imageUrl/SHA512SUMS.sign"
curl -sfLO "$imageUrl/$(awk '/xfce\.iso$/ {print $NF}' SHA512SUMS)"
```

Download the Debian signing public key:

```bash
gpg --keyserver hkps://keyring.debian.org \
    --recv DF9B9C49EAA9298432589D76DA87E80D6294BE9B
```

If the public key cannot be received, use a different keyserver or DNS server:

```bash
gpg --keyserver hkps://keyserver.ubuntu.com:443 \
    --recv DF9B9C49EAA9298432589D76DA87E80D6294BE9B
```

The Debian Live signing public key is also available for import in [pubkeys](https://github.com/drduh/YubiKey-Guide/tree/main/pubkeys):

```bash
gpg --import pubkeys/debian-DA87E80D6294BE9B.asc
```

Verify the signature:

```bash
gpg --verify SHA512SUMS.sign SHA512SUMS
```

Confirm the fingerprint matches Debian's published fingerprint:

```console
gpg: Good signature from "Debian CD signing key <debian-cd@lists.debian.org>"
```

Verify the image hash matches the signed sums file:

```bash
grep $(sha512sum debian-live-*-amd64-xfce.iso) SHA512SUMS
```

See [Verifying authenticity of Debian CDs](https://www.debian.org/CD/verify) for more information.

## Create bootable USB device

Connect a storage device and identify the device path. This guide uses `/dev/sdc` throughout, but this value may differ on your system.

> [!WARNING]
> The following `dd` commands erase and overwrite the selected device. Check the device path before continuing!

**Linux**

```console
$ sudo dmesg | tail
usb-storage 3-2:1.0: USB Mass Storage device detected
sd 2:0:0:0: [sdc] Attached SCSI removable disk
```

Copy the Debian image to the device:

```bash
sudo dd if=debian-live-*-amd64-xfce.iso of=/dev/sdc bs=4M status=progress ; sync
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

## Prepare hardware

Shut down the computer that will be used to generate keys.

Disconnect internal storage and unnecessary peripherals, such as the wireless card.

# Install software

Boot the computer from the Debian Live USB drive.

Configure networking to install the required software; see [Network considerations](#network-considerations) for optional restrictions.

> [!TIP]
> If the screen locks on Debian Live, unlock with `user` / `live`

Open a terminal and install the required software.

**Debian/Ubuntu**

```bash
sudo apt update
sudo apt -y upgrade
sudo apt -y install \
  wget gnupg2 gnupg-agent dirmngr \
  cryptsetup scdaemon pcscd \
  yubikey-personalization yubikey-manager
```

**OpenBSD**

```bash
doas pkg_add gnupg pcsc-tools
```

**macOS**

Download and install [Homebrew](https://brew.sh/) and the following packages:

```bash
brew install gnupg yubikey-personalization ykman pinentry-mac wget
```

Or using [MacPorts](https://www.macports.org/install.php), install the following packages:

```bash
sudo port install gnupg2 yubikey-manager pinentry wget
```

**NixOS**

Use this repository's purpose-built live ISO instead of Debian Live. Copy the resulting ISO to a USB drive, boot from it, and keep the system offline while generating keys.

```bash
ref=$(git ls-remote https://github.com/drduh/Yubikey-Guide refs/heads/main | awk '{print $1}')
nix build --experimental-features "nix-command flakes" \
  github:drduh/YubiKey-Guide/$ref?dir=nix#nixosConfigurations.yubikeyLive.x86_64-linux.config.system.build.isoImage
```

If you have this repository checked out:

Recommended, but optional: update `nixpkgs` and `drduh/config`:

```bash
nix flake update --commit-lock-file
```

Build the image:

```bash
nix build --experimental-features "nix-command flakes" nix#nixosConfigurations.yubikeyLive.x86_64-linux.config.system.build.isoImage
```

Copy to USB drive:

```bash
sudo cp -v result/iso/yubikeyLive.iso /dev/sdc ; sync
```

Skip steps to create a temporary working directory and a hardened configuration, as they are already part of the image.

Test builds using virtualization tools like QEMU. A virtual machine provides less isolation than a booted live system. To test the image in QEMU with 4 GiB of RAM, two CPUs, and KVM enabled:

```bash
qemu-system-x86_64 -enable-kvm -m 4G -smp 2 \
  -drive readonly=on,media=cdrom,format=raw,file=result/iso/yubikeyLive.iso
```

**Arch Linux**

```bash
sudo pacman -Syu --needed gnupg pcsclite ccid yubikey-personalization
```

**Red Hat Enterprise Linux (RHEL)**

```bash
sudo yum install -y gnupg2 pinentry pcsc-lite pcsc-lite-libs gnupg2-smime
```

**Fedora**

```bash
sudo dnf install --skip-unavailable \
  wget gnupg2 \
  cryptsetup gnupg2-scdaemon pcsc-lite \
  yubikey-personalization-gui yubikey-manager
```

# Prepare GnuPG

Create a temporary directory for [GnuPG configuration](https://www.gnupg.org/documentation/manuals/gnupg/Configuration-Options.html):

```bash
export GNUPGHOME=$(mktemp -d "${TMPDIR:-/tmp}/$(date +%Y.%m.%d)-XXXXXXXX")
printf "\nTemporary directory:\t%s\n\n" "$GNUPGHOME"
```

> [!NOTE]
> This directory is cleared by reboot only when it is stored on a memory-backed filesystem such as [tmpfs](https://en.wikipedia.org/wiki/Tmpfs).
>
> If it is stored on persistent disk, remove it after completing the guide with `rm -rf "$GNUPGHOME"` and then reboot.

## Configuration

Download the recommended [GnuPG configuration](https://github.com/drduh/YubiKey-Guide/blob/main/config/gpg.conf) into the temporary GnuPG directory.

```bash
wget https://raw.githubusercontent.com/drduh/YubiKey-Guide/main/config/gpg.conf \
  -P $GNUPGHOME
```

Review the configuration before using it. It selects modern cryptographic defaults and privacy-oriented options, such as hiding recipient key IDs:

```console
$ grep -v "^#" $GNUPGHOME/gpg.conf
personal-cipher-preferences AES256 AES192 AES
personal-digest-preferences SHA512 SHA384 SHA256
personal-compress-preferences ZLIB BZIP2 ZIP Uncompressed
default-preference-list SHA512 SHA384 SHA256 AES256 AES192 AES ZLIB BZIP2 ZIP Uncompressed
cert-digest-algo SHA512
s2k-digest-algo SHA512
s2k-cipher-algo AES256
charset utf-8
no-comments
no-emit-version
no-greeting
keyid-format 0xlong
list-options show-uid-validity
verify-options show-uid-validity
with-fingerprint
require-cross-certification
require-secmem
no-symkey-cache
armor
use-agent
throw-keyids
```

> [!IMPORTANT]
> Networking should be disabled for the remainder of the setup.

## Identity

Create a user ID - the public label attached to the key.

Use a random label if the key does not need to be publicly identified:

```bash
export IDENTITY="yk.$(LC_ALL=C tr -dc 'a-z0-9' < /dev/urandom | head -c 16)"
printf "\nIdentity:\t\t%s\n\n" "$IDENTITY"
```

If email encryption or Git verification use is anticipated, set the Identity label to a name and email address:

```bash
export IDENTITY="YubiKey User <yubikey@example.com>"
```

> [!TIP]
> Use single quotes to wrap double quote characters (`"`):
>
> `export IDENTITY='My Identity (a.k.a. "YubiKey User") <yubikey@example.com>'`

## Key algorithm

Set the key algorithm and size - RSA 4096 is recommended:

```bash
export KEY_TYPE=rsa4096
```

## Expiration

The Certify key is the offline primary key and should not have an expiration date.[^1]

The signing, encryption, and authentication Subkeys will be stored on YubiKey. Assign Subkeys an expiration date so a lost or obsolete YubiKey becomes inoperable after that date. A two-year expiration for Subkeys is recommended, balancing security and usability. Longer expiration durations reduce maintenance frequency.

> [!NOTE]
> After a Subkey expires, GnuPG can still use it to decrypt existing messages, and SSH may still use it for authentication. However, the expired Subkey cannot encrypt new data or create new signatures!

Subkeys are renewed or rotated using the Certify key. See [Updating keys](#updating-keys).

Set Subkeys to expire on a planned date:

```bash
export KEY_EXPIRATION=2028-08-01
```

The expiration date may also be relative, for example set to two years from today:

```bash
export KEY_EXPIRATION=2y
```

## Passphrase

Create a passphrase for the offline Certify key. This passphrase protects the backup copy of the Certify key and is required to manage Subkeys.

A passphrase consisting only of uppercase letters and numbers is recommended: the limited character set makes handwritten storage easier to write and read.

The following commands will generate and print a strong passphrase[^2]:

```bash
export CERTIFY_PASS=$(LC_ALL=C tr -dc "A-Z3-9" < /dev/urandom |
  tr -d "IOUS5" |
  head -c ${PASS_LENGTH:-24} |
  fold -w ${PASS_GROUPSIZE:-4} |
  paste -sd ${PASS_DELIMITER:--} -)
printf "\nCertify passphrase:\t%s\n\n" "$CERTIFY_PASS"
```

To change the passphrase length, delimiter character or group size, export the respective variable(s) prior to running the passphrase generation command, for example:

```bash
export PASS_GROUPSIZE=6
export PASS_DELIMITER=+
export PASS_LENGTH=48
```

Record the Certify key passphrase on durable media and store it separately from the encrypted backup containing the key material, or memorize it.

The included [passphrase.html](https://github.com/drduh/YubiKey-Guide/blob/main/templates/passphrase.html) and [passphrase.txt](https://github.com/drduh/YubiKey-Guide/blob/main/templates/passphrase.txt) templates can assist with accurate transcription.

Save the [html file](https://raw.githubusercontent.com/drduh/YubiKey-Guide/main/templates/passphrase.html), open in a browser to render and print. Mark the corresponding character on sequential rows for each passphrase character. [passphrase.txt](https://raw.githubusercontent.com/drduh/YubiKey-Guide/main/templates/passphrase.txt) can also be printed for use without a browser:

```bash
lp -d Printer-Name passphrase.txt
```

[Diceware](https://secure.research.vt.edu/diceware) is another popular method for creating memorable passphrases.

# Create Certify key

The Certify key is the primary OpenPGP key: it authorizes the signing, encryption, and authentication Subkeys. Keep it offline and use it only in a secure environment to create, renew, revoke, or replace Subkeys.

Generate the Certify key:

```bash
printf '%s' "$CERTIFY_PASS" |
  gpg --batch --passphrase-fd 0 \
      --quick-generate-key "$IDENTITY" "$KEY_TYPE" cert never
```

Set and print `KEY_FP` (the full key fingerprint) and `KEY_ID` (the last 16 characters of the fingerprint - a shorter identifier commonly accepted by GnuPG):

```bash
export KEY_FP=$(gpg -k --with-colons $IDENTITY | awk -F: '/^fpr:/ { print $10; exit }')
export KEY_ID="${KEY_FP: -16}"
printf "\nKey ID/Fingerprint:\t%s\n%s\n\n" "$KEY_ID" "$KEY_FP"
```

<details>
<summary>Additional identities (optional)</summary>

Skip this section unless the OpenPGP key must have [multiple public identities](https://github.com/drduh/YubiKey-Guide/issues/445). Examples include addresses used for different languages or Git providers. Do not add both personal and professional addresses if linking those identities would reduce privacy - use separate YubiKeys instead.

Define a Bash array of additional user IDs. Put each complete user ID in quotes and separate array entries with spaces:

```bash
declare -a additional_uids
additional_uids=("Super Cool YubiKey 2026" "uid 1 <uid1@example.com>")
```

Add the additional UIDs to the Identity.

```bash
for uid in "${additional_uids[@]}" ; do \
  printf '%s' "$CERTIFY_PASS" |
  gpg --batch --passphrase-fd 0 \
      --pinentry-mode loopback --quick-add-uid "$KEY_FP" "$uid"
done
```

Set UID trust levels to *ultimate*:

```bash
gpg --command-fd 0 --pinentry-mode loopback --edit-key "$KEY_FP" <<EOF
uid *
trust
5
y
save
EOF
```
</details>

# Create Subkeys

Generate Signature and Encryption Subkeys:

```bash
printf '%s' "$CERTIFY_PASS" |
  gpg --batch --pinentry-mode loopback --passphrase-fd 0 \
      --quick-add-key "$KEY_FP" "$KEY_TYPE" sign "$KEY_EXPIRATION"
printf '%s' "$CERTIFY_PASS" |
  gpg --batch --pinentry-mode loopback --passphrase-fd 0 \
      --quick-add-key "$KEY_FP" "$KEY_TYPE" encrypt "$KEY_EXPIRATION"
```

Generate the Authentication Subkey:

> [!NOTE]
> Some SSH servers do not accept RSA authentication keys. To create the Authentication Subkey as [Ed25519](https://ed25519.cr.yp.to/), run `export KEY_TYPE=ed25519` before the following command.

```bash
printf '%s' "$CERTIFY_PASS" |
  gpg --batch --pinentry-mode loopback --passphrase-fd 0 \
      --quick-add-key "$KEY_FP" "$KEY_TYPE" auth "$KEY_EXPIRATION"
```

# Verify keys

List available secret keys:

```bash
gpg -K
```

The output should display **[C]ertify, [S]ignature, [E]ncryption and [A]uthentication** keys:

```console
sec   rsa4096/0xF0F2CFEB04341FB5 2026-08-01 [C]
      Key fingerprint = 4E2C 1FA3 372C BA96 A06A  C34A F0F2 CFEB 0434 1FB5
uid                   [ultimate] yk.pn8wgfx67khlhext
ssb   rsa4096/0xB3CD10E502E19637 2026-08-01 [S] [expires: 2028-08-01]
ssb   rsa4096/0x30CBE8C4B085B9F7 2026-08-01 [E] [expires: 2028-08-01]
ssb   rsa4096/0xAD9E24E1B8CB9600 2026-08-01 [A] [expires: 2028-08-01]
```

# Backup keys

Export the public key:

```bash
gpg --output $GNUPGHOME/public-$KEY_ID-$(date +%F).asc \
    --armor --export $KEY_ID
```

Export the Certify key:

```bash
printf '%s' "$CERTIFY_PASS" |
  gpg --batch --pinentry-mode loopback --passphrase-fd 0 \
      --output $GNUPGHOME/secret-$KEY_ID-Certify.key \
      --armor --export-secret-keys $KEY_ID
```

Export the Subkeys:

```bash
printf '%s' "$CERTIFY_PASS" |
  gpg --batch --pinentry-mode loopback --passphrase-fd 0 \
      --output $GNUPGHOME/secret-$KEY_ID-Subkeys.key \
      --armor --export-secret-subkeys $KEY_ID
```

> [!IMPORTANT]
> The exported `.key` files contain secret keys. Anyone who obtains these files and the Certify key passphrase can create Subkeys and sign or decrypt data encrypted to those keys.

Create a backup on encrypted storage to be kept offline in a secure and durable location.

Repeat the process several times on multiple portable storage devices, as they may fail over time. As an additional backup measure, [Paperkey](https://www.jabberwocky.com/software/paperkey/) can create a physical copy of key materials for improved durability.

> [!TIP]
> [ext2](https://en.wikipedia.org/wiki/Ext2) file systems (without encryption) can be mounted on Linux and OpenBSD.
> Use [FAT32](https://en.wikipedia.org/wiki/Fat32) or [NTFS](https://en.wikipedia.org/wiki/Ntfs) file systems for macOS and Windows compatibility instead.

> [!WARNING]
> Confirm the destination (`of`) before issuing `dd` commands as they are destructive! This guide uses `/dev/sdc` - this value may be different on your system.

**Linux**

Attach a portable storage device and confirm its label - in this example `/dev/sdc`:

```console
$ sudo dmesg | tail
usb-storage 3-2:1.0: USB Mass Storage device detected
sd 2:0:0:0: [sdc] Attached SCSI removable disk

$ sudo fdisk -l /dev/sdc
Disk /dev/sdc: 14.9 GiB, 15931539456 bytes, 31116288 sectors
```

Clear the first 4 MiB so the operating system does not retain previous partition tables:

```bash
sudo dd if=/dev/zero of=/dev/sdc bs=4M count=1
```

Remove and reconnect the storage device so the operating system reads the cleared partition table before the next command.

Create a new GPT partition table:

```bash
sudo fdisk /dev/sdc <<EOF
g
w
EOF
```

Create a small partition (at least 20 MB, to account for the LUKS header) for storing backups:

```bash
sudo fdisk /dev/sdc <<EOF
n


+20M
w
EOF
```

Use [LUKS](https://dys2p.com/en/2023-05-luks-security.html) to encrypt the backup partition before storing the Certify key on it.

Generate another unique [passphrase](#passphrase) (different from the Certify key passphrase) to protect the encrypted volume:

```bash
export LUKS_PASS=$(LC_ALL=C tr -dc "A-Z3-9" < /dev/urandom |
  tr -d "IOUS5" |
  head -c ${PASS_LENGTH:-24} |
  fold -w ${PASS_GROUPSIZE:-4} |
  paste -sd ${PASS_DELIMITER:--} -)
printf "\nLUKS passphrase:\t%s\n\n" "$LUKS_PASS"
```

This passphrase unlocks the encrypted backup volume, which contains the Certify key. It is needed to renew, rotate, or recover Subkeys. Write the passphrase down or memorize it.

Confirm root privileges are available:

```bash
sudo -v
```

Format the partition:

```bash
printf '%s' "$LUKS_PASS" | sudo cryptsetup -q luksFormat /dev/sdc1
```

Unlock the encrypted partition and create the mapped device:

```bash
printf '%s' "$LUKS_PASS" | sudo cryptsetup -q luksOpen /dev/sdc1 gnupg-secrets
```

Create an ext2 filesystem:

```bash
sudo mkfs.ext2 /dev/mapper/gnupg-secrets -L gnupg-$(date +%F)
```

Mount the filesystem and copy the temporary GnuPG working directory with key materials:

```bash
sudo mkdir -p /mnt/encrypted-storage
sudo mount /dev/mapper/gnupg-secrets /mnt/encrypted-storage
sudo cp -av $GNUPGHOME /mnt/encrypted-storage/
```

Unmount and close the encrypted volume:

```bash
sudo umount /mnt/encrypted-storage
sudo cryptsetup luksClose gnupg-secrets
```

Repeat the process for any additional storage devices (at least two are recommended).

**OpenBSD**

Attach a USB disk and determine its label:

```console
$ dmesg | grep sd.\ at
sd2 at scsibus5 targ 1 lun 0: <TS-RDF5, SD Transcend, TS37> SCSI4 0/direct removable serial.00000000000000000000
```

Print the existing partitions to make sure it's the right device:

```bash
doas disklabel -h sd2
```

Create an `a` partition of FS type `RAID` and size of 25 Megabytes:

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

Encrypt with bioctl using a unique [Passphrase](#passphrase):

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

```bash
doas mkdir -p /mnt/encrypted-storage
doas mount /dev/sd3i /mnt/encrypted-storage
doas cp -av $GNUPGHOME /mnt/encrypted-storage
```

Unmount and remove the encrypted volume:

```bash
doas umount /mnt/encrypted-storage
doas bioctl -d sd3
```

See [OpenBSD FAQ#14](https://www.openbsd.org/faq/faq14.html#softraidCrypto) for more information.

# Export public key

> [!IMPORTANT]
> YubiKey stores the transferred private Subkeys. Each computer also needs the public key and its metadata to identify and use them with GnuPG. Without the public key, it is **not** be possible to use GnuPG to decrypt and sign. However, YubiKey can still be used for SSH authentication.

Connect another portable storage device or create a new partition on the existing one.

**Linux**

Using the same `/dev/sdc` device as in the previous step, create a small (at least 20 MB is recommended) partition for storing materials:

```bash
sudo fdisk /dev/sdc <<EOF
n


+20M
w
EOF
```

Create a filesystem and export the public key:

```bash
sudo mkfs.ext2 /dev/sdc2
sudo mkdir -p /mnt/public
sudo mount /dev/sdc2 /mnt/public
gpg --armor --export $KEY_ID | sudo tee /mnt/public/$KEY_ID-$(date +%F).asc
sudo chmod 0444 /mnt/public/*.asc
```

Unmount and remove the storage device:

```bash
sudo umount /mnt/public
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

```bash
doas newfs sd2b
doas mkdir -p /mnt/public
doas mount /dev/sd2b /mnt/public
gpg --armor --export $KEY_ID | doas tee /mnt/public/$KEY_ID-$(date +%F).asc
```

Unmount and remove the storage device:

```bash
doas umount /mnt/public
```

# Configure YubiKey

Connect YubiKey and confirm its status:

```bash
gpg --card-status
```

If the YubiKey is locked, follow [Reset YubiKey](#reset-yubikey) to permanently delete any existing keys stored on it.

## Change PIN

YubiKey contains several independent [applications](https://developers.yubico.com/). This guide uses the [OpenPGP application](https://developers.yubico.com/PGP/), whose PINs are separate from PINs used by [PIV](https://developers.yubico.com/PIV/), FIDO, and other card features.

Name | Default | Capability
:-: | :-: | -
User PIN | `123456` | routine key operations (decrypt, sign, authenticate)
Admin PIN | `12345678` | manage card settings (reset PIN, change Reset Code, add keys and owner information)
Reset Code | None | reset PIN ([more information](https://forum.yubico.com/viewtopicd01c.html?p=9055#p9055))

The *User PIN* must be at least 6 characters and the *Admin PIN* must be at least 8 characters. A maximum of 127 ASCII characters are allowed. See [Managing PINs](https://www.gnupg.org/howtos/card-howto/en/ch03s02.html) for more information.

YubiKey limits failed PIN attempts, which reduces guessing risk, allowing the User PIN to be short and convenient for regular use.

Generate convenient numeric PINs: an 8-digit Admin PIN and a 6-digit User PIN. These meet the minimum lengths but can be increased:

```bash
PINS=$(LC_ALL=C tr -dc '0-9' < /dev/urandom | head -c 14)
export ADMIN_PIN=${PINS:0:8}
export USER_PIN=${PINS:8:6}
printf "\nAdmin PIN:\t\t%s\nUser  PIN:\t\t%s\n\n" "$ADMIN_PIN" "$USER_PIN"
```

Change the Admin PIN:

```bash
gpg --command-fd 0 --pinentry-mode loopback --change-pin <<EOF
3
12345678
$ADMIN_PIN
$ADMIN_PIN
q
EOF
```

Change the User PIN:

```bash
gpg --command-fd 0 --pinentry-mode loopback --change-pin <<EOF
1
123456
$USER_PIN
$USER_PIN
q
EOF
```

Remove and reinsert YubiKey.

> [!CAUTION]
> Three incorrect *User PIN* entries will cause it to become blocked and must be unblocked with either the *Admin PIN* or *Reset Code*. Three incorrect *Admin PIN* or *Reset Code* entries will destroy data on YubiKey.

Increase PIN limits if the risk of accidental lockout outweighs the increased opportunity for guessing. This command sets five attempts for the User PIN, Reset Code, and Admin PIN:

```bash
ykman openpgp access set-retries 5 5 5 -f -a $ADMIN_PIN
```

## Set attributes

> [!IMPORTANT]
> OpenPGP card metadata is readable without authentication by anyone with physical access to the YubiKey. This includes the card serial number, key fingerprints, public-key data, and other card attributes. Do not store a name, email address, account name, or other personal identifier in Login data, except for deliberate lost-and-found or asset-management purposes.

Set the card Login attribute. The random label generated by the following command is intentionally non-identifying:

```bash
export CARD_ATTR_LOGIN="yk.$(LC_ALL=C tr -dc 'a-z0-9' < /dev/urandom | head -c 16)"
printf "\nLogin attribute:\t%s\n\n" "$CARD_ATTR_LOGIN"
```

Apply the attribute:

```bash
gpg --command-fd 0 --pinentry-mode loopback --edit-card <<EOF
admin
login
$CARD_ATTR_LOGIN
$ADMIN_PIN
quit
EOF
```

Verify the attribute:

```console
$ gpg --card-status | grep Login
Login data .......: yk.3i568zcrib5f
```

[Smart card attributes](https://gnupg.org/howtos/card-howto/en/smartcard-howto-single.html) can also be set with `gpg --edit-card` and `admin` mode. Use `help` to see available options. The [login](https://www.gnupg.org/documentation/manuals/gnupg/gpg_002dcard.html) attribute is [required](https://github.com/drduh/YubiKey-Guide/issues/461) to transfer keys.

# Transfer Subkeys

> [!NOTE]
> After each transfer, GnuPG deletes its usable local copy of the private key and retains only a record that the Subkey is on this YubiKey. The Subkey cannot be copied back from the YubiKey. Confirm that offline backups exist before continuing.

The Certify key passphrase and Admin PIN are required to transfer keys.

## Signature key

Transfer the Signature key:

```bash
gpg --command-fd 0 --pinentry-mode loopback --edit-key $KEY_FP <<EOF
key 1
keytocard
1
$CERTIFY_PASS
$ADMIN_PIN
save
EOF
```

## Encryption key

Repeat the process for the Encryption key:

```bash
gpg --command-fd 0 --pinentry-mode loopback --edit-key $KEY_FP <<EOF
key 2
keytocard
2
$CERTIFY_PASS
$ADMIN_PIN
save
EOF
```

## Authentication key

Repeat the process for the Authentication key:

```bash
gpg --command-fd 0 --pinentry-mode loopback --edit-key $KEY_FP <<EOF
key 3
keytocard
3
$CERTIFY_PASS
$ADMIN_PIN
save
EOF
```

# Verify transfer

Verify Subkeys are on YubiKey:

```bash
gpg -K
```

All three Subkeys should appear as `ssb>` - the `>` indicates the private key is on the smart card:

```console
sec   rsa4096/0xF0F2CFEB04341FB5 2026-08-01 [C]
      Key fingerprint = 4E2C 1FA3 372C BA96 A06A  C34A F0F2 CFEB 0434 1FB5
uid                   [ultimate] yk.pn8wgfx67khlhext
ssb>  rsa4096/0xB3CD10E502E19637 2026-08-01 [S] [expires: 2028-08-01]
ssb>  rsa4096/0x30CBE8C4B085B9F7 2026-08-01 [E] [expires: 2028-08-01]
ssb>  rsa4096/0xAD9E24E1B8CB9600 2026-08-01 [A] [expires: 2028-08-01]
```

# Finish setup

Confirm the following steps were successfully completed to finish setup:

- [ ] Memorized or recorded the Certify key passphrase and stored it in a secure, durable location
  - `echo $CERTIFY_PASS` to see it again
  - [passphrase.html](https://raw.githubusercontent.com/drduh/YubiKey-Guide/main/templates/passphrase.html) or [passphrase.txt](https://raw.githubusercontent.com/drduh/YubiKey-Guide/main/templates/passphrase.txt) to transcribe it
- [ ] Memorized or recorded the passphrase for the encrypted backup volume and stored it separately from that volume
  - `echo $LUKS_PASS` to see it again
  - [passphrase.html](https://raw.githubusercontent.com/drduh/YubiKey-Guide/main/templates/passphrase.html) or [passphrase.txt](https://raw.githubusercontent.com/drduh/YubiKey-Guide/main/templates/passphrase.txt) to transcribe it
- [ ] Saved the Certify key and Subkeys to encrypted portable storage, to be kept offline
  - At least two backups are recommended
  - Backups stored at separate locations
- [ ] Exported a copy of the public key where it can be easily accessed later
  - Separate device or non-encrypted partition was used
- [ ] Memorized or wrote down the User PIN and Admin PIN, which are unique and changed from default values
  - `echo $USER_PIN $ADMIN_PIN` to see them again
  - [`passphrase.html`](https://raw.githubusercontent.com/drduh/YubiKey-Guide/main/templates/passphrase.html) or [`passphrase.txt`](https://raw.githubusercontent.com/drduh/YubiKey-Guide/main/templates/passphrase.txt) to transcribe them
- [ ] Moved Encryption, Signature and Authentication Subkeys to YubiKey
  - `gpg -K` shows `ssb>` for all 3 Subkeys
- [ ] Cleared temporary working directory/environment with reboot or explicit command

# Using YubiKey

Create or inspect the local GnuPG keyring. This command lists public keys and initializes `~/.gnupg` if needed:

```bash
gpg -k
```

Import the [recommended configuration](https://github.com/drduh/YubiKey-Guide/blob/main/config/gpg.conf):

```bash
cd ~/.gnupg
wget https://raw.githubusercontent.com/drduh/YubiKey-Guide/main/config/gpg.conf
```

Set the following option. This avoids the problem where GnuPG will repeatedly prompt for the insertion of an already-inserted YubiKey:

```bash
touch scdaemon.conf
echo "disable-ccid" >>scdaemon.conf
```

Install the required packages:

**Debian/Ubuntu**

```bash
sudo apt update
sudo apt install -y gnupg gnupg-agent scdaemon pcscd
```

**Arch**

```bash
sudo pacman -S --needed gnupg pcsc-tools
sudo systemctl enable --now pcscd.service
```

**macOS**

```bash
brew install gnupg
```

Or using MacPorts

```bash
sudo port install gnupg2 pcsc-tools
```

**OpenBSD**

```bash
doas pkg_add gnupg pcsc-tools
doas rcctl enable pcscd
doas reboot
```

Mount the non-encrypted volume with the public key:

**Debian/Ubuntu**

```bash
sudo mkdir -p /mnt/public
sudo mount /dev/sdc2 /mnt/public
```

**OpenBSD**

```bash
doas mkdir -p /mnt/public
doas mount /dev/sd3i /mnt/public
```

Import the public key:

```bash
gpg --import /mnt/public/public-*.asc
```

Or download the public key from a keyserver:

```bash
gpg --recv $KEY_ID
```

Or with the URL on YubiKey, retrieve the public key:

```bash
printf "fetch" | gpg --command-fd 0 --pinentry-mode loopback --card-edit
```

Determine the key ID:

```bash
gpg -k
export KEY_ID=0xF0F2CFEB04341FB5
```

Assign ultimate trust by typing `trust` and selecting option `5` then `quit`:

```bash
gpg --command-fd 0 --pinentry-mode loopback --edit-key $KEY_ID <<EOF
trust
5
y
save
EOF
```

Remove and reinsert YubiKey.

Verify the status with `gpg --card-status` which will list the available Subkeys:

```console
Reader ...........: Yubico YubiKey FIDO CCID
Application ID ...: D2760001240102010006055532110000
Application type .: OpenPGP
Version ..........: 3.4
Manufacturer .....: Yubico
Serial number ....: 05553211
Name of cardholder: [not set]
Language prefs ...: [not set]
Salutation .......:
URL of public key : [not set]
Login data .......: yk.3i568zcrib5f
Signature PIN ....: not forced
Key attributes ...: rsa4096 rsa4096 rsa4096
Max. PIN lengths .: 127 127 127
PIN retry counter : 3 3 3
Signature counter : 0
KDF setting ......: off
UIF setting ......: Sign=off Decrypt=off Auth=off
Signature key ....: CF5A 305B 808B 7A0F 230D  A064 B3CD 10E5 02E1 9637
      created ....: 2026-08-01 12:00:00
Encryption key....: A5FA A005 5BED 4DC9 889D  38BC 30CB E8C4 B085 B9F7
      created ....: 2026-08-01 12:00:00
Authentication key: 570E 1355 6D01 4C04 8B6D  E2A3 AD9E 24E1 B8CB 9600
      created ....: 2026-08-01 12:00:00
General key info..: sub  rsa4096/0xB3CD10E502E19637 2026-08-01 yk.pn8wgfx67khlhext
sec#  rsa4096/0xF0F2CFEB04341FB5  created: 2026-08-01  expires: never
ssb>  rsa4096/0xB3CD10E502E19637  created: 2026-08-01  expires: 2028-08-01
                                  card-no: 0006 05553211
ssb>  rsa4096/0x30CBE8C4B085B9F7  created: 2026-08-01  expires: 2028-08-01
                                  card-no: 0006 05553211
ssb>  rsa4096/0xAD9E24E1B8CB9600  created: 2026-08-01  expires: 2028-08-01
                                  card-no: 0006 05553211
```

`sec#` indicates the corresponding key is not available (the Certify key is offline).

YubiKey is now ready for use!

## Encryption

Encrypt a message to yourself (useful for storing credentials or protecting backups):

```bash
echo -e "\ntest message string" |
  gpg --encrypt --armor \
      --recipient $KEY_ID --output encrypted.txt
```

Decrypt the message - a prompt for the User PIN will appear:

```bash
gpg --decrypt --armor encrypted.txt
```

To encrypt to multiple recipients/keys, set the preferred key ID last:

```bash
echo "test message string" |
  gpg --encrypt --armor \
      --recipient $KEY_ID_2 \
      --recipient $KEY_ID_1 \
      --recipient $KEY_ID_0 \
      --output encrypted.txt
```

Use a [shell function](https://github.com/drduh/config/blob/main/zshrc) to make encrypting files easier:

```bash
secret () {
  output="${1}".$(date +%s).enc
  gpg --encrypt --armor --output ${output} \
    -r $KEY_ID "${1}" && echo "${1} -> ${output}"
}

reveal () {
  output=$(echo "${1}" | rev | cut -c16- | rev)
  gpg --decrypt --output ${output} "${1}" && \
    echo "${1} -> ${output}"
}
```

Example output:

```console
$ secret document.pdf
document.pdf -> document.pdf.1780000000.enc

$ reveal document.pdf.1780000000.enc
gpg: anonymous recipient; trying secret key 0xF0F2CFEB04341FB5 ...
gpg: okay, we are the anonymous recipient.
gpg: encrypted with RSA key, ID 0x0000000000000000
document.pdf.1780000000.enc -> document.pdf
```

[drduh/Purse](https://github.com/drduh/Purse) is a secrets manager implemented with GnuPG and YubiKey.

## Signature

Sign a message:

```bash
echo "test message string" | gpg --armor --clearsign > signed.txt
```

Verify the signature:

```bash
gpg --verify signed.txt
```

The output will be similar to:

```console
gpg: Signature made Sat 01 Aug 2026 12:00:00 PM UTC
gpg:                using RSA key CF5A305B808B7A0F230DA064B3CD10E502E19637
gpg: Good signature from "yk.pn8wgfx67khlhext" [ultimate]
Primary key fingerprint: 4E2C 1FA3 372C BA96 A06A  C34A F0F2 CFEB 0434 1FB5
     Subkey fingerprint: CF5A 305B 808B 7A0F 230D  A064 B3CD 10E5 02E1 9637
```

## Configure touch

By default, cryptographic operations do not require any action from the user after YubiKey is unlocked with the User PIN.

To require a touch for each operation, use [YubiKey Manager](https://developers.yubico.com/yubikey-manager/) and the Admin PIN to set key policy.

Encryption:

```bash
ykman openpgp keys set-touch dec on
```

> [!NOTE]
> YubiKey Manager prior to version 5.1.0 uses `enc` instead of `dec` for encryption:

```bash
ykman openpgp keys set-touch enc on
```

> [!NOTE]
> Legacy versions of YubiKey Manager use `touch` instead of `set-touch`.

Signature:

```bash
ykman openpgp keys set-touch sig on
```

Authentication:

```bash
ykman openpgp keys set-touch aut on
```

To view and adjust policy options:

```bash
ykman openpgp keys set-touch --help
```

`Cached` or `Cached-Fixed` may be desirable for YubiKey use with email clients.

YubiKey blinks when waiting for a touch. On Linux, [maximbaz/yubikey-touch-detector](https://github.com/maximbaz/yubikey-touch-detector) can also be used for indication.

## SSH

Create or import a [hardened configuration](https://github.com/drduh/YubiKey-Guide/blob/main/config/gpg-agent.conf):

```bash
cd ~/.gnupg
wget https://raw.githubusercontent.com/drduh/YubiKey-Guide/main/config/gpg-agent.conf
```

> [!NOTE]
> `cache-ttl` options do **not** apply when using YubiKey as a smart card, because the PIN is [cached by the smart card itself](https://dev.gnupg.org/T3362). To clear the PIN from cache (equivalent to `default-cache-ttl` and `max-cache-ttl`), remove YubiKey, or set `forcesig` when editing the card to be prompted for the PIN each time.

> [!TIP]
> Set `pinentry-program` to `/usr/bin/pinentry-gnome3` for a GUI-based prompt.

**macOS**

Install pinentry with `brew install pinentry-mac` or `sudo port install pinentry` then edit `gpg-agent.conf` to set the `pinentry-program` path to:

- Apple Silicon Macs: `/opt/homebrew/bin/pinentry-mac`
- Intel Macs: `/usr/local/bin/pinentry-mac` or `/opt/local/bin/pinentry` (MacPorts)
- MacGPG Suite: `/usr/local/MacGPG2/libexec/pinentry-mac.app/Contents/MacOS/pinentry-mac`

Then run `gpgconf --kill gpg-agent` for the change to take effect.

To use graphical applications on macOS, [additional setup is required](https://jms1.net/yubikey/make-ssh-use-gpg-agent.md).

Create `$HOME/Library/LaunchAgents/gnupg.gpg-agent.plist` with the following contents:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>gnupg.gpg-agent</string>
        <key>RunAtLoad</key>
        <true/>
        <key>KeepAlive</key>
        <false/>
        <key>EnvironmentVariables</key>
        <dict>
            <key>PATH</key>
            <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/usr/local/MacGPG2/bin:/bin</string>
        </dict>
        <key>ProgramArguments</key>
        <array>
            <string>/usr/bin/env</string>
            <string>gpg-connect-agent</string>
            <string>/bye</string>
        </array>
    </dict>
</plist>
```

Load it:

```bash
launchctl load $HOME/Library/LaunchAgents/gnupg.gpg-agent.plist
```

Create `$HOME/Library/LaunchAgents/gnupg.gpg-agent-symlink.plist` with the following contents:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0/dtd">
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

Load it:

```bash
launchctl load $HOME/Library/LaunchAgents/gnupg.gpg-agent-symlink.plist
```

Reboot to activate changes.

**Windows**

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

```bash
gpg-connect-agent killagent /bye
gpg-connect-agent /bye
```

Verify YubiKey details:

```bash
gpg --card-status
```

Import the public key and set ultimate trust:

```bash
gpg --import <path to public key file>
```

Retrieve the public key id:

```bash
gpg --list-public-keys
```

Export the SSH public key:

```bash
gpg --export-ssh-key <public key id>
```

Copy the public SSH key to a file - it corresponds to the secret key on YubiKey and can be copied to SSH destination hosts.

Create a shortcut that points to `gpg-connect-agent /bye` and place it in the startup folder `shell:startup` to make sure the agent starts after reboot. Modify the shortcut properties so it starts in a "Minimized" window.

PuTTY can now be used for public-key SSH authentication. When the server asks for public-key verification, PuTTY will forward the request to GnuPG, which will prompt for a PIN to authorize the operation.

**WSL**

The goal is to configure SSH client inside WSL work together with the Windows agent, such as gpg-agent.exe.

See the [WSL agent architecture](media/schema_gpg.png) illustration for an overview.

GnuPG forwarding for cryptographic operations is not supported. See [vuori/weasel-pageant](https://github.com/vuori/weasel-pageant) for more information.

One way to forward is just `ssh -A` (still need to eval weasel to setup local ssh-agent), and only relies on OpenSSH. In this track, `ForwardAgent` and `AllowAgentForwarding` in ssh/sshd config may be involved. However, when using ssh socket forwarding, do not enable `ForwardAgent` in ssh config. See [SSH Agent Forwarding](#ssh-agent-forwarding) for more information. This requires Ubuntu 16.04 or newer for WSL and Kleopatra.

Download [vuori/weasel-pageant](https://github.com/vuori/weasel-pageant).

Add `eval $(/mnt/c/<path of extraction>/weasel-pageant -r -a /tmp/S.weasel-pageant)` to the shell rc file. Use a named socket here so it can be used in the `RemoteForward` directive of `~/.ssh/config`. Source it with `source ~/.bashrc`.

Display the SSH key with `ssh-add -l`.

Edit `~/.ssh/config` to add the following for each agent forwarding host:

```console
RemoteForward <remote SSH socket path> /tmp/S.weasel-pageant
```

The remote SSH socket path can be found with `gpgconf --list-dirs agent-ssh-socket`

Add the following to the shell rc file:

```bash
export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
```

Add the following to `/etc/ssh/sshd_config`:

```console
StreamLocalBindUnlink yes
```

Reload SSH daemon:

```bash
sudo service sshd reload
```

Remove YubiKey and reboot. Log back into Windows, open a WSL console and enter `ssh-add -l` - no output should appear.

Plug in YubiKey, enter the same command to display the SSH key.

Connect to the remote host and use `ssh-add -l` to confirm forwarding works.

Agent forwarding may be chained through multiple hosts. Follow the same [protocol](#remote-host-configuration) to configure each host.

An alternate method is the [usbipd-win](https://github.com/dorssel/usbipd-win) library. If you encounter issues with accessing the YubiKey in WSL after configuring usbipd-win, you may need to add custom polkit rules to ensure proper permissions for the pcscd service. Here's an example configuration using a scard group (the group logic is optional):

Create a new rule file at /etc/polkit-1/rules.d/99-pcscd.rules:

```bash
polkit.addRule(function(action, subject) {
    if (action.id == "org.debian.pcsc-lite.access_card" &&
        subject.isInGroup("scard")) {
        return polkit.Result.YES;
    }
});

polkit.addRule(function(action, subject) {
    if (action.id == "org.debian.pcsc-lite.access_pcsc" &&
        subject.isInGroup("scard")) {
        return polkit.Result.YES;
    }
});
```

### Replace agents

To launch `gpg-agent` for SSH, use `gpg-connect-agent /bye` or `gpgconf --launch gpg-agent` commands.

Add the following to the shell rc file:

```bash
export GPG_TTY=$(tty)
export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
gpgconf --launch gpg-agent
gpg-connect-agent updatestartuptty /bye > /dev/null
```

For fish, `config.fish` should look like this (consider putting them into the `is-interactive` block):

```fish
set -x GPG_TTY (tty)
set -x SSH_AUTH_SOCK (gpgconf --list-dirs agent-ssh-socket)
gpgconf --launch gpg-agent
```

When using `ForwardAgent` for ssh-agent forwarding, `SSH_AUTH_SOCK` only needs to be set on the *local* host, where YubiKey is connected. On the *remote* host, `ssh` will set `SSH_AUTH_SOCK` to something like `/tmp/ssh-mXzCzYT2Np/agent.7541` upon connection. Do **not** set `SSH_AUTH_SOCK` on the remote host - doing so will break [SSH Agent Forwarding](#ssh-agent-forwarding).

For `S.gpg-agent.ssh` (see [SSH Agent Forwarding](#ssh-agent-forwarding) for more info), `SSH_AUTH_SOCK` should also be set on the *remote*. However, `GPG_TTY` should not be set on the *remote*, explanation specified in that section.

### Copy public key

> [!TIP]
> It is **not** necessary to import the GnuPG public key in order to use SSH only.

Copy and paste the output from `ssh-add` to the server's `authorized_keys` file:

```console
$ ssh-add -L
ssh-rsa AAAAB4NzaC1yc2EAAAADAQABAAACAz[...]zreOKM+HwpkHzcy9DQcVG2Nw== cardno:000605553211
```

**Optional** Save the public key for identity file configuration. By default, SSH attempts to use all the identities available via the agent. It's often a good idea to manage exactly which keys SSH will use to connect to a server, for example to separate different roles or [to avoid being fingerprinted by untrusted ssh servers](https://words.filippo.io/ssh-whoami-filippo-io/). To do this you'll need to use the command line argument `-i [identity_file]` or the `IdentityFile` and `IdentitiesOnly` options in `.ssh/config`.

The argument provided to `IdentityFile` is traditionally the path to the _private_ key file (for example `IdentityFile ~/.ssh/id_rsa`). For YubiKey, `IdentityFile` must point to the _public_ key file, and `ssh` will select the appropriate private key from those available via ssh-agent. To prevent `ssh` from trying all keys in the agent, use `IdentitiesOnly yes` along with one or more `-i` or `IdentityFile` options for the target host.

To reiterate, with `IdentitiesOnly yes`, `ssh` will not enumerate public keys loaded into `ssh-agent` or `gpg-agent`. This means public-key authentication will not proceed unless explicitly named by `ssh -i [identity_file]` or in `.ssh/config` on a per-host basis.

In the case of YubiKey usage, to extract the public key from the ssh agent:

```bash
ssh-add -L | grep "cardno:000605553211" > ~/.ssh/id_rsa_yubikey.pub
```

Then explicitly associate this YubiKey-stored key for use with a host - `github.com` for example, as follows:

```console
$ cat << EOF >> ~/.ssh/config
Host github.com
  IdentitiesOnly yes
  IdentityFile ~/.ssh/id_rsa_yubikey.pub
EOF
```

Connect with public key authentication:

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

> [!TIP]
> To enable multiple SSH connections, use the [ControlMaster](https://en.wikibooks.org/wiki/OpenSSH/Cookbook/Multiplexing) option.

### Import SSH keys

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

To show MD5 fingerprints, as used by `gpg-connect-agent`'s `KEYINFO` and `DELETE_KEY` commands:

```console
$ ssh-add -E md5 -l
4096 MD5:... cardno:00060123456 (RSA)
2048 MD5:... /Users/username/.ssh/id_rsa (RSA)
```

When using the key `pinentry` will be invoked to request the key passphrase. The passphrase will be cached for up to 10 idle minutes between uses, up to a maximum of 2 hours.

### SSH agent forwarding

> [!CAUTION]
> SSH Agent Forwarding can [add additional risk](https://matrix.org/blog/2019/05/08/post-mortem-and-remediations-for-apr-11-security-incident/#ssh-agent-forwarding-should-be-disabled) - proceed with caution!

There are two methods for ssh-agent forwarding, one is provided by OpenSSH and the other is provided by GnuPG.

The latter one may be more insecure as raw socket is just forwarded (not like `S.gpg-agent.extra` with only limited functionality; if `ForwardAgent` implemented by OpenSSH is just forwarding the raw socket, then they are insecure to the same degree). But for the latter one, one convenience is that one may forward once and use this agent everywhere in the remote. So again, proceed with caution!

For example, tmux does not have environment variables such as `$SSH_AUTH_SOCK` when connecting to remote hosts and attaching an existing session. For each shell, find the socket and `export SSH_AUTH_SOCK=/tmp/ssh-agent-xxx/xxxx.socket`. However, with `S.gpg-agent.ssh` in a fixed place, it can be used as the ssh-agent in shell rc files.

#### Use ssh-agent

Run `ssh -A remote` from the local host. On the remote host, `ssh-add -l` should list the public key from the YubiKey as a `cardno:` entry. Enable `ForwardAgent yes` only for explicitly trusted hosts!

#### Use S.gpg-agent.ssh

Before continuing, configure [GnuPG agent forwarding](gnupg-agent-forwarding) and record the local and remote values of `gpgconf --list-dirs agent-ssh-socket`.

Edit `~/.ssh/config` to add the remote host:

```console
Host
  Hostname remote-host.tld
  StreamLocalBindUnlink yes
  RemoteForward /run/user/1000/gnupg/S.gpg-agent.ssh /run/user/1000/gnupg/S.gpg-agent.ssh
  #RemoteForward [remote socket] [local socket]
  #Note that ForwardAgent is not wanted here!
```

After successfully connecting to the remote host, confirm `/run/user/1000/gnupg/S.gpg-agent.ssh` exists and configure `SSH_AUTH_SOCK`:

```bash
export SSH_AUTH_SOCK="/run/user/$UID/gnupg/S.gpg-agent.ssh"
```

`ssh-add -l` should now return the correct public key.

In this process no gpg-agent in the remote is involved, hence `gpg-agent.conf` in the remote is of no use. Also pinentry is invoked locally.

#### Chained forwarding

To use `ssh-agent` provided by OpenSSH to forward into a *third* host, use `ssh -A third` on the *remote* host.

If you use `S.gpg-agent.ssh`, assume you have gone through the steps above and have `S.gpg-agent.ssh` on the *remote*, and you would like to forward this agent into a *third* box, first configure `sshd_config` and `SSH_AUTH_SOCK` of *third* in the same way as *remote*, then configure SSH of *remote* by adding the following lines:

```console
Host third
  Hostname third-host.tld
  StreamLocalBindUnlink yes
  RemoteForward /run/user/1000/gnupg/S.gpg-agent.ssh /run/user/1000/gnupg/S.gpg-agent.ssh
  #RemoteForward [remote socket] [local socket]
  #Note that ForwardAgent is not wanted here!
```

The path must be set according to `gpgconf --list-dirs agent-ssh-socket` on *remote* and *third* hosts.

## GitHub

Use YubiKey to sign Git commits and tags and to authenticate to GitHub over SSH. To authenticate, first add the exported SSH public key to [GitHub SSH keys](https://github.com/settings/keys).

Configure the signing key:

```bash
git config --global user.signingkey $KEY_ID
```

Alternatively, if you are using the aforementioned `IdentityFile` (SSH key) for signing:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_rsa_yubikey.pub
```

Configure the `user.name` and `user.email` options to match the identity associated with this key:

```bash
git config --global user.name 'YubiKey User'
git config --global user.email yubikey@example.com
```

To sign commits or tags, use the `-S` option, or consider enabling commit and tag signing by default:

```bash
git config --global commit.gpgsign true
git config --global tag.gpgSign true
```

**Windows**

Configure authentication:

```bash
git config --global core.sshcommand "plink -agent"
git config --global gpg.program 'C:\Program Files (x86)\GnuPG\bin\gpg.exe'
```

Then update the repository URL to `git@github.com:USERNAME/repository`

## GnuPG agent forwarding

YubiKey can sign Git commits and decrypt files on remote hosts by forwarding GnuPG agent operations. To connect through an intermediate host and then access GitHub over SSH, see [SSH agent forwarding](#ssh-agent-forwarding).

After forwarding is configured, GnuPG on the remote host communicates through a forwarded socket to gpg-agent on the local host. The local agent accesses the YubiKey and displays any PIN prompt locally.

On the remote host, edit `/etc/ssh/sshd_config` to set `StreamLocalBindUnlink yes`.

**Optional** Without root access on the remote host to edit `/etc/ssh/sshd_config`, socket located at `gpgconf --list-dir agent-socket` on the remote host will need to be removed before forwarding works. See [AgentForwarding GNUPG wiki page](https://wiki.gnupg.org/AgentForwarding) for more information.

Import the public key on the remote host. On the local host, copy the public keyring to the remote host:

```bash
scp ~/.gnupg/pubring.kbx remote:~/.gnupg/
```

On modern distributions, such as Fedora 30, there is no need to set `RemoteForward` in `~/.ssh/config`

### Legacy distributions

On the local host, run:

```bash
gpgconf --list-dirs agent-extra-socket
```

This should return a path to agent-extra-socket - `/run/user/1000/gnupg/S.gpg-agent.extra` - though on some Linux distros (and macOS) it may be `/home/<user>/.gnupg/S.gpg-agent.extra`

Find the agent socket on the **remote** host:

```bash
gpgconf --list-dirs agent-socket
```

This should return a path such as `/run/user/1000/gnupg/S.gpg-agent`

Finally, enable agent forwarding for a given host by adding the following to the local host's `~/.ssh/config` (agent sockets may differ):

```
Host
  Hostname remote-host.tld
  StreamLocalBindUnlink yes
  RemoteForward /run/user/1000/gnupg/S.gpg-agent /run/user/1000/gnupg/S.gpg-agent.extra
  #RemoteForward [remote socket] [local socket]
```

It may be necessary to edit `gpg-agent.conf` on the *local* host to add the following information:

```
pinentry-program /usr/bin/pinentry-gtk-2
extra-socket /run/user/1000/gnupg/S.gpg-agent.extra
```

> [!IMPORTANT]
> The pinentry program starts on the *local* host, not remote.

Any pinentry program except `pinentry-tty` or `pinentry-curses` may be used. This is because local `gpg-agent` may start headlessly (by systemd without `$GPG_TTY` set locally telling which tty it is on), thus failed to obtain the pin. Errors on the remote may be misleading saying that there is *IO Error*. (Yes, internally there is actually an *IO Error* since it happens when writing to/reading from tty while finding no tty to use, but for end users this is not friendly.)

See [Issue 85](https://github.com/drduh/YubiKey-Guide/issues/85) for more information and troubleshooting.

### Chained GnuPG agent forwarding

Assume you have gone through the steps above and have `S.gpg-agent` on the *remote*, and you would like to forward this agent into a *third* box, first you may need to configure `sshd_config` of *third* in the same way as *remote*, then in the ssh config of *remote*, add the following lines:

```console
Host third
  Hostname third-host.tld
  StreamLocalBindUnlink yes
  RemoteForward /run/user/1000/gnupg/S.gpg-agent /run/user/1000/gnupg/S.gpg-agent
  #RemoteForward [remote socket] [local socket]
```

You should change the path according to `gpgconf --list-dirs agent-socket` on *remote* and *third*.

On *local* you have `S.gpg-agent.extra` whereas on *remote* and *third*, you only have `S.gpg-agent`.

## Using multiple YubiKeys

When a GnuPG key is added to YubiKey using `keytocard`, the credential is deleted from the keyring and a local reference ('stub') pointing to the card is added. The stub identifies the GnuPG key ID and YubiKey serial number.

When a Subkey is added to an additional YubiKey, the stub is overwritten and will now point to the latest YubiKey. GnuPG will request a specific YubiKey by serial number, as referenced by the stub, and will not recognize another YubiKey with a different serial number.

To scan an additional YubiKey and recreate the correct stub:

```bash
gpg-connect-agent "scd serialno" "learn --force" /bye
```

Alternatively, use a script to delete the GnuPG shadowed key, where the serial number is stored (see [GnuPG #T2291](https://dev.gnupg.org/T2291)):

```bash
mkdir -p ~/scripts && cat >> ~/scripts/remove-keygrips.sh <<EOF
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

~/scripts/remove-keygrips.sh $KEY_ID
```

See discussion in [#19](https://github.com/drduh/YubiKey-Guide/issues/19) and [#112](https://github.com/drduh/YubiKey-Guide/issues/112) for more information.

## Email

YubiKey can decrypt and sign emails and attachments using [Thunderbird](https://www.thunderbird.net/) and [Mutt](http://www.mutt.org/). Thunderbird supports OAuth and can be used with Gmail. See [this EFF guide](https://ssd.eff.org/en/module/how-use-pgp-linux) for more information.

### Thunderbird

Follow [Mozilla instructions](https://wiki.mozilla.org/Thunderbird:OpenPGP:Smartcards#Configure_an_email_account_to_use_an_external_GnuPG_key) to setup YubiKey with Thunderbird using the external GPG provider.

> [!NOTE]
> Thunderbird will [fail to decrypt](https://github.com/drduh/YubiKey-Guide/issues/448) messages if the `armor` option is configured.
> If you see the error `gpg: [don't know]: invalid packet (ctb=2d)` or `message cannot be decrypted (there are unknown problems with this encrypted message)`, remove `armor` from `~/.gnupg/gpg.conf`, then restart Thunderbird.

### Mailvelope

[Mailvelope](https://www.mailvelope.com/en) allows YubiKey to be used with Gmail and others.

> [!NOTE]
> Mailvelope [does not work](https://github.com/drduh/YubiKey-Guide/issues/178) with the `throw-keyids` option set in `gpg.conf`

On macOS, install gpgme using Homebrew:

```bash
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

```bash
sudo launchctl config user path /usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
```

Finally, install the [Mailvelope extension](https://chromewebstore.google.com/detail/mailvelope/kajibbejlbohfaggdiogboambcijhkke) from the Chrome web store.

### Mutt

Mutt can be used from the command line or its text-based interface. To enable OpenPGP support, copy the sample GnuPG configuration file (`/usr/share/doc/mutt/samples/gpg.rc`), set `pgp_default_key`, `pgp_sign_as`, and `pgp_autosign` in that file, then add a source line for it in the Mutt configuration file (`~/.muttrc`).

> [!NOTE]
> `pinentry-tty` set as the pinentry program in `gpg-agent.conf` may cause problems with Mutt because it uses curses; use `pinentry-curses` or other graphic pinentry program instead.

## Keyserver

Optionally, publish the public key to a keyserver so others can find it.

Select a server to send it to:

```bash
gpg --send-key $KEY_ID
gpg --keyserver keys.gnupg.net --send-key $KEY_ID
gpg --keyserver hkps://keyserver.ubuntu.com:443 --send-key $KEY_ID
```

Or if [uploading to keys.openpgp.org](https://keys.openpgp.org/about/usage):

```bash
gpg --export $KEY_ID | curl -T - https://keys.openpgp.org
```

A retrieval URL can also be stored on YubiKey:

```bash
URL="hkps://keyserver.ubuntu.com:443/pks/lookup?op=get&search=${KEY_ID}"
```

Edit YubiKey with `gpg --edit-card` and the Admin PIN:

```console
gpg/card> admin

gpg/card> url
URL to retrieve public key: hkps://keyserver.ubuntu.com:443/pks/lookup?op=get&search=0xFF00000000000000

gpg/card> quit
```

# Updating keys

OpenPGP does not provide [forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy): if an encryption key is compromised, an attacker may be able to decrypt messages encrypted to that key in the past. Renewing or replacing Subkeys limits future use of a lost or obsolete key, but it may not protect previously encrypted data. Choose an expiration and renewal schedule to meet individual risk tolerance and maintenance capacity preferences.

When a Subkey expires, it can either be renewed or replaced. Both actions require access to the Certify key.

- Renewal preserves existing Subkeys and is generally simpler to operate.
- Replacement creates new Subkeys and may be more secure: new Subkeys will **not** be able to decrypt previous data, authenticate with SSH, etc. The public key will need to be updated and any encrypted data must be decrypted and re-encrypted to new Subkeys. This process is functionally equivalent to provisioning a new YubiKey.

Neither rotation method is superior and it is up to personal philosophy on identity management and individual threat modeling to decide which one to use, or whether to expire Subkeys at all. Ideally, Subkeys would be ephemeral: used only once for each unique encryption, signature and authentication event, however in practice that is not really practical nor worthwhile with YubiKey. Advanced users may dedicate an air-gapped machine for frequent credential rotation.

To renew or rotate Subkeys, follow the same process as generating keys: boot to a secure environment, install required software and disable networking.

Connect the portable storage device with the Certify key and identify the device path.

Decrypt and mount the encrypted volume:

```bash
sudo cryptsetup luksOpen /dev/sdc1 gnupg-secrets
sudo mkdir -p /mnt/encrypted-storage
sudo mount /dev/mapper/gnupg-secrets /mnt/encrypted-storage
```

Mount the non-encrypted public partition:

```bash
sudo mkdir -p /mnt/public
sudo mount /dev/sdc2 /mnt/public
```

Copy the original private key materials (after updating the encrypted storage directory name) to a temporary working directory:

```bash
export GNUPGHOME=$(mktemp -d "${TMPDIR:-/tmp}/$(date +%Y.%m.%d)-XXXXXXXX")
cp -avi /mnt/encrypted-storage/2026.*/* $GNUPGHOME/
```

Confirm the identity is available, set the key ID and fingerprint values:

```bash
gpg -K
export KEY_FP=$(gpg -k --with-colons $IDENTITY | awk -F: '/^fpr:/ { print $10; exit }')
export KEY_ID="${KEY_FP: -16}"
printf "\nKey ID/Fingerprint:\t%s\n%s\n\n" "$KEY_ID" "$KEY_FP"
```

Recall the Certify key passphrase and set it, for example:

```bash
export CERTIFY_PASS="ABCD-0123-IJKL-4567-QRST-UVWX"
```

## Renew Subkeys

Set the updated expiration date:

```bash
export KEY_EXPIRATION=2028-09-01
```

Renew the Subkeys:

```bash
printf '%s' "$CERTIFY_PASS" |
  gpg --batch --pinentry-mode loopback \
      --passphrase-fd 0 --quick-set-expire "$KEY_FP" "$KEY_EXPIRATION" \
    $(gpg -K --with-colons |
      awk -F: '$1=="fpr" { if (++n > 1) printf "%s ", $10 } END { print "" }')
```

Export the updated public key:

```bash
gpg --armor --export $KEY_ID | sudo tee /mnt/public/$KEY_ID-$(date +%F).asc
```

Transfer the public key to the destination host and import it:

```bash
gpg --import /mnt/public/*.asc
```

Alternatively, publish to a public key server and download it:

```bash
gpg --send-key $KEY_ID
gpg --recv $KEY_ID
```

The validity of the GnuPG identity will be extended, enabling encryption and signature operations.

The SSH public key does **not** need to be updated on remote hosts.

## Rotate Subkeys

Follow the original procedure to [Create Subkeys](#create-subkeys).

Previous Subkeys can be deleted from the identity.

Finish by transferring new Subkeys to YubiKey.

Copy the **new** temporary working directory to encrypted storage, which is still mounted:

```bash
sudo cp -avi $GNUPGHOME /mnt/encrypted-storage
```

Unmount and close the encrypted volume:

```bash
sudo umount /mnt/encrypted-storage
sudo cryptsetup luksClose gnupg-secrets
```

Export the updated public key:

```bash
sudo mkdir -p /mnt/public
sudo mount /dev/sdc2 /mnt/public
gpg --armor --export $KEY_ID | sudo tee /mnt/public/$KEY_ID-$(date +%F).asc
sudo umount /mnt/public
```

Remove the storage device and follow the original steps to transfer new Subkeys (`4`, `5` and `6`) to YubiKey, replacing existing ones.

Reboot or securely erase the temporary working directory.

# Reset YubiKey

If PIN attempts are exceeded, the YubiKey is locked and must be [Reset](https://developers.yubico.com/ykneo-openpgp/ResetApplet.html) and set up again using the encrypted backup.

Use YubiKey Manager to reset the OpenPGP application:

```bash
ykman openpgp reset
```

YubiKey can also be reset with [scripts/resetCard.sh](https://github.com/drduh/YubiKey-Guide/blob/main/scripts/resetCard.sh), or by copying the following commands to a file and running `gpg-connect-agent -r <filename>`:

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
/bye
```

Remove and reinsert the YubiKey to complete reset.

# Optional hardening

The following steps may improve the security and privacy of YubiKey.

## Improving entropy

Generating cryptographic keys requires high-quality [randomness](https://www.random.org/randomness/), measured as entropy. Most operating systems use software-based pseudorandom number generators or CPU-based hardware random number generators (HRNG).

Optionally, a device such as [OneRNG](https://onerng.info/onerng/) may be used to [increase the speed](https://lwn.net/Articles/648550/) and possibly the quality of available entropy.

Before creating keys, configure [rng-tools](https://wiki.archlinux.org/title/Rng-tools):

```bash
sudo apt -y install at rng-tools python3-gnupg openssl
wget https://github.com/OneRNG/onerng.github.io/raw/master/sw/onerng_3.7-1_all.deb
```

Verify the package:

```bash
sha256sum onerng_3.7-1_all.deb
```

The value must match:

```console
b7cda2fe07dce219a95dfeabeb5ee0f662f64ba1474f6b9dddacc3e8734d8f57
```

Install the package:

```bash
sudo dpkg -i onerng_3.7-1_all.deb
echo "HRNGDEVICE=/dev/ttyACM0" | sudo tee /etc/default/rng-tools
```

Insert the device and restart rng-tools:

```bash
sudo atd
sudo service rng-tools restart
```

## Enable KDF

> [!IMPORTANT]
> This feature is not compatible with legacy GnuPG versions, especially mobile clients, and may cause the PIN to always be rejected.

This step must be completed before changing PINs or moving keys or an error will occur: `gpg: error for setup KDF: Conditions of use not satisfied`

A key derivation function (KDF) derives a value from the PIN before it is sent to the card, reducing its exposure.

Enable KDF using the default Admin PIN of `12345678`:

```bash
gpg --command-fd 0 --pinentry-mode loopback --card-edit <<EOF
admin
kdf-setup
12345678
EOF
```

## Network considerations

This section is primarily focused on Debian/Ubuntu systems, but the concepts apply to any system connected to a network.

Whether using a virtual machine, installing on dedicated hardware, or running a Live OS temporarily, start *without* a network connection and disable any unnecessary services listening on all interfaces before connecting to the network.

Services such as cups and avahi may listen on the network by default, increasing potential attack surface. For this workflow, treat every network as untrusted.

**Disable listening services**

Ensure only essential network services are running. If a service does not exist, a "Failed to stop" warning may appear:

```bash
sudo systemctl stop bluetooth exim4 cups avahi avahi-daemon sshd
```

**Firewall**

Enable a basic firewall policy of *deny inbound, allow outbound*.

Debian does not enable a default host-firewall policy by default.

On Ubuntu, [ufw](https://ubuntu.com/server/docs/how-to/security/firewalls/) is built-in and can be enabled with:

```bash
sudo ufw enable
```

On systems without `ufw`, `nftables` is replacing `iptables`. The [nftables wiki has examples](https://wiki.nftables.org/wiki-nftables/index.php/Simple_ruleset_for_a_workstation) for a baseline *deny inbound, allow outbound* policy. The `fw.inet.basic` policy covers both IPv4 and IPv6.

Download this README and any other resources to another external drive when creating the bootable media, to have this information ready to use offline.

Regardless of which policy is configured, write the contents to a file (e.g., `nftables.conf`) and apply the policy with the following command:

```bash
sudo nft -f ./nftables.conf
```

**Review system state**

`NetworkManager` should be the only listening service on port 68/udp to obtain a DHCP lease (and 58/icmp6 if you have IPv6).

To examine a process's command line arguments, use `ps axjf` to print a process tree.

```bash
# Dump network state information
sudo ss -anp -A inet

# List all processes in a process tree
ps axjf

# BSD syntax, list all processes but no process tree
ps aux
```

If you find any additional processes listening on the network that aren't needed, take note and disable them with one of the following:

```bash
# Stop services managed by systemctl
sudo systemctl stop <process-name>

# Terminate the process by matching its command line string
sudo pkill -f '<process-name-or-command-line-string>'

# Obtain the process ID
pgrep -f '<process-name-or-command-line-string>'

# Terminate the process ID
sudo kill <pid>
```

After reviewing the system state and applying any desired restrictions, connect to the network only to download required software. Disconnect again before generating keys.

# Notes

1. YubiKey has two USB configurations selected by a short or long touch. By default, a short touch may type a one-time-password string beginning with `cccccccc`. This behavior is separate from the OpenPGP workflow and can be moved to the second configuration or disabled with `ykman config usb -d OTP`.

1. Using YubiKey for GnuPG does not prevent use of [other features](https://developers.yubico.com/), such as [WebAuthn](https://developers.yubico.com/WebAuthn/) and [OTP](https://developers.yubico.com/OTP/).

1. To switch between YubiKeys, remove the first YubiKey and restart gpg-agent, ssh-agent and pinentry with `pkill "gpg-agent|ssh-agent|pinentry" ; eval $(gpg-agent --daemon --enable-ssh-support)` then insert the other YubiKey and run `gpg-connect-agent updatestartuptty /bye`.

1. To use YubiKey on multiple computers, import the corresponding public keys, then confirm YubiKey is visible with `gpg --card-status`. Trust the imported public keys ultimately with `trust` and `5`, then `gpg --list-secret-keys` will show the correct and trusted key.

1. To [participate in keysigning parties](https://www.gnupg.org/gph/en/manual/x334.html), signing [imported public keys](https://gist.github.com/F21/b0e8c62c49dfab267ff1d0c6af39ab84) requires first setting up a secure ephemeral environment and importing the Certify key into that enclave; a signing Subkey cannot be used to sign [imported public keys](https://security.stackexchange.com/questions/153057/possible-to-sign-an-imported-key-with-a-subkey-using-gpg).

# Troubleshooting

Symptom or error | Recommended action
--- | ---
General GnuPG questions or unfamiliar options | Use `man gpg` to review GnuPG options and command-line flags.
Need more diagnostic detail | Restart `gpg-agent` with verbose debug output: `pkill gpg-agent; gpg-agent --daemon --no-detach -v -v --debug-level advanced --homedir ~/.gnupg`
General YubiKey or GnuPG issue | Remove and reinsert the YubiKey, or restart `gpg-agent`.
`Yubikey core error: no yubikey present` | Confirm that the YubiKey is inserted correctly. It should blink once when plugged in.
`Yubikey core error: no yubikey present` persists | Install a newer version of `yubikey-personalization`, as described in [Install software](#install-software).
`General key info..: [none]` in card-status output | Import the public key.
The public key is lost | Follow [Recovering lost GPG public keys from your YubiKey](https://www.nicksherlock.com/2021/08/recovering-lost-gpg-public-keys-from-your-yubikey/) to recover it from the YubiKey.
`gpg: decryption failed: secret key not available` | Install GnuPG 2.x. Also verify that the PIN is correct and that the required private Subkey is available on the YubiKey.
`Yubikey core error: write error` | The YubiKey may be locked. Install and run `yubikey-personalization-gui` to unlock it.
`Key does not match the card's capability` | Use 2048-bit RSA key sizes.
`sign_and_send_pubkey: signing failed: agent refused operation` | Verify that `ssh-agent` has been replaced with `gpg-agent`, as described in [Replace agents](#replace-agents).
`sign_and_send_pubkey: signing failed: agent refused operation` persists | Run `gpg-connect-agent updatestartuptty /bye`.
`sign_and_send_pubkey: signing failed: agent refused operation` persists after updating the startup TTY | Set a valid `pinentry` program path in `~/.gnupg/gpg-agent.conf`. A related error may be `gpg: decryption failed: No secret key`.
`sign_and_send_pubkey: signing failed: agent refused operation` with OpenSSH 8.9p1 or later | This may be a known OpenSSH issue. Review the linked [Arch Linux discussion](https://bbs.archlinux.org/viewtopic.php?id=274571).
`The agent has no identities` from `ssh-add -L` | Install and start `scdaemon`.
`Error connecting to agent: No such file or directory` from `ssh-add -L` | Ensure that the agent's UNIX socket is configured and available. Review [Replace agents](#replace-agents).
`Permission denied (publickey)` | Run SSH with verbosity, for example `ssh -v host`, and confirm that the card's public key is offered: `Offering public key: RSA SHA256:... cardno:00060123456`. Also verify the user exists on the target system (different from the user on the local system).
SSH authentication still fails | Increase SSH verbosity with up to three flags: `ssh -vvv host`.
SSH authentication still fails after reviewing verbose client output | On the server, stop the background SSH service, for example with `sudo systemctl stop sshd`, then run `/usr/sbin/sshd -eddd` in the foreground with extensive debug logging to inspect the authentication attempt. Note that the server will not fork and will only process one connection and has to be restarted after every SSH connection test.
`Please insert the card with serial number ...` | See [Using multiple YubiKeys](#using-multiple-yubikeys).
`There is no assurance this key belongs to the named user`, `encryption failed: Unusable public key`, or `No public key` | Run `gpg --edit-key` and set owner trust to `5 = I trust ultimately`.
`Need the secret key to do this` while setting trust | Specify trust for the identity with the `trust-key [key ID]` directive.
`pass insert` reports `There is no assurance this key belongs to the named user` and `encryption failed: Unusable public key` | Adjust the identity's trust level as described above.
`gpg: ... skipped: Unusable public key`, `signing failed: Unusable secret key`, or `encryption failed: Unusable public key` | The Subkey may have expired. Follow [Updating keys](#updating-keys) to renew or rotate the Subkeys.
The pinentry dialog does not appear and SSH signing fails with `agent refused operation` | Install the `dbus-user-session` package, then restart the session or system.
Unexpected PIN prompts during SSH authentication | Add `disable-application piv` to `~/.gnupg/scdaemon.conf`.
`gpg: selecting card failed: No such device` or `gpg: OpenPGP card not available: No such device` | The local `pcscd` service may lack permission to access the card. Create the Polkit rule shown below, replacing `wheel` if the system uses a different administrative group.

Create `/etc/polkit-1/rules.d/99-pcscd.rules` with the following contents:

```toml
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
```

# Alternative solutions

- [vorburger/ed25519-sk.md](https://github.com/vorburger/blog/blob/main/security/ed25519-sk.md) - use YubiKey for SSH without GnuPG
- [smlx/piv-agent](https://github.com/smlx/piv-agent) - SSH and GnuPG agent which can be used with PIV devices
- [keytotpm](https://www.gnupg.org/documentation/manuals/gnupg/OpenPGP-Key-Management.html) - use GnuPG with TPM systems

# Additional resources

- [Yubico - PGP](https://developers.yubico.com/PGP/)
- [Yubico - YubiKey Personalization](https://developers.yubico.com/yubikey-personalization/)
- [A Visual Explanation of GPG Subkeys (2022)](https://rgoulter.com/blog/posts/programming/2022-06-10-a-visual-explanation-of-gpg-subkeys.html)
- [dhess/nixos-yubikey](https://github.com/dhess/nixos-yubikey)
- [lsasolutions/makegpg](https://gitlab.com/lsasolutions/makegpg)
- [Trammell Hudson - Yubikey (2020)](https://trmm.net/Yubikey)
- [Yubikey forwarding SSH keys (2019)](https://blog.onefellow.com/post/180065697833/yubikey-forwarding-ssh-keys)
- [GPG Agent Forwarding (2018)](https://mlohr.com/gpg-agent-forwarding/)
- [Stick with security: YubiKey, SSH, GnuPG, macOS (2018)](https://evilmartians.com/chronicles/stick-with-security-yubikey-ssh-gnupg-macos)
- [PGP and SSH keys on a Yubikey NEO (2015)](https://www.esev.com/blog/post/2015-01-pgp-ssh-key-on-yubikey-neo/)
- [Offline GnuPG Master Key and Subkeys on YubiKey NEO Smartcard (2014)](https://blog.josefsson.org/2014/06/23/offline-gnupg-master-key-and-subkeys-on-yubikey-neo-smartcard/)
- [Creating the perfect GPG keypair (2013)](https://alexcabal.com/creating-the-perfect-gpg-keypair/)

[^1]: [Revocation certificates](https://security.stackexchange.com/questions/14718/does-openpgp-key-expiration-add-to-security/79386#79386) should be used to revoke an identity.
[^2]: See [issue 477](https://github.com/drduh/YubiKey-Guide/issues/477) for NIST guideline discussion.
