# Creating a Secure Environment for GPG in Alpine Linux

by Matt Borja

**Purpose.** This document describes a process for creating a secure environment using Alpine Linux: a lightweight and secure distribution of Linux capable of supporting newer versions of GPG with smart card support on very modest hardware such as the ARM-based Raspberry Pi 1 Model B (32-bit). This document also demonstrates the highly portable characteristics of Alpine Package Keeper (APK) to provide for ease of package installation and use in air-gapped environments.

**Tags.** Tails OS, Alpine Linux, GnuPG, Raspberry Pi.

**Disclaimer.** The procedures outlined in this document are provided as best effort measures for creating a safer working environment for managing GPG keys; and are not intended to eliminate every possible threat scenario including, but not limited to those arising from the presence of: advanced persistent threats, viruses, infected firmware, or other similarly compromised peripherals or protocols used by these procedures. Caution must still be exercised when considering the use, proximity, and direct connection of any “active” or unshielded electronic device.

## Stage 1: Establishing a Secure Imaging Host

Preparing a secure environment for GPG normally involves the initial use of a host system (e.g., Windows, Mac OS) to create a bootable disk. While this might be satisfactory to many, it is worth considering the risk of contamination through daily use. Think of it as grabbing a clean plate before putting food on it!

Therefore, to mitigate the potential of host contamination, we will establish an *intermediary environment* (abstraction) prior to creating the actual secure working environment. We will also consider a tightly coupled process for verifying the target image before writing it to disk.
 
### 1.1. Use Tails OS as an Intermediary (Recommended)
[Tails OS](https://tails.net/install/expert/index.en.html) provides for a convenient, isolated ephemeral environment, placing special emphasis on proper verification of its USB images before use. Consider booting into a system like this before starting in on these procedures.

### 1.2. Use the target OS to download packages

#### 1.2.1. Acquire the target image
Let's assume you've gone through the steps of downloading, verifying, and booting into **Tails**. You'll now need to import a copy of the target OS image ([Alpine Linux](https://alpinelinux.org/downloads/)) by either:
- Connecting Tails to the Internet and using its Tor Browser to download the image
- Leaving Tails disconnected from the Internet and instead using another device (e.g., smartphone) to bring over the downloaded image using a removable storage device

**Important.** You must verify this image using its GPG signature and corresponding signing key just as you should have done to verify Tails prior to using as an intermediary. These steps may seem repetitive, but are critical to building a clean path into a highly secure environment.

#### 1.2.2. Boot the target image and download OS packages
In the same way you installed Tails onto a USB stick using the `dd` command, you will want to do this *within Tails* for the Alpine Linux image you've just acquired. Clearly, this will require its own separate USB stick, but what you've now accomplished will be an Alpine Linux image written to a USB stick from the intermediary environment as a preferred alternative to a contaminated host environment.

Next, you will want to boot into the Alpine Linux system you've just created, login as `root`, and connect to the Internet to download the required packages for this specific platform:

```shell
# 1. Set date
root@host:~$ date -s 'YYYY-MM-DD hh:mm:ss'

# 2. Connect to Internet
# See https://wiki.alpinelinux.org/wiki/Configure_Networking

# 3. Download packages for offline installation
root@host:~$ apk update
root@host:~$ apk upgrade
root@host:~$ apk fetch --recursive gpg gnupg-scdaemon pcsc-lite

# NOTE: Internet is no longer required beyond this point

# 4. Review downloaded packages
root@host:~$ ls -lha *.apk

# 5. Bundle packages for offline use
root@host:~$ tar -czvf gpg-bundle.tar.gz *.apk

# 6. Optional. Take SHA256 checksum
root@host:~$ sha256sum gpg-bundle.tar.gz > gpg-bundle.tar.gz.sha256

# 6. Mount removable storage and copy over (replace /dev/sda1 with your actual device file handle)
root@host:~$ mount -t exfat /dev/sda1 /mnt
root@host:~$ cp gpg-bundle.* /mnt/
root@host:~$ umount /mnt
```

**Important.** With offline packages in hand, you may consider repeating the prior section (*1.2.1. Acquiring the target image*) to provide yourself with another "clean plate" (one that's never been connected to the Internet) before continuing.

**CI/CD Considerations.** It is curate a clean, custom bootable image of Alpine Linux with these same offline packages using a CI/CD pipeline if carefully designed to also demonstrate software provenance and image signing before release.

## Stage 2. Secure Environment

At this point, the newly provisioned secure environment should be booted, free of any extraneous peripheral attachments, with networking completely disabled.

Post-installation packages should be readily available (e.g., written to its boot partition for the preceding in intermediate environment) and cryptographically re-verified cryptographically before continuing with offline installation.

Additional setup requirements within the secure environment may include:

- Manually setting the system date
- Setting the keyboard language and layout
- Configuring the local GPG system
- Adding entropy sources
- Importing keys

### 2.1 Installing Offline Packages
After booting into the secure environment, the user proceeds to verify the SHA256 checksums of the previously GPG-verified APK packages stored in the boot partition. Once verified, the user issues the following command within the package subdirectory to install them:

```shell
$ apk --allow-untrusted --force-non-repository add *.apk
```

### 2.2 GPG Environment
The user can now begin [working with GPG](https://github.com/drduh/YubiKey-Guide?tab=readme-ov-file#prepare-gnupg) and smart cards in their new environment:

```shell
$ gpg --import yubikey.pub
$ gpg --card-status
$ gpg --list-secret-keys
```

## Stage 3. Takedown

When finished performing tasks, the secure environment should either be a) promptly destroyed or b) properly secured away; to close the window on unknown threats to a dormant system (e.g., physical, technological, theoretical, unknown).