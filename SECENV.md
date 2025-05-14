# Creating a Secure Environment for GPG in Alpine Linux

by Matt Borja

**Purpose.** This document describes a process for creating a secure environment using Alpine Linux: a lightweight and secure distribution of Linux capable of supporting newer versions of GPG with smart card support on even *older versions* of architecturally diverse platforms such as the ARM-based Raspberry Pi 1 Model B (32-bit). This document  also demonstrates the highly portable characteristics of the Alpine Package Keeper (APK) to provide for ease of installation and use in air-gapped environments.

**Tags.** Tails OS, Alpine Linux, GnuPG, Raspberry Pi.

**Disclaimer.** The procedures outlined in this document are provided as best effort measures for creating a safer working environment for managing GPG keys; and are not intended to eliminate every possible threat scenario including, but not limited to those arising from the presence of: advanced persistent threats, viruses, infected firmware, or other similarly compromised peripherals or protocols used by these procedures. Caution must still be exercised when considering the use, proximity, and direct connection of any “active” or unshielded electronic device.

## Stage 1: Establishing a Secure Imaging Host

Preparing a secure environment for GPG normally involves the initial use of a host system (e.g., Windows, Mac OS) to create a bootable image (e.g. Raspbian, Alpine Linux). While potentially sufficient for sensitive tasks as-is, this scenario could also be easily presumed contaminated by unknown threats in original imaging host environment, especially if the host is used regularly for day-to-day tasks, etc.

Therefore, to mitigate the potential of host contamination, an *intermediary imaging environment* should first be established, isolated, hardened and *booted* as the current working environment (abstraction) prior to creating and the actual final, secure working environment. This process of creating and booting into an abstracted working environment may optionally be repeated (and also varied) as often as deemed necessary to evade any threats, potential or realized, in the preceding environment.

**Note.** It will be necessary for this first working environment to either be: a) Internet-connected, or b) connected to a USB storage medium containing images for the final environment; for the purpose building and deploying the final secure image.

### 1.1 Obtaining Alpine Linux
**Smartphone Device Example.** The user connects a USB storage medium to their fully updated iPhone (cannot be jail broken) using an Apple-certified USB camera adapter. The iPhone in this scenario can serve as an initial intermediary environment reserved solely for the purpose of downloading an [official Alpine Linux ISO image](https://alpinelinux.org/downloads/) for the Raspberry Pi along with its corresponding signatures and public keys to the connected USB storage medium via the Files app.

Note: This same acquisition method can be applied to any desired OS supported by the target device.

**Post-Environment Example.** The user creates an intermediary environment using the [Raspberry Pi Imager](https://www.raspberrypi.com/software/) and boots the 32-bit Alpine Linux image on their Raspberry Pi 1 Model B with networking enabled.

Note: While this is the same OS that will ultimately be used for GPG, we are merely borrowing it as a "post-environment" at this stage in the process, solely for the purpose of prefetching an offline copy of the selfsame OS-specific APK packages that will be required for GPG (and smart card use) later on.

### 1.2 Downloading APK packages for offline use
While still booted in the "post-environment," you can run the following commands to update APK and download the relevant packages:
```shell
$ apk update && apk upgrade && apk fetch --recursive gpg gnupg-scdaemon pcsc-lite
```

**Tip.** The `--recursive` option is key to ensuring all dependencies are also downloaded.

After running the above command, the downloaded packages will be found downloaded locally in the current working directory and should then be transferred to a USB storage medium.

**CI/CD Considerations.** It is possible to bypass this entire user story if a CI/CD pipeline were to be carefully designed to demonstrate software provenance in the curation and signing of a custom Alpine Linux image with these requirements.

### 1.3 Building the Secure Environment
Once an intermediary environment has been finalized and selected to become the new imaging host environment, the user may begin to build out their final working environment, including but not limited to the base OS, and any post-installation scripts, packages, tools, etc. needed for work.

**Example.** The user elects to use Tails OS as the last intermediate environment (the new imaging host environment) following a series of abstracted pre-environments. During its creation (prior to booting), an encrypted persistent storage is configured (e.g., LUKS) and used to store an offline, verified copy of Alpine Linux (32-bit) for their Raspberry Pi, along with all prefetched APK packages required for use in the final working environment. With permanent storage detached and networking completely disabled, the user proceeds to boot into Tails OS with Persistent Storage unlocked. Once booted, they use the disk utility program (Disks) to to "Restore Disk Image" to an SD card using the Alpine Linux image residing in Persistent Storage. Once imaged, the use proceeds to mount its writable 80 MB boot partition to copy relevant prefetched APK packages into a subfolder for post-installation. The SD card should now have everything needed to boot a securely created environment without the need to be connected to the Internet or other extraneous storage medium or peripherals.

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
After booting into the secure environment, the user proceeds to verify the SHA256 checksums of the previously GPG-verified APK packages stored in the boot partition. Once verified, the user issues they following command within the package subdirectory to install them:

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