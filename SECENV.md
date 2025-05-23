# Creating a Secure Environment for GPG in Alpine Linux

Copyright (c) 2025 Matt Borja

## Abstract
This document describes a process for creating a secure environment for GPG key management using Alpine Linux: a lightweight and secure Linux distribution capable of supporting newer versions of GPG with smart card support on very modest hardware such as the ARM-based Raspberry Pi 1 Model B (32-bit). This document also considers the highly portable nature of Alpine Package Keeper (APK) for ease of dependency installation in air-gapped environments and a tightly coupled process to further assert package integrity as an installation prerequisite within the air-gapped environment.

**Tags.** Tails OS, Alpine Linux, GnuPG, Raspberry Pi.

## Disclaimer
The procedures outlined in this document are provided as best effort measures for creating a safer working environment for managing GPG keys; and are not intended to eliminate every possible threat scenario including, but not limited to those arising from the presence of: advanced persistent threats, viruses, infected firmware, or other similarly compromised peripherals or protocols used by these procedures. Caution must still be exercised when considering the use, proximity, and direct connection of any “active” or unshielded electronic device.

Furthermore:

THIS DOCUMENTATION IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THIS DOCUMENTATION OR THE USE OR OTHER DEALINGS IN THIS DOCUMENTATION.

## 1. Prepare a Secure Imaging Host

Preparing a secure environment for GPG normally involves the initial use of an external host system (e.g., Windows, Mac OS, etc.) to create its bootable disk. While this might be satisfactory to many, it is worth considering the risk of host contamination through daily use. Therefore we will consider an *intermediary environment* from which we will then create the bootable disk. One might think of this seemingly superfluous step as merely grabbing a clean plate before putting food on it to eat!
 
### 1.1. Use Tails OS as an Intermediary (Recommended)
[Tails OS](https://tails.net/install/expert/index.en.html) provides for a convenient, isolated ephemeral environment, placing special emphasis on proper verification of its USB images before use. Consider booting into a system like this before starting in on these procedures.

As mentioned before, this environment alone may arguably be considered satisfactory for GPG purposes, but it is out of an abundance of caution we are limiting our use of it for verification and imaging purposes only.

### 1.2. Use the target OS to download packages and gpg.conf
The goal of this section is to have all the necessary assets in hand to avert the need for an Internet connection post-installation towards the end of this guide.

#### 1.2.1. Acquire the target image
If you haven't already, follow the [Tails installation guide](https://tails.net/install/expert/index.en.html) *carefully* to ensure you have [verified](https://tails.net/install/expert/index.en.html#verify-key) and booted into a valid Tails environment before continuing.

Next, import a copy of [Alpine Linux](https://alpinelinux.org/downloads/) by either:
- Connecting Tails to the Internet and using the Tor Browser to download the image
- Leaving Tails disconnected from the Internet and instead using another device (e.g., smartphone) to bring over the downloaded image using a removable storage device

**Note.** If you have designated an older Raspberry Pi as your preferred air-gapped device, you will need to provide a SD card for imaging and likely use the ARMhf (hard float) images from their [downloads page](https://www.alpinelinux.org/downloads/).

**Important.** In the same way you should have done for Tails, you must verify the Alpine Linux image using its corresponding GPG signature against its signing key before continuing. Always check [official sources](https://docs.alpinelinux.org/user-handbook/0.1a/Installing/medium.html#_optional_verifying_the_downloaded_files_pgp) and consider additional evidence sources ([example](https://sig3.dev)) for validity completness. These steps may seem repetitive and strenuous, but are critical to building a verifiable path into a highly secure environment.

Once you've verified the image download, you can use the **Restore Disk Image...** in the *Disks* utility from within Tails to write the image to a target disk (e.g., SD card for a Raspberry Pi).

#### 1.2.2. Download a copy of gpg.conf (hardened)

While still connected to the Internet, consider downloading a copy of a hardened version of gpg.conf ([example](https://github.com/drduh/YubiKey-Guide/blob/master/config/gpg.conf)) to add to your `$GNUPGHOME` on initial boot into the secure environment.

#### 1.2.3. Boot the target image to download OS-specific packages for GnuPG

Boot into the Alpine Linux system, login as `root`, and connect to the Internet to download the required packages for this specific platform:

```shell
# 1. Set date
root@host:~$ date -s 'YYYY-MM-DD hh:mm:ss'

# 2. Connect to Internet (https://wiki.alpinelinux.org/wiki/Configure_Networking)

# 3a. Download packages for offline installation
root@host:~$ apk update
root@host:~$ apk upgrade
root@host:~$ apk fetch --recursive gpg gnupg-scdaemon pcsc-lite

# 3b. Use the same apk fetch --recursive command to download any additional packages you require for additional work in the air-gapped enviroment.

# Note. Internet is no longer required beyond this point.

# 4. Review downloaded packages
root@host:~$ ls -lha *.apk

# 5. Bundle for offline use and take SHA256 checksum
root@host:~$ tar -czvf airgap-bundle.tar.gz *.apk
root@host:~$ sha256sum airgap-bundle.tar.gz > airgap-bundle.tar.gz.sha256

# 6. Visually inspect and note SHA256 checksum for verification
root@root:~$ cat airgap-bundle.tar.gz.sha256

# 6. Mount removable storage and transfer (replace $SD_PARTITION_DEV with your actual device file handle, as in /dev/sda1, etc.)
root@host:~$ mount -t exfat "${SD_PARTITION_DEV}" /mnt
root@host:~$ cp airgap-bundle.* /mnt/
root@host:~$ umount /mnt
```

**Note.** With offline packages now in hand, you might consider repeating the prior section (*1.2.1. Acquiring the target image*) to provide yourself with another "clean plate" (one that's never been connected to the Internet) before continuing. Pragmatically speaking, you can also just "wash the plate" by re-imaging Alpine Linux over the selfsame SD card used in this step to download packages.

## 2. Boot the Secure Environment

The newly provisioned Alpine Linux environment should now be booted, free of any extraneous peripheral attachments, with networking completely disabled.

Additional setup tasks may include:

- Manually setting the system date (`date -s "$CURRENT_UTC_TIMESTAMP"`)
- Setting the keyboard language and layout

### 2.1 Install Offline Packages for GnuPG
After booting into the secure environment, the user proceeds to verify the SHA256 checksums of the previously GPG-verified APK packages download to removable storage:

```shell
root@host:~$ mkdir work && cd work
root@host:~/work$ mount -t exfat "${SD_PARTITION_DEV}" /mnt
root@host:~/work$ cp /mnt/airgap-bundle.* .
root@host:~/work$ umount /mnt
```

The following command provides strict coupling (`&&`) between the cryptographic verification of the bundle created earlier, and its subsequent extraction. If the checksum is invalid, the tarball will not be extracted and the `apk` command that follows is expected to fail.
```shell
# Require sha256sum to pass before extracting and installing with `apk`
root@host:~/work$ sha256sum -c airgap-bundle.tar.gz.sha256 \
                  && tar -xzvf airgap-bundle-tar-gz \
                  && apk --allow-untrusted --force-non-repository add *.apk
```

**Don't forget!** If you obtained a copy of [gpg.conf](https://github.com/drduh/YubiKey-Guide/blob/master/config/gpg.conf), be sure to import it into your `$GNUPGHOME` before continuing.

**CI/CD Considerations.** For DevOps teams, this concludes the essential requirements for provisioning an Alpine Linux image with an offline copy of packages for GPG key management. In the interest of transparency, be sure to include any relevant steps and artifacts in your software provenance and image signing before releasing.

### 2.2 Verify the Environment
Assuming package installation is successfully, begin verifying the environment for GPG use:

**Note.** If you have a YubiKey, go ahead and insert it now.

```shell
# Verify GPG installation
root@host:~$ gpg --version

# Verify smartcard connection
root@host:~$ gpg --card-status

# Import corresponding public key to view all details
root@host:~$ gpg --import yubikey.pub
root@host:~$ gpg --list-sigs "$YUBIKEY_FINGERPRINT"
root@host:~$ gpg --list-secret-keys "$YUBIKEY_FINGERPRINT"
```

**Note.** If you run into issues detecting your YubiKey switching between `$GNUPGHOME` directories (common during heavy key management operations such as ring transfers, etc.), try restarting the `gpg-agent` as follows:

```shell
root@host:~$ pkill gpg-agent
root@host:~$ gpg --card-status
```

**All done!** You can now begin [working with GPG](https://github.com/drduh/YubiKey-Guide?tab=readme-ov-file#identity) and smart cards in your new air-gapped environment!

## Stage 3. Takedown
When finished performing key management tasks, the secure environment should either be a) promptly destroyed or b) properly secured away; to close the window on unknown threats to a dormant system (e.g., physical, technological, theoretical, unknown).