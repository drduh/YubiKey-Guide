#!/usr/bin/env python3

import os
import sys
import argparse
from subprocess import Popen, PIPE, getoutput
from apt.cache import Cache
from getpass import getpass
from gpg import Context
from pycurl import Curl
import certifi

_PACKAGES_LIST = {
    "wget": False,
    "gnupg2": False,
    "gnupg-agent": False,
    "dirmngr": False,
    "cryptsetup": False,
    "scdaemon": False,
    "pcscd": False,
    "secure-delete": False,
    "hopenpgp-tools": False,
    "yubikey-personalization": False
}
_SERVICES_TO_SHUTDOWN = {
    "network-manager",
    "NetworkManager",
    "avahi-daemon"
}


# ===== START OF CORE FUNCTIONS =====
def out_success(text):
    print("[+] " + text)


def out_error(text):
    print("[!] ERROR: " + text)


def out_info(text):
    print("[i] " + text)


def out_question_yes_no(text):
    print(text)
    resp = input("Please choose (Y/y/N/n): ")
    if resp.lower() == "y":
        return 1
    else:
        return 0


def out_question_arbitrary(text):
    return input(text)


# ===== END OF CORE FUNCTIONS =====

# ===== START OF FUNCTIONS =====
def verify_yk():
    return out_question_yes_no("Did you verify your YubiKey?")


def verify_live():
    live = os.system(_CMD_WHOAMI + " | grep \"user\"")  # Rewrite that. Detect live system not username
    # Maybe detect the device root is mounted on? /dev/sdx
    if live is 0:
        return True
    return False


def kill_network():
    cmdchain = ""
    for service in _SERVICES_TO_SHUTDOWN:
        cmdchain += "sudo "+_SUDO_ARGS+_CMD_SERVICE+" "+service+" stop;"
    for interface in os.listdir("/sys/class/net"):
        if not interface == "lo":
            cmdchain +=  "sudo "+_SUDO_ARGS+_CMD_IFCONFIG+" "+interface+" down;"

    proc = Popen(cmdchain, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE, text=True)
    if not _USE_ASKPASS: passwd = getpass(); proc.communicate(passwd + "\n")
    proc.wait()


def check_dependencies():
    cache = Cache()
    ret = True
    for package in _PACKAGES_LIST:
        if cache[package].is_installed:
            _PACKAGES_LIST[package] = True
        else:
            ret = False
    return ret


def install_dependencies():
    cache = Cache()
    if _SUDO_V19:
        pass
        # Do sudo v1.9 stuff here
        #cache.update()
        #cache.open()
        # for package in packages_list:
        #     if packages_list[package] is False:
        #         cache[package].mark_install()
        # cache.commit()
        # Remember to drop sudo privs here
    else:
        missing_packages = ""

        for package in _PACKAGES_LIST:
            if _PACKAGES_LIST[package] is False:
                missing_packages += package+" "

        proc = Popen(
            "sudo "+_SUDO_ARGS+"apt update;"
            "sudo "+_SUDO_ARGS+"apt install -y "+missing_packages,
            shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE, text=True)
        if not _USE_ASKPASS: passwd = getpass(); proc.communicate(passwd+"\n")
        proc.wait()
        passwd = None


def download_conf():
    with open(_WORKDIR+"/gpg.conf", 'wb') as f:
        c = Curl()
        c.setopt(c.URL, "https://raw.githubusercontent.com/drduh/config/master/gpg.conf")
        c.setopt(c.WRITEDATA, f)
        c.setopt(c.CAINFO, certifi.where())
        c.perform()
        c.close()
    out_success("Configuration downloaded!")


# ===== START KEY GENERATION =====
def keygen():
    c = Context(True, home_dir=_WORKDIR)

    uid = out_question_arbitrary("Your name: ")+" <"+out_question_arbitrary("Your E-Mail: ")+">"
    passwd = getoutput("gpg --gen-random --armor 0 24")
    print("This is your passphrase. Write it down somewhere safe!\n"+passwd)

    # Create master key
    masterkey = c.create_key(uid, "rsa4096", expires=False, certify=True, passphrase=passwd)
    master_fpr = masterkey.fpr
    seckey = c.get_key(master_fpr, True)

    # create subkeys
    sign_key = c.create_subkey(seckey, "rsa4096", 31536000, sign=True)
    encrypt_key = c.create_subkey(seckey, "rsa4096", 31536000, encrypt=True)
    auth_key = c.create_subkey(seckey, "rsa4096", 31536000, authenticate=True)

    # Export master key
    with open(_WORKDIR+"/master.sec.asc", "wb") as f:
        f.write(c.key_export_secret(master_fpr))
        f.flush()
        f.close()

    with open(_WORKDIR+"/sub.sec.asc", "wb") as f:
        f.write(c.key_export_secret(sign_key.fpr))
        f.write(c.key_export_secret(encrypt_key.fpr))
        f.write(c.key_export_secret(auth_key.fpr))
        f.flush()
        f.close()

    out_success("Keys generated!")


# ===== END KEY GENERATION =====

# ===== END OF FUNCTIONS =====

# ===== START OF MAIN =====
parser = argparse.ArgumentParser(
    description="This script tries to accomplish what @drdruh describes in the README\n"
                "WARNING: This script only works on Debian and Ubuntu"
)
parser.add_argument("--verified-yk",
                    action="store_true",
                    help="Skip the YubiKey verification check (!DANGEROUS! If your YK is compromised your keys are too!)")
parser.add_argument("--skip-live",
                    action="store_true",
                    help="Skip the live system check (!DANGEROUS! Data could be saved on your hard disk)")
parser.add_argument("-d1", "--sec-backup-device",
                    nargs=1,
                    type=str,
                    help="Device to send the secret keys backup to")
parser.add_argument("-d2", "--public-backup-device",
                    nargs=1,
                    type=str,
                    help="Device to send the public key backup to")
parser.add_argument("--create-backup-usb",
                    nargs=1,
                    type=str,
                    help="Path to device to create a encrypted backup")
parser.add_argument("--no-hardened",
                    action="store_false",
                    help="Don't use the hardened configuration (WARNING: you could generate weak keys!)")

args = parser.parse_args()


# ===== CONSTANTS =====
_YK_VERIFIED = args.verified_yk
_LIVE_VERIFIED = args.skip_live
_USE_HARDENED_CONF = args.no_hardened
_SUDO_V19 = False
_SUDO_ARGS = "-S"
_USE_ASKPASS = False

_CMD_SERVICE = getoutput("which service")
_CMD_IFCONFIG = getoutput("which ifconfig")
_CMD_WHOAMI = getoutput("which whoami")

_BACKUP_SEC_DEVICE = args.sec_backup_device
_BACKUP_PUB_DEVICE = args.public_backup_device
_BACKUP_DEVICE = args.create_backup_usb

_WORKDIR = getoutput("mktemp -d")
print(_WORKDIR)


# ===== CONSTANTS =====

# ===== PRE-CHECKS =====
try:
    import sudo
    _SUDO_V19 = True # Not used yet tho. Don't know the sudo plugin API.
except ModuleNotFoundError:
    pass

if os.environ.get("SUDO_ASKPASS") is not None:
    _USE_ASKPASS = True

_SUDO_ARGS += ("A " if _USE_ASKPASS else " ")

if _BACKUP_SEC_DEVICE is not None and _BACKUP_PUB_DEVICE is not None:
    if _BACKUP_DEVICE is not None:
        out_error("Please use either \"--sec-backup-device\" with \"--public-backup-device\" or \"--create-backup-usb\"")
        exit(1)
else:
    if _BACKUP_DEVICE is None:
        out_error("Please use either \"--sec-backup-device\" with \"--public-backup-device\" or \"--create-backup-usb\"")
        exit(1)


# ===== END PRE-CHECKS =====

if not _YK_VERIFIED and verify_yk() is not 1:
    os.system("/bin/bash -c \"x-www-browser 'https://www.yubico.com/genuine/'\"")
    out_error("Please verify before proceeding!")
    exit(1)

if _LIVE_VERIFIED or verify_live():
    out_success("Great! You seem to be on a live system!")
else:
    out_error("You are not on a live system! Please boot into one or pass the \"--skip-live\" flag!")
    exit(1)

if check_dependencies():
    out_success("Great! All packages are installed!")
else:
    if out_question_yes_no("Some packages are missing. Would you like me to install them?"):
        out_info("Installing packages...")
        install_dependencies()
        out_success("Everything set up!")
    else:
        out_error("Sorry can't run without them.")
        exit(1)

if _USE_HARDENED_CONF:
    download_conf()

out_info("Shutting down all interfaces...")
kill_network()
out_success("Seems like we are ready to go. YAY! Let's generate keys!")

# TODO:Setup backup device here
keygen()


# ===== END MAIN =====