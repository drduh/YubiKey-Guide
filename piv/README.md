# Required software

## macOS

```bash
brew install openssl libp11 opensc
```

# Configure names

Set root name:

```bash
export NAME_ROOT="/CN=yk.root.$(LC_ALL=C tr -dc 'a-z0-9' < /dev/urandom | head -c 16)"
```

Set intermediate name:

```bash
export NAME_IA="/CN=yk.intermediate.$(LC_ALL=C tr -dc 'a-z0-9' < /dev/urandom | head -c 16)"
```

Set server name:

```bash
export NAME_SERVER="/CN=example.local"
```

Print names:

```bash
printf '\nRoot Name:\t\t%s'       "$NAME_ROOT"
printf '\nIntermediate Name:\t%s' "$NAME_IA"
printf '\nServer Name:\t\t%s\n\n' "$NAME_SERVER"
```

# Root Certificate

## Prepare root configuration

Create a temporary directory:

```bash
cd $(mktemp -d)
```

Copy [`yk.cnf`](./yk.cnf):

```bash
cp ~/git/YubiKey-Guide/piv/yk.cnf .
```

Set path to compatible OpenSSL:

```bash
export OPENSSL=/opt/homebrew/bin/openssl
```

Prepare root materials:

```bash
mkdir -p certs
touch index
$OPENSSL rand -hex 16 > serial
```

## Generate root key

Select from one of the following key types:

```bash
$OPENSSL ecparam -genkey -name secp384r1 -out root.key
$OPENSSL genpkey -algorithm ed25519 -out root.key
$OPENSSL genrsa -out root.key
```

## Issue root certificate request

```bash
$OPENSSL req -new \
  -config yk.cnf \
  -subj "$NAME_ROOT" \
  -key root.key \
  -out root.csr
```

## Sign root certificate

```bash
local DATE_START="$(date -u -v0H -v0M -v0S '+%Y%m%d%H%M%SZ')"
local DATE_END="20500101000000Z"
$OPENSSL ca -selfsign -batch \
  -config yk.cnf \
  -extensions config_root \
  -startdate "$DATE_START" \
  -enddate "$DATE_END" \
  -keyfile root.key \
  -in root.csr \
  -out root.pem
```

## Verify root certificate

```bash
$OPENSSL x509 -noout -text -in root.pem
```

## Save materials offline

TODO: Copy certificate authority files to encrypted storage

# Intermediate certificate

## Generate intermediate key

Select from one of the following key types:

```bash
$OPENSSL ecparam -genkey -name secp384r1 -out intermediate.key
$OPENSSL genpkey -algorithm ed25519 -out intermediate.key
$OPENSSL genrsa -out intermediate.key
```

## Issue intermediate certificate request

```bash
$OPENSSL req -new \
  -config yk.cnf \
  -subj "$NAME_IA" \
  -key intermediate.key \
  -out intermediate.csr
```

## Sign intermediate certificate

Sign the intermediate certificate for two years (730 days):

```bash
$OPENSSL ca \
  -batch \
  -config yk.cnf \
  -extensions config_intermediate \
  -days "${IA_DAYS:-730}" \
  -keyfile root.key \
  -cert root.pem \
  -in intermediate.csr \
  -out intermediate.pem
```

## Verify intermediate certificate

```bash
$OPENSSL x509 -text -noout -in intermediate.pem
$OPENSSL verify -CAfile root.pem intermediate.pem
```

## YubiKey Transfer

## Reset

```bash
ykman piv info
ykman piv reset
```

## Load

YubiKey PIV slots:

```console
9a is for PIV Authentication
9c is for Digital Signature (PIN always checked)
9d is for Key Management
9e is for Card Authentication (PIN never checked)
```

Load slot `9c`:

```bash
ykman piv keys import 9c intermediate.key
ykman piv certificates import 9c intermediate.pem
```

# Server Certificates

## Generate server key

Select from one of the following key types:

```bash
$OPENSSL ecparam -genkey -name secp384r1 -out server.key
$OPENSSL genpkey -algorithm ed25519 -out server.key
$OPENSSL genrsa -out server.key
```

## Issue server certificate request

```bash
$OPENSSL req -new \
  -config yk.cnf \
  -subj "$NAME_SERVER" \
  -key server.key \
  -out server.csr
```

## Get intermediate certificate

```bash
ykman piv certificates export 9c - > intermediate.pem
```

## Sign server certificate

Sign a server certificate for 99 days using YubiKey:

```bash
$OPENSSL ca \
  -batch \
  -config yk.cnf \
  -extensions config_server \
  -days "${SERVER_DAYS:-99}" \
  -cert intermediate.pem \
  -keyfile 'pkcs11:id=%02;object=SIGN%20key;type=private' \
  -in server.csr \
  -out server.pem
```

## Verify server certificate

```bash
$OPENSSL x509 -text -noout -in server.pem
$OPENSSL verify \
  -CAfile root.pem \
  -untrusted intermediate.pem \
  server.pem
```

# Troubleshooting

Get help with CA application:

```bash
man openssl-ca
$OPENSSL ca -help
```

Examine card contents:

```bash
pkcs11-tool \
  --module /opt/homebrew/lib/opensc-pkcs11.so \
  --list-slots

pkcs11-tool \
  --module /opt/homebrew/lib/opensc-pkcs11.so \
  --login \
  --list-objects

pkcs11-tool \
  --module /opt/homebrew/lib/opensc-pkcs11.so \
  --login \
  --list-objects \
  --type privkey

pkcs11-tool \
  --module /opt/homebrew/lib/opensc-pkcs11.so \
  --login \
  --list-objects \
  --type privkey \
  --id 02
```
