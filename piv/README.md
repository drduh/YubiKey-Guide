# Root Certificate

## Prepare root configuration

Create a temporary directory:

```bash
cd $(mktemp -d)
```

Create `root.cnf`:

```conf
[ req ]
x509_extensions        = v3_ca

[ v3_ca ]
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash

[ ca ]
default_ca             = yk_piv_ca

[ yk_piv_ca ]
default_md             = sha512
dir                    = ./yk_piv_ca
database               = $dir/index
new_certs_dir          = $dir/certs
serial                 = $dir/serial
policy                 = policy_piv_ca

[ policy_piv_ca ]
commonName             = supplied
```

Set OpenSSL path:

```bash
export OPENSSL=/opt/homebrew/bin/openssl
```

Prepare root materials:

```bash
mkdir -p yk_piv_ca/certs
touch yk_piv_ca/index
$OPENSSL rand -hex 16 > yk_piv_ca/serial
```

## Generate root key

Select from one of the following key types:

```bash
$OPENSSL ecparam -genkey -name secp384r1 -out root.key
$OPENSSL genpkey -algorithm ed25519 -out root.key
$OPENSSL genrsa -out root.key
```

## Issue root certificate request

Set root common name:

```bash
export CA_NAME="/CN=yk.$(LC_ALL=C tr -dc 'a-z0-9' < /dev/urandom | head -c 16)"
```

Generate CSR:

```bash
$OPENSSL req -new \
  -config root.cnf \
  -subj "$CA_NAME" \
  -key root.key \
  -out root.csr
```

## Sign root certificate

```bash
$OPENSSL ca -selfsign -batch \
  -config root.cnf \
  -extensions "v3_ca" \
  -startdate "$(date -u -v0H -v0M -v0S '+%Y%m%d%H%M%SZ')" \
  -enddate "20500101000000Z" \
  -keyfile root.key \
  -in root.csr \
  -out root.pem
```

## Verify root certificate

```bash
$OPENSSL x509 -text -noout -in root.pem
```

# YubiKey Transfer

## Reset

```bash
ykman piv info
ykman piv reset
```

## Load

```bash
ykman piv keys import 9c root.key
ykman piv certificates import 9c root.pem
```

# Server Certificates

## Prepare server configuration

Edit `server.cnf`:

```conf
openssl_conf         = openssl_init

[ openssl_init ]
engines              = engine_section

[ engine_section ]
pkcs11               = pkcs11_section

[ pkcs11_section ]
dynamic_path         = /opt/homebrew/lib/engines-3/libpkcs11.dylib
MODULE_PATH          = /opt/homebrew/lib/opensc-pkcs11.so
init                 = 1
engine_id            = pkcs11

[ ca ]
default_ca           = yk_piv_server

[ yk_piv_server ]
certificate          = root.pem
default_days         = 100
default_md           = sha512
dir                  = ./yk_piv_server
database             = $dir/index
new_certs_dir        = $dir/certs
serial               = $dir/serial
private_key          = pkcs11:object=%02;type=private
policy               = policy_piv_server

[ policy_piv_server ]
commonName           = supplied

[ yk_piv_server_cert ]
basicConstraints     = CA:FALSE
extendedKeyUsage     = serverAuth
keyUsage             = digitalSignature, keyEncipherment
nsCertType           = server
subjectKeyIdentifier = hash
subjectAltName       = @alt_names

[ alt_names ]
DNS.1                = example.local
```

```bash
export OPENSSL=/opt/homebrew/bin/openssl
```

```bash
mkdir -p yk_piv_server/certs
touch yk_piv_server/index
$OPENSSL rand -hex 16 > yk_piv_server/serial
```

## Generate server key

Select from one of the following key types:

```bash
$OPENSSL ecparam -genkey -name secp384r1 -out server.key
$OPENSSL genpkey -algorithm ed25519 -out server.key
$OPENSSL genrsa -out server.key
```

## Issue server certificate request

```bash
export SERVER_NAME="/CN=example.local"
```

```bash
$OPENSSL req -new \
  -config server.cnf \
  -subj "$SERVER_NAME" \
  -key server.key \
  -out server.csr
```

## Get root certificate

```bash
ykman piv certificates export 9c - > root.pem
```

## Sign server certificate

```bash
OPENSSL_CONF=server.cnf $OPENSSL ca \
  -batch \
  -engine pkcs11 \
  -keyform engine \
  -keyfile "pkcs11:id=%02;type=private" \
  -extensions yk_piv_server_cert \
  -days 100 \
  -in server.csr \
  -out cert.pem
```

## Verify server certificate

```bash
$OPENSSL x509 -text -noout -in cert.pem
```
