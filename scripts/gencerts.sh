#!/usr/bin/env bash
set -euo pipefail
umask 077

cd "$(dirname "$0")/.."

if [ -e certs ]; then
    echo "ERROR: certs directory already exists"
    exit 1
fi

mkdir -m 700 certs
cd certs

echo "=== Generating Root CA ==="

openssl genrsa -out ca.key 4096

openssl req -new -x509 \
    -key ca.key \
    -sha256 -days 3650 \
    -subj "/CN=Lab6 Root CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out ca.crt

echo "=== Generating server certificate ==="

openssl genrsa -out server.key 2048

openssl req -new \
    -key server.key \
    -subj "/CN=localhost" \
    -out server.csr

cat > server.ext <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXT

openssl x509 -req \
    -in server.csr \
    -CA ca.crt -CAkey ca.key \
    -CAcreateserial \
    -out server.crt \
    -days 365 -sha256 \
    -extfile server.ext

echo "=== Generating client certificate ==="

openssl genrsa -out client.key 2048

openssl req -new \
    -key client.key \
    -subj "/CN=lab6-client" \
    -out client.csr

cat > client.ext <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXT

openssl x509 -req \
    -in client.csr \
    -CA ca.crt -CAkey ca.key \
    -CAserial ca.srl \
    -out client.crt \
    -days 365 -sha256 \
    -extfile client.ext

chmod 600 ./*.key

echo "=== Verifying certificates ==="

openssl verify -x509_strict \
    -CAfile ca.crt \
    -purpose sslserver \
    -verify_hostname localhost server.crt

openssl verify -x509_strict \
    -CAfile ca.crt \
    -purpose sslclient client.crt

echo "Certificates generated successfully"
