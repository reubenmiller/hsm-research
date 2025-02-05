#!/bin/sh
set -e

echo "-------------------------------------------------------"
echo "Checking if p11-kit is working with the remote settings"
echo ""
echo "p11-kit"
echo "-------"
p11-kit list-modules
echo
echo
echo "p11tool"
echo "-------"
p11tool --provider "$PKCS11_MODULE" --list-privkeys --login --set-pin="${PKCS11_PIN:-123456}"
p11tool --provider "$PKCS11_MODULE" --list-mechanisms --login --set-pin="${PKCS11_PIN:-123456}"

echo
echo "pkcs11-tool"
echo "-------"
echo "Mechanisms"
pkcs11-tool --module "$PKCS11_MODULE" -p "${PKCS11_PIN:-123456}" --list-mechanisms
echo
echo hello > ./test.data
pkcs11-tool --module "$PKCS11_MODULE" -p "${PKCS11_PIN:-123456}" -s -m "ECDSA" --input-file ./test.data --output-file test.data.sig
echo "-------------------------------------------------------"
echo

echo "Starting test client"
/usr/bin/test-client "$@"
